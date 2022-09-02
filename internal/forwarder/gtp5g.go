package forwarder

import (
	"fmt"
	"net"
	"sync"
	"syscall"
	"unsafe"

	"github.com/hashicorp/go-version"
	"github.com/khirono/go-nl"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/wmnsk/go-pfcp/ie"

	"github.com/free5gc/go-gtp5gnl"
	"github.com/free5gc/go-upf/internal/forwarder/buff"
	"github.com/free5gc/go-upf/internal/gtpv1"
	"github.com/free5gc/go-upf/internal/logger"
	"github.com/free5gc/go-upf/internal/report"
	"github.com/free5gc/go-upf/pkg/factory"
)

const (
	expectedGtp5gVersion string = "0.6.6"
	SOCKPATH             string = "/tmp/free5gc_unix_sock"
)

type Gtp5g struct {
	mux    *nl.Mux
	link   *Gtp5gLink
	conn   *nl.Conn
	client *gtp5gnl.Client
	bs     *buff.Server
	log    *logrus.Entry
}

func OpenGtp5g(wg *sync.WaitGroup, addr string, mtu uint32) (*Gtp5g, error) {
	g := &Gtp5g{
		log: logger.FwderLog.WithField(logger.FieldCategory, "Gtp5g"),
	}

	mux, err := nl.NewMux()
	if err != nil {
		return nil, errors.Wrap(err, "new Mux")
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		err = mux.Serve()
		if err != nil {
			g.log.Warnf("mux Serve err: %+v", err)
		}
	}()
	g.mux = mux

	link, err := OpenGtp5gLink(mux, addr, mtu, g.log)
	if err != nil {
		g.Close()
		return nil, errors.Wrap(err, "open link")
	}
	g.link = link

	conn, err := nl.Open(syscall.NETLINK_GENERIC)
	if err != nil {
		g.Close()
		return nil, errors.Wrap(err, "open netlink")
	}
	g.conn = conn

	c, err := gtp5gnl.NewClient(conn, mux)
	if err != nil {
		g.Close()
		return nil, errors.Wrap(err, "new client")
	}
	g.client = c

	err = g.checkVersion()
	if err != nil {
		return nil, errors.Wrap(err, "version mismatch")
	}

	bs, err := buff.OpenServer(wg, SOCKPATH)
	if err != nil {
		g.Close()
		return nil, errors.Wrap(err, "open buff server")
	}
	g.bs = bs

	return g, nil
}

func (g *Gtp5g) Close() {
	if g.conn != nil {
		g.conn.Close()
	}
	if g.link != nil {
		g.link.Close()
	}
	if g.mux != nil {
		g.mux.Close()
	}
	if g.bs != nil {
		g.bs.Close()
	}
}

func (g *Gtp5g) checkVersion() error {
	// get gtp5g version
	gtp5gVer, err := gtp5gnl.GetVersion(g.client)
	if err != nil {
		return err
	}

	// compare version
	expVer, err := version.NewVersion(expectedGtp5gVersion)
	if err != nil {
		return errors.Wrapf(err, "parse expectedGtp5gVersion err")
	}
	nowVer, err := version.NewVersion(gtp5gVer)
	if err != nil {
		return errors.Wrapf(err, "Unable to parse gtp5g version(%s)", nowVer)
	}
	if nowVer.LessThan(expVer) {
		return errors.Errorf(
			"gtp5g version should be >= %s, please upgrade it",
			expectedGtp5gVersion)
	}

	return nil
}

func (g *Gtp5g) Link() *Gtp5gLink {
	return g.link
}

func (g *Gtp5g) newFlowDesc(s string) (nl.AttrList, error) {
	var attrs nl.AttrList
	fd, err := ParseFlowDesc(s)
	if err != nil {
		return nil, err
	}
	switch fd.Action {
	case "permit":
		attrs = append(attrs, nl.Attr{
			Type:  gtp5gnl.FLOW_DESCRIPTION_ACTION,
			Value: nl.AttrU8(gtp5gnl.SDF_FILTER_PERMIT),
		})
	default:
		return nil, fmt.Errorf("not support action %v", fd.Action)
	}
	switch fd.Dir {
	case "in":
		attrs = append(attrs, nl.Attr{
			Type:  gtp5gnl.FLOW_DESCRIPTION_DIRECTION,
			Value: nl.AttrU8(gtp5gnl.SDF_FILTER_IN),
		})
	case "out":
		attrs = append(attrs, nl.Attr{
			Type:  gtp5gnl.FLOW_DESCRIPTION_DIRECTION,
			Value: nl.AttrU8(gtp5gnl.SDF_FILTER_OUT),
		})
	default:
		return nil, fmt.Errorf("not support dir %v", fd.Dir)
	}
	attrs = append(attrs, nl.Attr{
		Type:  gtp5gnl.FLOW_DESCRIPTION_PROTOCOL,
		Value: nl.AttrU8(fd.Proto),
	})
	attrs = append(attrs, nl.Attr{
		Type:  gtp5gnl.FLOW_DESCRIPTION_SRC_IPV4,
		Value: nl.AttrBytes(fd.Src.IP),
	})
	attrs = append(attrs, nl.Attr{
		Type:  gtp5gnl.FLOW_DESCRIPTION_SRC_MASK,
		Value: nl.AttrBytes(fd.Src.Mask),
	})
	attrs = append(attrs, nl.Attr{
		Type:  gtp5gnl.FLOW_DESCRIPTION_DEST_IPV4,
		Value: nl.AttrBytes(fd.Dst.IP),
	})
	attrs = append(attrs, nl.Attr{
		Type:  gtp5gnl.FLOW_DESCRIPTION_DEST_MASK,
		Value: nl.AttrBytes(fd.Dst.Mask),
	})
	attrs = append(attrs, nl.Attr{
		Type:  gtp5gnl.FLOW_DESCRIPTION_SRC_PORT,
		Value: nl.AttrBytes(convertSlice(fd.SrcPorts)),
	})
	attrs = append(attrs, nl.Attr{
		Type:  gtp5gnl.FLOW_DESCRIPTION_DEST_PORT,
		Value: nl.AttrBytes(convertSlice(fd.DstPorts)),
	})
	return attrs, nil
}

func convertSlice(ports [][]uint16) []byte {
	b := make([]byte, len(ports)*4)
	off := 0
	for _, p := range ports {
		x := (*uint32)(unsafe.Pointer(&b[off]))
		switch len(p) {
		case 1:
			*x = uint32(p[0])<<16 | uint32(p[0])
		case 2:
			*x = uint32(p[0])<<16 | uint32(p[1])
		}
		off += 4
	}
	return b
}

func (g *Gtp5g) newSdfFilter(i *ie.IE) (nl.AttrList, error) {
	var attrs nl.AttrList

	v, err := i.SDFFilter()
	if err != nil {
		return nil, err
	}

	if v.HasFD() {
		fd, err := g.newFlowDesc(v.FlowDescription)
		if err != nil {
			return nil, err
		}
		attrs = append(attrs, nl.Attr{
			Type:  gtp5gnl.SDF_FILTER_FLOW_DESCRIPTION,
			Value: fd,
		})
	}
	if v.HasTTC() {
		// TODO:
		// v.ToSTrafficClass string
		x := uint16(29)
		attrs = append(attrs, nl.Attr{
			Type:  gtp5gnl.SDF_FILTER_TOS_TRAFFIC_CLASS,
			Value: nl.AttrU16(x),
		})
	}
	if v.HasSPI() {
		// TODO:
		// v.SecurityParameterIndex string
		x := uint32(30)
		attrs = append(attrs, nl.Attr{
			Type:  gtp5gnl.SDF_FILTER_SECURITY_PARAMETER_INDEX,
			Value: nl.AttrU32(x),
		})
	}
	if v.HasFL() {
		// TODO:
		// v.FlowLabel string
		x := uint32(31)
		attrs = append(attrs, nl.Attr{
			Type:  gtp5gnl.SDF_FILTER_FLOW_LABEL,
			Value: nl.AttrU32(x),
		})
	}
	if v.HasBID() {
		attrs = append(attrs, nl.Attr{
			Type:  gtp5gnl.SDF_FILTER_SDF_FILTER_ID,
			Value: nl.AttrU32(v.SDFFilterID),
		})
	}

	return attrs, nil
}

func (g *Gtp5g) newPdi(i *ie.IE) (nl.AttrList, error) {
	var attrs nl.AttrList

	ies, err := i.PDI()
	if err != nil {
		return nil, err
	}
	for _, x := range ies {
		switch x.Type {
		case ie.SourceInterface:
		case ie.FTEID:
			v, err := x.FTEID()
			if err != nil {
				break
			}
			attrs = append(attrs, nl.Attr{
				Type: gtp5gnl.PDI_F_TEID,
				Value: nl.AttrList{
					{
						Type:  gtp5gnl.F_TEID_I_TEID,
						Value: nl.AttrU32(v.TEID),
					},
					{
						Type:  gtp5gnl.F_TEID_GTPU_ADDR_IPV4,
						Value: nl.AttrBytes(v.IPv4Address),
					},
				},
			})
		case ie.NetworkInstance:
		case ie.UEIPAddress:
			v, err := x.UEIPAddress()
			if err != nil {
				break
			}
			attrs = append(attrs, nl.Attr{
				Type:  gtp5gnl.PDI_UE_ADDR_IPV4,
				Value: nl.AttrBytes(v.IPv4Address),
			})
		case ie.SDFFilter:
			v, err := g.newSdfFilter(x)
			if err != nil {
				break
			}
			attrs = append(attrs, nl.Attr{
				Type:  gtp5gnl.PDI_SDF_FILTER,
				Value: v,
			})
		case ie.ApplicationID:
		}
	}

	return attrs, nil
}

func (g *Gtp5g) CreatePDR(lSeid uint64, req *ie.IE) error {
	var pdrid uint64
	var attrs []nl.Attr

	ies, err := req.CreatePDR()
	if err != nil {
		return err
	}

	for _, i := range ies {
		switch i.Type {
		case ie.PDRID:
			v, err := i.PDRID()
			if err != nil {
				break
			}
			pdrid = uint64(v)
		case ie.Precedence:
			v, err := i.Precedence()
			if err != nil {
				break
			}
			attrs = append(attrs, nl.Attr{
				Type:  gtp5gnl.PDR_PRECEDENCE,
				Value: nl.AttrU32(v),
			})
		case ie.PDI:
			v, err := g.newPdi(i)
			if err != nil {
				break
			}
			if v != nil {
				attrs = append(attrs, nl.Attr{
					Type:  gtp5gnl.PDR_PDI,
					Value: v,
				})
			}
		case ie.OuterHeaderRemoval:
			v, err := i.OuterHeaderRemovalDescription()
			if err != nil {
				break
			}
			attrs = append(attrs, nl.Attr{
				Type:  gtp5gnl.PDR_OUTER_HEADER_REMOVAL,
				Value: nl.AttrU8(v),
			})
			// ignore GTPUExternsionHeaderDeletion
		case ie.FARID:
			v, err := i.FARID()
			if err != nil {
				break
			}
			attrs = append(attrs, nl.Attr{
				Type:  gtp5gnl.PDR_FAR_ID,
				Value: nl.AttrU32(v),
			})
		case ie.QERID:
			v, err := i.QERID()
			if err != nil {
				break
			}
			attrs = append(attrs, nl.Attr{
				Type:  gtp5gnl.PDR_QER_ID,
				Value: nl.AttrU32(v),
			})
		case ie.URRID:
			v, err := i.URRID()
			if err != nil {
				break
			}
			attrs = append(attrs, nl.Attr{
				Type:  gtp5gnl.PDR_URR_ID,
				Value: nl.AttrU32(v),
			})
		}
	}

	// TODO:
	// Not in 3GPP spec, just used for routing
	// var roleAddrIpv4 net.IP
	// roleAddrIpv4 = net.IPv4(34, 35, 36, 37)
	// pdr.RoleAddrIpv4 = &roleAddrIpv4

	// TODO:
	// Not in 3GPP spec, just used for buffering
	attrs = append(attrs, nl.Attr{
		Type:  gtp5gnl.PDR_UNIX_SOCKET_PATH,
		Value: nl.AttrString(SOCKPATH),
	})

	oid := gtp5gnl.OID{lSeid, pdrid}
	return gtp5gnl.CreatePDROID(g.client, g.link.link, oid, attrs)
}

func (g *Gtp5g) UpdatePDR(lSeid uint64, req *ie.IE) error {
	var pdrid uint64
	var attrs []nl.Attr

	ies, err := req.UpdatePDR()
	if err != nil {
		return err
	}

	for _, i := range ies {
		switch i.Type {
		case ie.PDRID:
			v, err := i.PDRID()
			if err != nil {
				break
			}
			pdrid = uint64(v)
		case ie.Precedence:
			v, err := i.Precedence()
			if err != nil {
				break
			}
			attrs = append(attrs, nl.Attr{
				Type:  gtp5gnl.PDR_PRECEDENCE,
				Value: nl.AttrU32(v),
			})
		case ie.PDI:
			v, err := g.newPdi(i)
			if err != nil {
				break
			}
			if v != nil {
				attrs = append(attrs, nl.Attr{
					Type:  gtp5gnl.PDR_PDI,
					Value: v,
				})
			}
		case ie.OuterHeaderRemoval:
			v, err := i.OuterHeaderRemovalDescription()
			if err != nil {
				break
			}
			attrs = append(attrs, nl.Attr{
				Type:  gtp5gnl.PDR_OUTER_HEADER_REMOVAL,
				Value: nl.AttrU8(v),
			})
			// ignore GTPUExternsionHeaderDeletion
		case ie.FARID:
			v, err := i.FARID()
			if err != nil {
				break
			}
			attrs = append(attrs, nl.Attr{
				Type:  gtp5gnl.PDR_FAR_ID,
				Value: nl.AttrU32(v),
			})
		case ie.QERID:
			v, err := i.QERID()
			if err != nil {
				break
			}
			attrs = append(attrs, nl.Attr{
				Type:  gtp5gnl.PDR_QER_ID,
				Value: nl.AttrU32(v),
			})
		case ie.URRID:
			v, err := i.URRID()
			if err != nil {
				break
			}
			attrs = append(attrs, nl.Attr{
				Type:  gtp5gnl.PDR_URR_ID,
				Value: nl.AttrU32(v),
			})
		}
	}

	oid := gtp5gnl.OID{lSeid, pdrid}
	return gtp5gnl.UpdatePDROID(g.client, g.link.link, oid, attrs)
}

func (g *Gtp5g) RemovePDR(lSeid uint64, req *ie.IE) error {
	v, err := req.PDRID()
	if err != nil {
		return errors.New("not found PDRID")
	}
	oid := gtp5gnl.OID{lSeid, uint64(v)}
	return gtp5gnl.RemovePDROID(g.client, g.link.link, oid)
}

func (g *Gtp5g) newForwardingParameter(ies []*ie.IE) (nl.AttrList, error) {
	var attrs nl.AttrList

	for _, x := range ies {
		switch x.Type {
		case ie.DestinationInterface:
		case ie.NetworkInstance:
		case ie.OuterHeaderCreation:
			v, err := x.OuterHeaderCreation()
			if err != nil {
				break
			}
			var hc nl.AttrList
			hc = append(hc, nl.Attr{
				Type:  gtp5gnl.OUTER_HEADER_CREATION_DESCRIPTION,
				Value: nl.AttrU16(v.OuterHeaderCreationDescription),
			})
			if x.HasTEID() {
				hc = append(hc, nl.Attr{
					Type:  gtp5gnl.OUTER_HEADER_CREATION_O_TEID,
					Value: nl.AttrU32(v.TEID),
				})
				// GTPv1-U port
				hc = append(hc, nl.Attr{
					Type:  gtp5gnl.OUTER_HEADER_CREATION_PORT,
					Value: nl.AttrU16(factory.UpfGtpDefaultPort),
				})
			} else {
				hc = append(hc, nl.Attr{
					Type:  gtp5gnl.OUTER_HEADER_CREATION_PORT,
					Value: nl.AttrU16(v.PortNumber),
				})
			}
			if x.HasIPv4() {
				hc = append(hc, nl.Attr{
					Type:  gtp5gnl.OUTER_HEADER_CREATION_PEER_ADDR_IPV4,
					Value: nl.AttrBytes(v.IPv4Address),
				})
			}
			attrs = append(attrs, nl.Attr{
				Type:  gtp5gnl.FORWARDING_PARAMETER_OUTER_HEADER_CREATION,
				Value: hc,
			})
		case ie.ForwardingPolicy:
			v, err := x.ForwardingPolicyIdentifier()
			if err != nil {
				break
			}
			attrs = append(attrs, nl.Attr{
				Type:  gtp5gnl.FORWARDING_PARAMETER_FORWARDING_POLICY,
				Value: nl.AttrString(v),
			})
		case ie.PFCPSMReqFlags:
			v, err := x.PFCPSMReqFlags()
			if err != nil {
				break
			}
			attrs = append(attrs, nl.Attr{
				Type:  gtp5gnl.FORWARDING_PARAMETER_PFCPSM_REQ_FLAGS,
				Value: nl.AttrU8(v),
			})
		}
	}

	return attrs, nil
}

func (g *Gtp5g) CreateFAR(lSeid uint64, req *ie.IE) error {
	var farid uint64
	var attrs []nl.Attr

	ies, err := req.CreateFAR()
	if err != nil {
		return err
	}
	for _, i := range ies {
		switch i.Type {
		case ie.FARID:
			v, err := i.FARID()
			if err != nil {
				return err
			}
			farid = uint64(v)
		case ie.ApplyAction:
			v, err := i.ApplyAction()
			if err != nil {
				return err
			}
			attrs = append(attrs, nl.Attr{
				Type:  gtp5gnl.FAR_APPLY_ACTION,
				Value: nl.AttrU8(v),
			})
		case ie.ForwardingParameters:
			xs, err := i.ForwardingParameters()
			if err != nil {
				return err
			}
			v, err := g.newForwardingParameter(xs)
			if err != nil {
				break
			}
			if v != nil {
				attrs = append(attrs, nl.Attr{
					Type:  gtp5gnl.FAR_FORWARDING_PARAMETER,
					Value: v,
				})
			}
		case ie.BARID:
			v, err := i.BARID()
			if err != nil {
				break
			}
			attrs = append(attrs, nl.Attr{
				Type:  gtp5gnl.FAR_BAR_ID,
				Value: nl.AttrU8(v),
			})
		}
	}

	oid := gtp5gnl.OID{lSeid, farid}
	return gtp5gnl.CreateFAROID(g.client, g.link.link, oid, attrs)
}

func (g *Gtp5g) UpdateFAR(lSeid uint64, req *ie.IE) error {
	var farid uint64
	var attrs []nl.Attr

	ies, err := req.UpdateFAR()
	if err != nil {
		return err
	}
	for _, i := range ies {
		switch i.Type {
		case ie.FARID:
			v, err := i.FARID()
			if err != nil {
				return err
			}
			farid = uint64(v)
		case ie.ApplyAction:
			v, err := i.ApplyAction()
			if err != nil {
				return err
			}
			attrs = append(attrs, nl.Attr{
				Type:  gtp5gnl.FAR_APPLY_ACTION,
				Value: nl.AttrU8(v),
			})
			g.applyAction(lSeid, int(farid), v)
		case ie.UpdateForwardingParameters:
			xs, err := i.UpdateForwardingParameters()
			if err != nil {
				return err
			}
			v, err := g.newForwardingParameter(xs)
			if err != nil {
				break
			}
			if v != nil {
				attrs = append(attrs, nl.Attr{
					Type:  gtp5gnl.FAR_FORWARDING_PARAMETER,
					Value: v,
				})
			}
		case ie.BARID:
			v, err := i.BARID()
			if err != nil {
				break
			}
			attrs = append(attrs, nl.Attr{
				Type:  gtp5gnl.FAR_BAR_ID,
				Value: nl.AttrU8(v),
			})
		}
	}

	oid := gtp5gnl.OID{lSeid, farid}
	return gtp5gnl.UpdateFAROID(g.client, g.link.link, oid, attrs)
}

func (g *Gtp5g) RemoveFAR(lSeid uint64, req *ie.IE) error {
	v, err := req.FARID()
	if err != nil {
		return errors.New("not found FARID")
	}
	oid := gtp5gnl.OID{lSeid, uint64(v)}
	return gtp5gnl.RemoveFAROID(g.client, g.link.link, oid)
}

func (g *Gtp5g) CreateQER(lSeid uint64, req *ie.IE) error {
	var qerid uint64
	var attrs []nl.Attr

	ies, err := req.CreateQER()
	if err != nil {
		return err
	}
	for _, i := range ies {
		switch i.Type {
		case ie.QERID:
			// M
			v, err := i.QERID()
			if err != nil {
				break
			}
			qerid = uint64(v)
		case ie.QERCorrelationID:
			// C
			v, err := i.QERCorrelationID()
			if err != nil {
				break
			}
			attrs = append(attrs, nl.Attr{
				Type:  gtp5gnl.QER_CORR_ID,
				Value: nl.AttrU32(v),
			})
		case ie.GateStatus:
			// M
			v, err := i.GateStatus()
			if err != nil {
				break
			}
			attrs = append(attrs, nl.Attr{
				Type:  gtp5gnl.QER_GATE,
				Value: nl.AttrU8(v),
			})
		case ie.MBR:
			// C
			ul, err := i.MBRUL()
			if err != nil {
				break
			}
			dl, err := i.MBRDL()
			if err != nil {
				break
			}
			attrs = append(attrs, nl.Attr{
				Type: gtp5gnl.QER_MBR,
				Value: nl.AttrList{
					{
						Type:  gtp5gnl.QER_MBR_UL_HIGH32,
						Value: nl.AttrU32(ul >> 8),
					},
					{
						Type:  gtp5gnl.QER_MBR_UL_LOW8,
						Value: nl.AttrU8(ul),
					},
					{
						Type:  gtp5gnl.QER_MBR_DL_HIGH32,
						Value: nl.AttrU32(dl >> 8),
					},
					{
						Type:  gtp5gnl.QER_MBR_DL_LOW8,
						Value: nl.AttrU8(dl),
					},
				},
			})
		case ie.GBR:
			// C
			ul, err := i.GBRUL()
			if err != nil {
				break
			}
			dl, err := i.GBRDL()
			if err != nil {
				break
			}
			attrs = append(attrs, nl.Attr{
				Type: gtp5gnl.QER_GBR,
				Value: nl.AttrList{
					{
						Type:  gtp5gnl.QER_GBR_UL_HIGH32,
						Value: nl.AttrU32(ul >> 8),
					},
					{
						Type:  gtp5gnl.QER_GBR_UL_LOW8,
						Value: nl.AttrU8(ul),
					},
					{
						Type:  gtp5gnl.QER_GBR_DL_HIGH32,
						Value: nl.AttrU32(dl >> 8),
					},
					{
						Type:  gtp5gnl.QER_GBR_DL_LOW8,
						Value: nl.AttrU8(dl),
					},
				},
			})
		case ie.QFI:
			// C
			v, err := i.QFI()
			if err != nil {
				break
			}
			attrs = append(attrs, nl.Attr{
				Type:  gtp5gnl.QER_QFI,
				Value: nl.AttrU8(v),
			})
		case ie.RQI:
			// C
			v, err := i.RQI()
			if err != nil {
				break
			}
			attrs = append(attrs, nl.Attr{
				Type:  gtp5gnl.QER_RQI,
				Value: nl.AttrU8(v),
			})
		case ie.PagingPolicyIndicator:
			// C
			v, err := i.PagingPolicyIndicator()
			if err != nil {
				break
			}
			attrs = append(attrs, nl.Attr{
				Type:  gtp5gnl.QER_PPI,
				Value: nl.AttrU8(v),
			})
		}
	}

	oid := gtp5gnl.OID{lSeid, qerid}
	return gtp5gnl.CreateQEROID(g.client, g.link.link, oid, attrs)
}

func (g *Gtp5g) UpdateQER(lSeid uint64, req *ie.IE) error {
	var qerid uint64
	var attrs []nl.Attr

	ies, err := req.UpdateQER()
	if err != nil {
		return err
	}
	for _, i := range ies {
		switch i.Type {
		case ie.QERID:
			// M
			v, err := i.QERID()
			if err != nil {
				break
			}
			qerid = uint64(v)
		case ie.QERCorrelationID:
			// C
			v, err := i.QERCorrelationID()
			if err != nil {
				break
			}
			attrs = append(attrs, nl.Attr{
				Type:  gtp5gnl.QER_CORR_ID,
				Value: nl.AttrU32(v),
			})
		case ie.GateStatus:
			// M
			v, err := i.GateStatus()
			if err != nil {
				break
			}
			attrs = append(attrs, nl.Attr{
				Type:  gtp5gnl.QER_GATE,
				Value: nl.AttrU8(v),
			})
		case ie.MBR:
			// C
			ul, err := i.MBRUL()
			if err != nil {
				break
			}
			dl, err := i.MBRDL()
			if err != nil {
				break
			}
			attrs = append(attrs, nl.Attr{
				Type: gtp5gnl.QER_MBR,
				Value: nl.AttrList{
					{
						Type:  gtp5gnl.QER_MBR_UL_HIGH32,
						Value: nl.AttrU32(ul >> 8),
					},
					{
						Type:  gtp5gnl.QER_MBR_UL_LOW8,
						Value: nl.AttrU8(ul),
					},
					{
						Type:  gtp5gnl.QER_MBR_DL_HIGH32,
						Value: nl.AttrU32(dl >> 8),
					},
					{
						Type:  gtp5gnl.QER_MBR_DL_LOW8,
						Value: nl.AttrU8(dl),
					},
				},
			})
		case ie.GBR:
			// C
			ul, err := i.GBRUL()
			if err != nil {
				break
			}
			dl, err := i.GBRDL()
			if err != nil {
				break
			}
			attrs = append(attrs, nl.Attr{
				Type: gtp5gnl.QER_GBR,
				Value: nl.AttrList{
					{
						Type:  gtp5gnl.QER_GBR_UL_HIGH32,
						Value: nl.AttrU32(ul >> 8),
					},
					{
						Type:  gtp5gnl.QER_GBR_UL_LOW8,
						Value: nl.AttrU8(ul),
					},
					{
						Type:  gtp5gnl.QER_GBR_DL_HIGH32,
						Value: nl.AttrU32(dl >> 8),
					},
					{
						Type:  gtp5gnl.QER_GBR_DL_LOW8,
						Value: nl.AttrU8(dl),
					},
				},
			})
		case ie.QFI:
			// C
			v, err := i.QFI()
			if err != nil {
				break
			}
			attrs = append(attrs, nl.Attr{
				Type:  gtp5gnl.QER_QFI,
				Value: nl.AttrU8(v),
			})
		case ie.RQI:
			// C
			v, err := i.RQI()
			if err != nil {
				break
			}
			attrs = append(attrs, nl.Attr{
				Type:  gtp5gnl.QER_RQI,
				Value: nl.AttrU8(v),
			})
		case ie.PagingPolicyIndicator:
			// C
			v, err := i.PagingPolicyIndicator()
			if err != nil {
				break
			}
			attrs = append(attrs, nl.Attr{
				Type:  gtp5gnl.QER_PPI,
				Value: nl.AttrU8(v),
			})
		}
	}

	oid := gtp5gnl.OID{lSeid, qerid}
	return gtp5gnl.UpdateQEROID(g.client, g.link.link, oid, attrs)
}

func (g *Gtp5g) RemoveQER(lSeid uint64, req *ie.IE) error {
	v, err := req.QERID()
	if err != nil {
		return errors.New("not found QERID")
	}
	oid := gtp5gnl.OID{lSeid, uint64(v)}
	return gtp5gnl.RemoveQEROID(g.client, g.link.link, oid)
}

func (g *Gtp5g) CreateURR(lSeid uint64, req *ie.IE) error {
	var urrid uint64
	var attrs []nl.Attr

	ies, err := req.CreateURR()
	if err != nil {
		return err
	}
	for _, i := range ies {
		switch i.Type {
		case ie.URRID:
			v, err := i.URRID()
			if err != nil {
				return err
			}
			urrid = uint64(v)
		case ie.MeasurementMethod:
			v, err := i.MeasurementMethod()
			if err != nil {
				return err
			}
			attrs = append(attrs, nl.Attr{
				Type:  gtp5gnl.URR_MEASUREMENT_METHOD,
				Value: nl.AttrU64(v),
			})
		case ie.ReportingTriggers:
			v, err := i.ReportingTriggers()
			if err != nil {
				return err
			}
			attrs = append(attrs, nl.Attr{
				Type:  gtp5gnl.URR_REPORTING_TRIGGER,
				Value: nl.AttrU64(v),
			})
		case ie.MeasurementPeriod:
			v, err := i.MeasurementPeriod()
			if err != nil {
				return err
			}
			// TODO: convert time.Duration -> ?
			attrs = append(attrs, nl.Attr{
				Type:  gtp5gnl.URR_MEASUREMENT_PERIOD,
				Value: nl.AttrU64(v),
			})
		case ie.MeasurementInformation:
			v, err := i.MeasurementInformation()
			if err != nil {
				return err
			}
			attrs = append(attrs, nl.Attr{
				Type:  gtp5gnl.URR_MEASUREMENT_INFO,
				Value: nl.AttrU64(v),
			})
			// TODO: URR_SEQ
		}
	}

	oid := gtp5gnl.OID{lSeid, urrid}
	return gtp5gnl.CreateURROID(g.client, g.link.link, oid, attrs)
}

func (g *Gtp5g) UpdateURR(lSeid uint64, req *ie.IE) error {
	var urrid uint64
	var attrs []nl.Attr

	ies, err := req.UpdateURR()
	if err != nil {
		return err
	}
	for _, i := range ies {
		switch i.Type {
		case ie.URRID:
			v, err := i.URRID()
			if err != nil {
				return err
			}
			urrid = uint64(v)
		case ie.MeasurementMethod:
			v, err := i.MeasurementMethod()
			if err != nil {
				return err
			}
			attrs = append(attrs, nl.Attr{
				Type:  gtp5gnl.URR_MEASUREMENT_METHOD,
				Value: nl.AttrU64(v),
			})
		case ie.ReportingTriggers:
			v, err := i.ReportingTriggers()
			if err != nil {
				return err
			}
			attrs = append(attrs, nl.Attr{
				Type:  gtp5gnl.URR_REPORTING_TRIGGER,
				Value: nl.AttrU64(v),
			})
		case ie.MeasurementPeriod:
			v, err := i.MeasurementPeriod()
			if err != nil {
				return err
			}
			// TODO: convert time.Duration -> ?
			attrs = append(attrs, nl.Attr{
				Type:  gtp5gnl.URR_MEASUREMENT_PERIOD,
				Value: nl.AttrU64(v),
			})
		case ie.MeasurementInformation:
			v, err := i.MeasurementInformation()
			if err != nil {
				return err
			}
			attrs = append(attrs, nl.Attr{
				Type:  gtp5gnl.URR_MEASUREMENT_INFO,
				Value: nl.AttrU64(v),
			})
			// TODO: URR_SEQ
		}
	}

	oid := gtp5gnl.OID{lSeid, urrid}
	return gtp5gnl.UpdateURROID(g.client, g.link.link, oid, attrs)
}

func (g *Gtp5g) RemoveURR(lSeid uint64, req *ie.IE) error {
	v, err := req.URRID()
	if err != nil {
		return errors.New("not found URRID")
	}
	oid := gtp5gnl.OID{lSeid, uint64(v)}
	return gtp5gnl.RemoveURROID(g.client, g.link.link, oid)
}

func (g *Gtp5g) CreateBAR(lSeid uint64, req *ie.IE) error {
	var barid uint64
	var attrs []nl.Attr

	ies, err := req.CreateBAR()
	if err != nil {
		return err
	}
	for _, i := range ies {
		switch i.Type {
		case ie.BARID:
			v, err := i.BARID()
			if err != nil {
				return err
			}
			barid = uint64(v)
		case ie.DownlinkDataNotificationDelay:
			v, err := i.DownlinkDataNotificationDelay()
			if err != nil {
				return err
			}
			// TODO: convert time.Duration -> ?
			attrs = append(attrs, nl.Attr{
				Type:  gtp5gnl.BAR_DOWNLINK_DATA_NOTIFICATION_DELAY,
				Value: nl.AttrU8(v),
			})
		case ie.SuggestedBufferingPacketsCount:
			v, err := i.SuggestedBufferingPacketsCount()
			if err != nil {
				return err
			}
			attrs = append(attrs, nl.Attr{
				Type:  gtp5gnl.BAR_BUFFERING_PACKETS_COUNT,
				Value: nl.AttrU16(v),
			})
		}
	}

	oid := gtp5gnl.OID{lSeid, barid}
	return gtp5gnl.CreateBAROID(g.client, g.link.link, oid, attrs)
}

func (g *Gtp5g) UpdateBAR(lSeid uint64, req *ie.IE) error {
	var barid uint64
	var attrs []nl.Attr

	ies, err := req.UpdateBAR()
	if err != nil {
		return err
	}
	for _, i := range ies {
		switch i.Type {
		case ie.BARID:
			v, err := i.BARID()
			if err != nil {
				return err
			}
			barid = uint64(v)
		case ie.DownlinkDataNotificationDelay:
			v, err := i.DownlinkDataNotificationDelay()
			if err != nil {
				return err
			}
			// TODO: convert time.Duration -> ?
			attrs = append(attrs, nl.Attr{
				Type:  gtp5gnl.BAR_DOWNLINK_DATA_NOTIFICATION_DELAY,
				Value: nl.AttrU8(v),
			})
		case ie.SuggestedBufferingPacketsCount:
			v, err := i.SuggestedBufferingPacketsCount()
			if err != nil {
				return err
			}
			attrs = append(attrs, nl.Attr{
				Type:  gtp5gnl.BAR_BUFFERING_PACKETS_COUNT,
				Value: nl.AttrU16(v),
			})
		}
	}

	oid := gtp5gnl.OID{lSeid, barid}
	return gtp5gnl.UpdateBAROID(g.client, g.link.link, oid, attrs)
}

func (g *Gtp5g) RemoveBAR(lSeid uint64, req *ie.IE) error {
	v, err := req.BARID()
	if err != nil {
		return errors.New("not found BARID")
	}
	oid := gtp5gnl.OID{lSeid, uint64(v)}
	return gtp5gnl.RemoveBAROID(g.client, g.link.link, oid)
}

func (g *Gtp5g) HandleReport(handler report.Handler) {
	g.bs.Handle(handler)
}

func (g *Gtp5g) applyAction(lSeid uint64, farid int, action uint8) {
	oid := gtp5gnl.OID{lSeid, uint64(farid)}
	far, err := gtp5gnl.GetFAROID(g.client, g.link.link, oid)
	if err != nil {
		g.log.Errorf("applyAction err: %+v", err)
		return
	}
	if far.Action&report.BUFF == 0 {
		return
	}
	switch {
	case action&report.DROP != 0:
		// BUFF -> DROP
		for _, pdrid := range far.PDRIDs {
			for {
				_, ok := g.bs.Pop(lSeid, pdrid)
				if !ok {
					break
				}
			}
		}
	case action&report.FORW != 0:
		// BUFF -> FORW
		for _, pdrid := range far.PDRIDs {
			oid := gtp5gnl.OID{lSeid, uint64(pdrid)}
			pdr, err := gtp5gnl.GetPDROID(g.client, g.link.link, oid)
			if err != nil {
				g.log.Warnf("applyAction GetPDROID err: %+v", err)
				continue
			}
			var qer *gtp5gnl.QER
			if pdr.QERID != nil {
				oid := gtp5gnl.OID{lSeid, uint64(*pdr.QERID)}
				q, err := gtp5gnl.GetQEROID(g.client, g.link.link, oid)
				if err != nil {
					g.log.Warnf("applyAction GetQEROID err: %+v", err)
					continue
				}
				qer = q
			}
			for {
				pkt, ok := g.bs.Pop(lSeid, pdrid)
				if !ok {
					break
				}
				err := g.WritePacket(far, qer, pkt)
				if err != nil {
					g.log.Warnf("applyAction WritePacket err: %+v", err)
					continue
				}
			}
		}
	}
}

func (g *Gtp5g) WritePacket(far *gtp5gnl.FAR, qer *gtp5gnl.QER, pkt []byte) error {
	if far.Param == nil || far.Param.Creation == nil {
		return errors.New("far param not found")
	}
	hc := far.Param.Creation
	addr := &net.UDPAddr{
		IP:   hc.PeerAddr,
		Port: int(hc.Port),
	}
	msg := gtpv1.Message{
		Flags:   0x34,
		Type:    gtpv1.MsgTypeTPDU,
		TEID:    hc.TEID,
		Payload: pkt,
	}
	if qer != nil {
		msg.Exts = []gtpv1.Encoder{
			gtpv1.PDUSessionContainer{
				PDUType:   0,
				QoSFlowID: qer.QFI,
			},
		}
	}
	n := msg.Len()
	b := make([]byte, n)
	_, err := msg.Encode(b)
	if err != nil {
		return err
	}
	_, err = g.link.WriteTo(b, addr)
	return err
}
