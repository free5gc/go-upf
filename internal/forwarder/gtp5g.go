package forwarder

import (
	"errors"
	"fmt"
	"net"
	"syscall"

	"github.com/khirono/go-gtp5gnl"
	"github.com/khirono/go-nl"
	"github.com/wmnsk/go-pfcp/ie"

	"github.com/free5gc/go-upf/internal/buff"
	"github.com/free5gc/go-upf/internal/gtpv1"
	"github.com/free5gc/go-upf/internal/report"
)

const (
	SOCKPATH = "/tmp/free5gc_unix_sock"
	BUFFLEN  = 512
)

type Gtp5g struct {
	mux    *nl.Mux
	link   *Gtp5gLink
	conn   *nl.Conn
	client *gtp5gnl.Client
	bs     *buff.Server
}

func OpenGtp5g(addr string) (*Gtp5g, error) {
	g := new(Gtp5g)

	mux, err := nl.NewMux()
	if err != nil {
		return nil, err
	}
	go mux.Serve()
	g.mux = mux

	link, err := OpenGtp5gLink(mux, addr)
	if err != nil {
		g.Close()
		return nil, err
	}
	g.link = link

	conn, err := nl.Open(syscall.NETLINK_GENERIC)
	if err != nil {
		g.Close()
		return nil, err
	}
	g.conn = conn

	c, err := gtp5gnl.NewClient(conn, mux)
	if err != nil {
		g.Close()
		return nil, err
	}
	g.client = c

	bs, err := buff.OpenServer(SOCKPATH, BUFFLEN)
	if err != nil {
		g.Close()
		return nil, err
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
	for _, p := range fd.SrcPorts {
		attrs = append(attrs, nl.Attr{
			Type:  gtp5gnl.FLOW_DESCRIPTION_SRC_PORT,
			Value: nl.AttrU32(p),
		})
	}
	for _, p := range fd.DstPorts {
		attrs = append(attrs, nl.Attr{
			Type:  gtp5gnl.FLOW_DESCRIPTION_DEST_PORT,
			Value: nl.AttrU32(p),
		})
	}
	return attrs, nil
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
		var x uint16
		x = 29
		attrs = append(attrs, nl.Attr{
			Type:  gtp5gnl.SDF_FILTER_TOS_TRAFFIC_CLASS,
			Value: nl.AttrU16(x),
		})
	}
	if v.HasSPI() {
		// TODO:
		// v.SecurityParameterIndex string
		var x uint32
		x = 30
		attrs = append(attrs, nl.Attr{
			Type:  gtp5gnl.SDF_FILTER_SECURITY_PARAMETER_INDEX,
			Value: nl.AttrU32(x),
		})
	}
	if v.HasFL() {
		// TODO:
		// v.FlowLabel string
		var x uint32
		x = 31
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

func (g *Gtp5g) CreatePDR(req *ie.IE) error {
	var pdrid int
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
			pdrid = int(v)
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
		}
	}

	// TODO:
	// Not in 3GPP spec, just used for routing
	// var roleAddrIpv4 net.IP
	// roleAddrIpv4 = net.IPv4(34, 35, 36, 37)
	// pdr.RoleAddrIpv4 = &roleAddrIpv4

	// XXX:
	// Not in 3GPP spec, just used for buffering
	attrs = append(attrs, nl.Attr{
		Type:  gtp5gnl.PDR_UNIX_SOCKET_PATH,
		Value: nl.AttrString(SOCKPATH),
	})

	return gtp5gnl.CreatePDR(g.client, g.link.link, pdrid, attrs)
}

func (g *Gtp5g) UpdatePDR(req *ie.IE) error {
	var pdrid int
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
			pdrid = int(v)
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
		}
	}

	return gtp5gnl.UpdatePDR(g.client, g.link.link, pdrid, attrs)
}

func (g *Gtp5g) RemovePDR(req *ie.IE) error {
	v, err := req.PDRID()
	if err != nil {
		return errors.New("not found PDRID")
	}
	return gtp5gnl.RemovePDR(g.client, g.link.link, int(v))
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
					Value: nl.AttrU16(2152),
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
		}
	}

	return attrs, nil
}

func (g *Gtp5g) CreateFAR(req *ie.IE) error {
	var farid int
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
			farid = int(v)
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
		}
	}

	return gtp5gnl.CreateFAR(g.client, g.link.link, farid, attrs)
}

func (g *Gtp5g) UpdateFAR(req *ie.IE) error {
	var farid int
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
			farid = int(v)
		case ie.ApplyAction:
			v, err := i.ApplyAction()
			if err != nil {
				return err
			}
			attrs = append(attrs, nl.Attr{
				Type:  gtp5gnl.FAR_APPLY_ACTION,
				Value: nl.AttrU8(v),
			})
			g.applyAction(farid, v)
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
		}
	}

	return gtp5gnl.UpdateFAR(g.client, g.link.link, farid, attrs)
}

func (g *Gtp5g) RemoveFAR(req *ie.IE) error {
	v, err := req.FARID()
	if err != nil {
		return errors.New("not found FARID")
	}
	return gtp5gnl.RemoveFAR(g.client, g.link.link, int(v))
}

func (g *Gtp5g) CreateQER(req *ie.IE) error {
	var qerid int
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
			qerid = int(v)
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

	return gtp5gnl.CreateQER(g.client, g.link.link, qerid, attrs)
}

func (g *Gtp5g) UpdateQER(req *ie.IE) error {
	var qerid int
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
			qerid = int(v)
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

	return gtp5gnl.UpdateQER(g.client, g.link.link, qerid, attrs)
}

func (g *Gtp5g) RemoveQER(req *ie.IE) error {
	v, err := req.QERID()
	if err != nil {
		return errors.New("not found QERID")
	}
	return gtp5gnl.RemoveQER(g.client, g.link.link, int(v))
}

func (g *Gtp5g) HandleReport(handler report.Handler) {
	g.bs.Handle(handler)
}

const (
	DROP = 1 << 0
	FORW = 1 << 1
	BUFF = 1 << 2
)

func (g *Gtp5g) applyAction(farid int, action uint8) {
	far, err := gtp5gnl.GetFAR(g.client, g.link.link, farid)
	if err != nil {
		return
	}
	if far.Action&BUFF == 0 {
		return
	}
	switch {
	case action&DROP != 0:
		// BUFF -> DROP
		for _, pdrid := range far.PDRIDs {
			for {
				_, ok := g.bs.Pop(pdrid)
				if !ok {
					break
				}
			}
		}
	case action&FORW != 0:
		// BUFF -> FORW
		for _, pdrid := range far.PDRIDs {
			pdr, err := gtp5gnl.GetPDR(g.client, g.link.link, int(pdrid))
			if err != nil {
				continue
			}
			var qer *gtp5gnl.QER
			if pdr.QERID != nil {
				q, err := gtp5gnl.GetQER(g.client, g.link.link, int(*pdr.QERID))
				if err != nil {
					continue
				}
				qer = q
			}
			for {
				pkt, ok := g.bs.Pop(pdrid)
				if !ok {
					break
				}
				err := g.WritePacket(far, qer, pkt)
				if err != nil {
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
