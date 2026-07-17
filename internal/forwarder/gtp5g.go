package forwarder

import (
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/hashicorp/go-version"
	"github.com/khirono/go-nl"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/wmnsk/go-pfcp/ie"

	"github.com/free5gc/go-gtp5gnl"
	"github.com/free5gc/go-upf/internal/forwarder/buffnetlink"
	"github.com/free5gc/go-upf/internal/forwarder/perio"
	"github.com/free5gc/go-upf/internal/gtpv1"
	"github.com/free5gc/go-upf/internal/logger"
	"github.com/free5gc/go-upf/internal/report"
	"github.com/free5gc/go-upf/pkg/factory"
	logger_util "github.com/free5gc/util/logger"
	"github.com/free5gc/util/pfcp"
)

const (
	expectedMinGtp5gVersion string = "0.9.5"
	expectedMaxGtp5gVersion string = "0.11.0"
)

type Gtp5g struct {
	mux      *nl.Mux
	link     *Gtp5gLink
	conn     *nl.Conn
	psConn   *nl.Conn
	client   *gtp5gnl.Client
	psClient *gtp5gnl.Client
	bsnl     *buffnetlink.Server
	ps       *perio.Server
	iptables *IptablesManager
	log      *logrus.Entry
}

func OpenGtp5g(wg *sync.WaitGroup, addr string, mtu uint32) (*Gtp5g, error) {
	g := &Gtp5g{
		log:      logger.FwderLog.WithField(logger_util.FieldCategory, "Gtp5g"),
		iptables: NewIptablesManager(),
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

	psConn, err := nl.Open(syscall.NETLINK_GENERIC)
	if err != nil {
		g.Close()
		return nil, errors.Wrap(err, "open ps netlink")
	}
	g.psConn = psConn

	psc, err := gtp5gnl.NewClient(psConn, mux)
	if err != nil {
		g.Close()
		return nil, errors.Wrap(err, "new ps client")
	}
	g.psClient = psc

	err = g.checkVersion()
	if err != nil {
		g.Close()
		return nil, errors.Wrap(err, "version mismatch")
	}

	bsnl, err := buffnetlink.OpenServer(wg, c.Client, mux)
	if err != nil {
		g.Close()
		return nil, errors.Wrap(err, "open buff(netlink) server")
	}
	g.bsnl = bsnl

	ps, err := perio.OpenServer(wg)
	if err != nil {
		g.Close()
		return nil, errors.Wrap(err, "open perio server")
	}
	g.ps = ps

	g.log.Infof("Forwarder started")
	return g, nil
}

func (g *Gtp5g) Close() {
	if g.conn != nil {
		g.conn.Close()
	}
	if g.psConn != nil {
		g.psConn.Close()
	}
	if g.link != nil {
		g.link.Close()
	}
	if g.mux != nil {
		g.mux.Close()
	}
	if g.bsnl != nil {
		g.bsnl.Close()
	}
	if g.ps != nil {
		g.ps.Close()
	}
	if g.iptables != nil {
		for _, err := range g.iptables.Cleanup() {
			g.log.Warnf("iptables cleanup err: %+v", err)
		}
	}
}

func (g *Gtp5g) checkVersion() error {
	// get gtp5g version
	gtp5gVer, err := gtp5gnl.GetVersion(g.client)
	if err != nil {
		return err
	}

	// compare version
	expMinVer, err := version.NewVersion(expectedMinGtp5gVersion)
	if err != nil {
		return errors.Wrapf(err, "parse expectedMinGtp5gVersion err")
	}
	expMaxVer, err := version.NewVersion(expectedMaxGtp5gVersion)
	if err != nil {
		return errors.Wrapf(err, "parse expectedMaxGtp5gVersion err")
	}
	nowVer, err := version.NewVersion(gtp5gVer)
	if err != nil {
		return errors.Wrapf(err, "Unable to parse gtp5g version(%s)", gtp5gVer)
	}
	if nowVer.LessThan(expMinVer) || nowVer.GreaterThanOrEqual(expMaxVer) {
		return errors.Errorf(
			"gtp5g version(%v) should be %s <= version < %s , please update it",
			nowVer, expectedMinGtp5gVersion, expectedMaxGtp5gVersion)
	}

	return nil
}

func (g *Gtp5g) Link() *Gtp5gLink {
	return g.link
}

func (g *Gtp5g) AddIptablesRules(cidr, ifName string, ipForwardEnable bool) error {
	if g.iptables == nil {
		g.iptables = NewIptablesManager()
	}
	return g.iptables.AddDNNRules(cidr, ifName, ipForwardEnable)
}

func (g *Gtp5g) newFlowDesc(s string, swapSrcDst bool) (nl.AttrList, error) {
	var attrs nl.AttrList
	fd, err := ParseFlowDesc(s)
	if err != nil {
		return nil, err
	}
	if swapSrcDst {
		fd.Src, fd.Dst = fd.Dst, fd.Src
		fd.SrcPorts, fd.DstPorts = fd.DstPorts, fd.SrcPorts
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

func (g *Gtp5g) newSdfFilter(i *ie.IE, srcIf uint8) (nl.AttrList, error) {
	var attrs nl.AttrList
	// i.Payload[0] corresponds to Octet 5 (Flags) in the spec
	flags := i.Payload[0]
	hasFD := (flags & 0x01) != 0 // Bit 1: Flow Description
	offset := 2
	if hasFD {
		if len(i.Payload) < offset+2 {
			return nil, errors.New("SDF Filter IE with FD flag needs Length of Flow Description")
		}
		// Read FDLength from i.Payload[2-3] (Octets 7-8 in spec)
		fdLength := uint16(i.Payload[offset])<<8 | uint16(i.Payload[offset+1])
		// Flow Description data starts at i.Payload[4] (Octet 9)
		flowDescStart := offset + 2
		availableBytes := len(i.Payload) - flowDescStart
		if int(fdLength) > availableBytes {
			return nil, errors.Errorf(
				"SDF Filter FDLength %d exceeds available payload %d bytes",
				fdLength, availableBytes)
		}
	}
	v, err := i.SDFFilter()
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse SDF Filter")
	}
	// Process validated SDF Filter fields
	if v.HasFD() {
		swapSrcDst := (srcIf == ie.SrcInterfaceAccess)
		fd, err := g.newFlowDesc(v.FlowDescription, swapSrcDst)
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

	var srcIf uint8
	var sdfIEs []*ie.IE
	for _, x := range ies {
		switch x.Type {
		case ie.SourceInterface:
			v, err := x.SourceInterface()
			if err != nil {
				break
			}
			attrs = append(attrs, nl.Attr{
				Type:  gtp5gnl.PDI_SRC_INTF,
				Value: nl.AttrU8(v),
			})
			srcIf = v
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
			// Validate SDF Filter IE payload length early (TS 29.244 Section 8.2.5)
			// Minimum: 1 byte (flags) + 1 byte (spare) + at least 1 byte for content
			if len(x.Payload) < 3 {
				return nil, errors.Errorf("SDF Filter IE payload too short: %d bytes (minimum 3)", len(x.Payload))
			}
			sdfIEs = append(sdfIEs, x)
		case ie.ApplicationID:
		}
	}

	for _, x := range sdfIEs {
		v, err := g.newSdfFilter(x, srcIf)
		if err != nil {
			return nil, errors.Wrap(err, "newSdfFilter failed")
		}
		attrs = append(attrs, nl.Attr{
			Type:  gtp5gnl.PDI_SDF_FILTER,
			Value: v,
		})
	}

	return attrs, nil
}

func (g *Gtp5g) newForwardingParameter(ies []*ie.IE) (nl.AttrList, error) {
	var attrs nl.AttrList

	for _, x := range ies {
		switch x.Type {
		case ie.DestinationInterface:
		case ie.NetworkInstance:
		case ie.OuterHeaderCreation:
			// Use parser from util/pfcp to work around go-pfcp bug with C-TAG/S-TAG
			v, err := pfcp.ParseOuterHeaderCreation(x.Payload)
			if err != nil {
				g.log.Warnf("Invalid OuterHeaderCreation IE: %v", err)
				break
			}
			var hc nl.AttrList
			hc = append(hc, nl.Attr{
				Type:  gtp5gnl.OUTER_HEADER_CREATION_DESCRIPTION,
				Value: nl.AttrU16(v.OuterHeaderCreationDescription),
			})
			if v.HasTEID() {
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
			if v.HasIPv4() {
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

func (g *Gtp5g) newVolumeThreshold(i *ie.IE) (nl.AttrList, error) {
	var attrs nl.AttrList

	v, err := i.VolumeThreshold()
	if err != nil {
		return nil, err
	}

	attrs = append(attrs, nl.Attr{
		Type:  gtp5gnl.URR_VOLUME_THRESHOLD_FLAG,
		Value: nl.AttrU8(v.Flags),
	})
	if v.HasTOVOL() {
		attrs = append(attrs, nl.Attr{
			Type:  gtp5gnl.URR_VOLUME_THRESHOLD_TOVOL,
			Value: nl.AttrU64(v.TotalVolume),
		})
	}
	if v.HasULVOL() {
		attrs = append(attrs, nl.Attr{
			Type:  gtp5gnl.URR_VOLUME_THRESHOLD_UVOL,
			Value: nl.AttrU64(v.UplinkVolume),
		})
	}
	if v.HasDLVOL() {
		attrs = append(attrs, nl.Attr{
			Type:  gtp5gnl.URR_VOLUME_THRESHOLD_DVOL,
			Value: nl.AttrU64(v.DownlinkVolume),
		})
	}

	return attrs, nil
}

func (g *Gtp5g) newVolumeQuota(i *ie.IE) (nl.AttrList, error) {
	var attrs nl.AttrList

	v, err := i.VolumeQuota()
	if err != nil {
		return nil, err
	}

	attrs = append(attrs, nl.Attr{
		Type:  gtp5gnl.URR_VOLUME_QUOTA_FLAG,
		Value: nl.AttrU8(v.Flags),
	})
	if v.HasTOVOL() {
		attrs = append(attrs, nl.Attr{
			Type:  gtp5gnl.URR_VOLUME_QUOTA_TOVOL,
			Value: nl.AttrU64(v.TotalVolume),
		})
	}
	if v.HasULVOL() {
		attrs = append(attrs, nl.Attr{
			Type:  gtp5gnl.URR_VOLUME_QUOTA_UVOL,
			Value: nl.AttrU64(v.UplinkVolume),
		})
	}
	if v.HasDLVOL() {
		attrs = append(attrs, nl.Attr{
			Type:  gtp5gnl.URR_VOLUME_QUOTA_DVOL,
			Value: nl.AttrU64(v.DownlinkVolume),
		})
	}

	return attrs, nil
}

func (g *Gtp5g) QueryURR(lSeid uint64, urrid uint32) ([]report.USAReport, error) {
	return g.queryURR(lSeid, urrid, false)
}

func (g *Gtp5g) psQueryURR(lSeidUrridsMap map[uint64][]uint32) (map[uint64][]report.USAReport, error) {
	return g.queryMultiURR(lSeidUrridsMap, true)
}

func (g *Gtp5g) queryURR(lSeid uint64, urrid uint32, ps bool) ([]report.USAReport, error) {
	var usars []report.USAReport

	oid := gtp5gnl.OID{lSeid, uint64(urrid)}
	c := g.client
	if ps {
		c = g.psClient
	}
	rs, err := gtp5gnl.GetReportOID(c, g.link.link, oid)
	if err != nil {
		return nil, errors.Wrapf(err, "queryURR[%#x:%#x]", lSeid, urrid)
	}

	if rs == nil {
		return nil, nil
	}

	for _, r := range rs {
		usar := report.USAReport{
			URRID:       r.URRID,
			QueryUrrRef: r.QueryUrrRef,
			StartTime:   r.StartTime,
			EndTime:     r.EndTime,
		}

		usar.VolumMeasure = report.VolumeMeasure{
			TotalVolume:    r.VolMeasurement.TotalVolume,
			UplinkVolume:   r.VolMeasurement.UplinkVolume,
			DownlinkVolume: r.VolMeasurement.DownlinkVolume,
			TotalPktNum:    r.VolMeasurement.TotalPktNum,
			UplinkPktNum:   r.VolMeasurement.UplinkPktNum,
			DownlinkPktNum: r.VolMeasurement.DownlinkPktNum,
		}

		usars = append(usars, usar)
	}

	g.log.Tracef("queryURR: %+v", usars)

	return usars, nil
}

func (g *Gtp5g) QueryMultiURR(lSeidUrridsMap map[uint64][]uint32) (map[uint64][]report.USAReport, error) {
	return g.queryMultiURR(lSeidUrridsMap, false)
}

func (g *Gtp5g) queryMultiURR(lSeidUrridsMap map[uint64][]uint32, ps bool) (map[uint64][]report.USAReport, error) {
	var oids []gtp5gnl.OID
	var reports []gtp5gnl.USAReport

	c := g.client
	if ps {
		c = g.psClient
	}

	// Note: the max size of netlink msg is 16k,
	//       the number of reports from gtp5g is limited
	//       depending on the size of report
	queryNum := 0
	queryNumOnce := gtp5gnl.MaxNetlinkUsageReportNum()
	for seid, urrIds := range lSeidUrridsMap {
		for _, urrId := range urrIds {
			oids = append(oids, gtp5gnl.OID{seid, uint64(urrId)})
			queryNum++

			if queryNum >= queryNumOnce {
				rs, err := gtp5gnl.GetMultiReportsOID(c, g.link.link, oids)
				if err != nil {
					return nil, errors.Wrapf(err, "queryMultiURR[%+v]", lSeidUrridsMap)
				}

				g.log.Tracef("Reports number in one netlink request: %+v", len(rs))
				reports = append(reports, rs...)
				oids = oids[:0]
				queryNum = 0
			}
		}
	}

	if len(oids) > 0 {
		rs, err := gtp5gnl.GetMultiReportsOID(c, g.link.link, oids)
		if err != nil {
			return nil, errors.Wrapf(err, "queryMultiURR[%+v]", lSeidUrridsMap)
		}

		g.log.Tracef("Reports number in one netlink request: %+v", len(rs))
		reports = append(reports, rs...)
	}

	if reports == nil {
		return nil, nil
	}

	usars := make(map[uint64][]report.USAReport)
	for _, r := range reports {
		usar := report.USAReport{
			URRID:       r.URRID,
			QueryUrrRef: r.QueryUrrRef,
			StartTime:   r.StartTime,
			EndTime:     r.EndTime,
		}

		usar.VolumMeasure = report.VolumeMeasure{
			TotalVolume:    r.VolMeasurement.TotalVolume,
			UplinkVolume:   r.VolMeasurement.UplinkVolume,
			DownlinkVolume: r.VolMeasurement.DownlinkVolume,
			TotalPktNum:    r.VolMeasurement.TotalPktNum,
			UplinkPktNum:   r.VolMeasurement.UplinkPktNum,
			DownlinkPktNum: r.VolMeasurement.DownlinkPktNum,
		}
		usars[r.SEID] = append(usars[r.SEID], usar)
	}

	g.log.Tracef("queryMultiURR: %+v", usars)

	return usars, nil
}

func (g *Gtp5g) HandleReport(handler report.Handler) {
	g.bsnl.Handle(handler)
	g.ps.Handle(handler, g.psQueryURR)
}

func (g *Gtp5g) applyAction(lSeid uint64, farid int, action report.ApplyAction) {
	oid := gtp5gnl.OID{lSeid, uint64(farid)}
	far, err := gtp5gnl.GetFAROID(g.client, g.link.link, oid)
	if err != nil {
		g.log.Errorf("applyAction err: %+v", err)
		return
	}
	if far.Action&report.APPLY_ACT_BUFF == 0 {
		return
	}
	switch {
	case action.DROP():
		// BUFF -> DROP
		for _, pdrid := range far.PDRIDs {
			for {
				_, ok := g.bsnl.Pop(lSeid, pdrid)
				if !ok {
					break
				}
			}
		}
	case action.FORW():
		// BUFF -> FORW
		for _, pdrid := range far.PDRIDs {
			oid := gtp5gnl.OID{lSeid, uint64(pdrid)}
			pdr, err := gtp5gnl.GetPDROID(g.client, g.link.link, oid)
			if err != nil {
				g.log.Warnf("applyAction GetPDROID err: %+v", err)
				continue
			}
			var qer *gtp5gnl.QER
			for _, qerId := range pdr.QERID {
				oid := gtp5gnl.OID{lSeid, uint64(qerId)}
				q, err := gtp5gnl.GetQEROID(g.client, g.link.link, oid)
				if err != nil {
					g.log.Warnf("applyAction GetQEROID err: %+v", err)
					continue
				}
				if q.QFI != 0 {
					qer = q
					break
				}
			}
			for {
				pkt, ok := g.bsnl.Pop(lSeid, pdrid)
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

// ============================================================================
// Plan-based methods for two-phase commit (validation + execution)
// ============================================================================

func (g *Gtp5g) BuildCreatePDRPlan(lSeid uint64, req *ie.IE) (*PDRPlan, error) {
	var pdrid uint64
	var attrs []nl.Attr
	var urrids []uint32

	ies, err := req.CreatePDR()
	if err != nil {
		return nil, err
	}

	for _, i := range ies {
		switch i.Type {
		case ie.PDRID:
			v, err := i.PDRID()
			if err != nil {
				return nil, errors.Wrap(err, "CreatePDR: failed to parse PDRID")
			}
			pdrid = uint64(v)
		case ie.Precedence:
			v, err := i.Precedence()
			if err != nil {
				return nil, errors.Wrap(err, "CreatePDR: failed to parse Precedence")
			}
			attrs = append(attrs, nl.Attr{
				Type:  gtp5gnl.PDR_PRECEDENCE,
				Value: nl.AttrU32(v),
			})
		case ie.PDI:
			v, err := g.newPdi(i)
			if err != nil {
				return nil, errors.Wrap(err, "CreatePDR: failed to parse PDI")
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
				return nil, errors.Wrap(err, "CreatePDR: failed to parse OuterHeaderRemoval")
			}
			attrs = append(attrs, nl.Attr{
				Type:  gtp5gnl.PDR_OUTER_HEADER_REMOVAL,
				Value: nl.AttrU8(v),
			})
			// ignore GTPUExternsionHeaderDeletion
		case ie.FARID:
			v, err := i.FARID()
			if err != nil {
				return nil, errors.Wrap(err, "CreatePDR: failed to parse FARID")
			}
			attrs = append(attrs, nl.Attr{
				Type:  gtp5gnl.PDR_FAR_ID,
				Value: nl.AttrU32(v),
			})
		case ie.QERID:
			v, err := i.QERID()
			if err != nil {
				// QER is optional, log but continue
				logger.FwderLog.Warnf("CreatePDR: Failed to parse QERID: %v", err)
				break
			}
			attrs = append(attrs, nl.Attr{
				Type:  gtp5gnl.PDR_QER_ID,
				Value: nl.AttrU32(v),
			})
		case ie.URRID:
			v, err := i.URRID()
			if err != nil {
				// URR is optional, log but continue
				logger.FwderLog.Warnf("CreatePDR: Failed to parse URRID: %v", err)
				break
			}
			attrs = append(attrs, nl.Attr{
				Type:  gtp5gnl.PDR_URR_ID,
				Value: nl.AttrU32(v),
			})
			urrids = append(urrids, v)
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
		Value: nl.AttrString(gtp5gnl.PdrAddrForNetlink),
	})

	return &PDRPlan{
		Op:         OpCreate,
		OID:        gtp5gnl.OID{lSeid, pdrid},
		Attrs:      attrs,
		OriginalIE: req,
		PDRID:      uint16(pdrid),
		URRIDs:     urrids,
	}, nil
}

func (g *Gtp5g) BuildUpdatePDRPlan(lSeid uint64, req *ie.IE) (*PDRPlan, error) {
	var pdrid uint64
	var attrs []nl.Attr
	var urrids []uint32

	ies, err := req.UpdatePDR()
	if err != nil {
		return nil, err
	}

	for _, i := range ies {
		switch i.Type {
		case ie.PDRID:
			v, err := i.PDRID()
			if err != nil {
				return nil, errors.Wrap(err, "UpdatePDR: failed to parse PDRID")
			}
			pdrid = uint64(v)
		case ie.Precedence:
			v, err := i.Precedence()
			if err != nil {
				// Precedence is optional in Update, log but continue
				logger.FwderLog.Warnf("UpdatePDR: Failed to parse Precedence: %v", err)
				break
			}
			attrs = append(attrs, nl.Attr{
				Type:  gtp5gnl.PDR_PRECEDENCE,
				Value: nl.AttrU32(v),
			})
		case ie.PDI:
			v, err := g.newPdi(i)
			if err != nil {
				return nil, errors.Wrap(err, "UpdatePDR: failed to parse PDI")
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
				logger.FwderLog.Warnf("UpdatePDR: Failed to parse OuterHeaderRemoval: %v", err)
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
				logger.FwderLog.Warnf("UpdatePDR: Failed to parse FARID: %v", err)
				break
			}
			attrs = append(attrs, nl.Attr{
				Type:  gtp5gnl.PDR_FAR_ID,
				Value: nl.AttrU32(v),
			})
		case ie.QERID:
			v, err := i.QERID()
			if err != nil {
				logger.FwderLog.Warnf("UpdatePDR: Failed to parse QERID: %v", err)
				break
			}
			attrs = append(attrs, nl.Attr{
				Type:  gtp5gnl.PDR_QER_ID,
				Value: nl.AttrU32(v),
			})
		case ie.URRID:
			v, err := i.URRID()
			if err != nil {
				logger.FwderLog.Warnf("UpdatePDR: Failed to parse URRID: %v", err)
				break
			}
			attrs = append(attrs, nl.Attr{
				Type:  gtp5gnl.PDR_URR_ID,
				Value: nl.AttrU32(v),
			})
			urrids = append(urrids, v)
		}
	}

	return &PDRPlan{
		Op:         OpUpdate,
		OID:        gtp5gnl.OID{lSeid, pdrid},
		Attrs:      attrs,
		OriginalIE: req,
		PDRID:      uint16(pdrid),
		URRIDs:     urrids,
	}, nil
}

func (g *Gtp5g) BuildRemovePDRPlan(lSeid uint64, req *ie.IE) (*PDRPlan, error) {
	v, err := req.PDRID()
	if err != nil {
		return nil, errors.New("not found PDRID")
	}

	return &PDRPlan{
		Op:         OpRemove,
		OID:        gtp5gnl.OID{lSeid, uint64(v)},
		Attrs:      nil,
		OriginalIE: req,
		PDRID:      v,
	}, nil
}

func (g *Gtp5g) BuildCreateFARPlan(lSeid uint64, req *ie.IE) (*FARPlan, error) {
	var farid uint64
	var attrs []nl.Attr

	ies, err := req.CreateFAR()
	if err != nil {
		return nil, err
	}

	for _, i := range ies {
		switch i.Type {
		case ie.FARID:
			v, err := i.FARID()
			if err != nil {
				return nil, err
			}
			farid = uint64(v)
		case ie.ApplyAction:
			b, err := i.ApplyAction()
			if err != nil {
				return nil, err
			}
			var act report.ApplyAction
			err = act.Unmarshal(b)
			if err != nil {
				return nil, err
			}
			attrs = append(attrs, nl.Attr{
				Type:  gtp5gnl.FAR_APPLY_ACTION,
				Value: nl.AttrU16(act.Flags),
			})
		case ie.ForwardingParameters:
			xs, err := i.ForwardingParameters()
			if err != nil {
				return nil, err
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

	return &FARPlan{
		Op:         OpCreate,
		OID:        gtp5gnl.OID{lSeid, farid},
		Attrs:      attrs,
		OriginalIE: req,
		FARID:      uint32(farid),
	}, nil
}

func (g *Gtp5g) BuildUpdateFARPlan(lSeid uint64, req *ie.IE) (*FARPlan, error) {
	var farid uint64
	var attrs []nl.Attr
	var applyAction *report.ApplyAction

	ies, err := req.UpdateFAR()
	if err != nil {
		return nil, err
	}

	for _, i := range ies {
		switch i.Type {
		case ie.FARID:
			v, err := i.FARID()
			if err != nil {
				return nil, err
			}
			farid = uint64(v)
		case ie.ApplyAction:
			b, err := i.ApplyAction()
			if err != nil {
				return nil, err
			}
			var act report.ApplyAction
			err = act.Unmarshal(b)
			if err != nil {
				return nil, err
			}
			attrs = append(attrs, nl.Attr{
				Type:  gtp5gnl.FAR_APPLY_ACTION,
				Value: nl.AttrU16(act.Flags),
			})
			applyAction = &act
		case ie.UpdateForwardingParameters:
			xs, err := i.UpdateForwardingParameters()
			if err != nil {
				return nil, err
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

	return &FARPlan{
		Op:          OpUpdate,
		OID:         gtp5gnl.OID{lSeid, farid},
		Attrs:       attrs,
		OriginalIE:  req,
		FARID:       uint32(farid),
		ApplyAction: applyAction,
	}, nil
}

func (g *Gtp5g) BuildRemoveFARPlan(lSeid uint64, req *ie.IE) (*FARPlan, error) {
	v, err := req.FARID()
	if err != nil {
		return nil, errors.New("not found FARID")
	}

	return &FARPlan{
		Op:         OpRemove,
		OID:        gtp5gnl.OID{lSeid, uint64(v)},
		Attrs:      nil,
		OriginalIE: req,
		FARID:      v,
	}, nil
}

func (g *Gtp5g) BuildCreateQERPlan(lSeid uint64, req *ie.IE) (*QERPlan, error) {
	var qerid uint64
	var attrs []nl.Attr

	ies, err := req.CreateQER()
	if err != nil {
		return nil, err
	}

	for _, i := range ies {
		switch i.Type {
		case ie.QERID:
			v, err := i.QERID()
			if err != nil {
				break
			}
			qerid = uint64(v)
		case ie.QERCorrelationID:
			v, err := i.QERCorrelationID()
			if err != nil {
				break
			}
			attrs = append(attrs, nl.Attr{
				Type:  gtp5gnl.QER_CORR_ID,
				Value: nl.AttrU32(v),
			})
		case ie.GateStatus:
			v, err := i.GateStatus()
			if err != nil {
				break
			}
			attrs = append(attrs, nl.Attr{
				Type:  gtp5gnl.QER_GATE,
				Value: nl.AttrU8(v),
			})
		case ie.MBR:
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
					{Type: gtp5gnl.QER_MBR_UL_HIGH32, Value: nl.AttrU32(ul >> 8)},
					{Type: gtp5gnl.QER_MBR_UL_LOW8, Value: nl.AttrU8(ul)},
					{Type: gtp5gnl.QER_MBR_DL_HIGH32, Value: nl.AttrU32(dl >> 8)},
					{Type: gtp5gnl.QER_MBR_DL_LOW8, Value: nl.AttrU8(dl)},
				},
			})
		case ie.GBR:
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
					{Type: gtp5gnl.QER_GBR_UL_HIGH32, Value: nl.AttrU32(ul >> 8)},
					{Type: gtp5gnl.QER_GBR_UL_LOW8, Value: nl.AttrU8(ul)},
					{Type: gtp5gnl.QER_GBR_DL_HIGH32, Value: nl.AttrU32(dl >> 8)},
					{Type: gtp5gnl.QER_GBR_DL_LOW8, Value: nl.AttrU8(dl)},
				},
			})
		case ie.QFI:
			v, err := i.QFI()
			if err != nil {
				break
			}
			attrs = append(attrs, nl.Attr{
				Type:  gtp5gnl.QER_QFI,
				Value: nl.AttrU8(v),
			})
		case ie.RQI:
			v, err := i.RQI()
			if err != nil {
				break
			}
			attrs = append(attrs, nl.Attr{
				Type:  gtp5gnl.QER_RQI,
				Value: nl.AttrU8(v),
			})
		case ie.PagingPolicyIndicator:
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

	return &QERPlan{
		Op:         OpCreate,
		OID:        gtp5gnl.OID{lSeid, qerid},
		Attrs:      attrs,
		OriginalIE: req,
		QERID:      uint32(qerid),
	}, nil
}

func (g *Gtp5g) BuildUpdateQERPlan(lSeid uint64, req *ie.IE) (*QERPlan, error) {
	var qerid uint64
	var attrs []nl.Attr

	ies, err := req.UpdateQER()
	if err != nil {
		return nil, err
	}

	for _, i := range ies {
		switch i.Type {
		case ie.QERID:
			v, err := i.QERID()
			if err != nil {
				break
			}
			qerid = uint64(v)
		case ie.QERCorrelationID:
			v, err := i.QERCorrelationID()
			if err != nil {
				break
			}
			attrs = append(attrs, nl.Attr{
				Type:  gtp5gnl.QER_CORR_ID,
				Value: nl.AttrU32(v),
			})
		case ie.GateStatus:
			v, err := i.GateStatus()
			if err != nil {
				break
			}
			attrs = append(attrs, nl.Attr{
				Type:  gtp5gnl.QER_GATE,
				Value: nl.AttrU8(v),
			})
		case ie.MBR:
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
					{Type: gtp5gnl.QER_MBR_UL_HIGH32, Value: nl.AttrU32(ul >> 8)},
					{Type: gtp5gnl.QER_MBR_UL_LOW8, Value: nl.AttrU8(ul)},
					{Type: gtp5gnl.QER_MBR_DL_HIGH32, Value: nl.AttrU32(dl >> 8)},
					{Type: gtp5gnl.QER_MBR_DL_LOW8, Value: nl.AttrU8(dl)},
				},
			})
		case ie.GBR:
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
					{Type: gtp5gnl.QER_GBR_UL_HIGH32, Value: nl.AttrU32(ul >> 8)},
					{Type: gtp5gnl.QER_GBR_UL_LOW8, Value: nl.AttrU8(ul)},
					{Type: gtp5gnl.QER_GBR_DL_HIGH32, Value: nl.AttrU32(dl >> 8)},
					{Type: gtp5gnl.QER_GBR_DL_LOW8, Value: nl.AttrU8(dl)},
				},
			})
		case ie.QFI:
			v, err := i.QFI()
			if err != nil {
				break
			}
			attrs = append(attrs, nl.Attr{
				Type:  gtp5gnl.QER_QFI,
				Value: nl.AttrU8(v),
			})
		case ie.RQI:
			v, err := i.RQI()
			if err != nil {
				break
			}
			attrs = append(attrs, nl.Attr{
				Type:  gtp5gnl.QER_RQI,
				Value: nl.AttrU8(v),
			})
		case ie.PagingPolicyIndicator:
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

	return &QERPlan{
		Op:         OpUpdate,
		OID:        gtp5gnl.OID{lSeid, qerid},
		Attrs:      attrs,
		OriginalIE: req,
		QERID:      uint32(qerid),
	}, nil
}

func (g *Gtp5g) BuildRemoveQERPlan(lSeid uint64, req *ie.IE) (*QERPlan, error) {
	v, err := req.QERID()
	if err != nil {
		return nil, errors.New("not found QERID")
	}

	return &QERPlan{
		Op:         OpRemove,
		OID:        gtp5gnl.OID{lSeid, uint64(v)},
		Attrs:      nil,
		OriginalIE: req,
		QERID:      v,
	}, nil
}

func (g *Gtp5g) BuildCreateURRPlan(lSeid uint64, req *ie.IE) (*URRPlan, error) {
	var urrid uint32
	var measureMethod uint8
	var rptTrig report.ReportingTrigger
	var measurePeriod time.Duration
	var measureInfoIE *ie.IE
	var attrs []nl.Attr

	ies, err := req.CreateURR()
	if err != nil {
		return nil, err
	}

	for _, i := range ies {
		switch i.Type {
		case ie.URRID:
			urrid, err = i.URRID()
			if err != nil {
				return nil, err
			}
		case ie.MeasurementMethod:
			measureMethod, err = i.MeasurementMethod()
			if err != nil {
				return nil, err
			}
			attrs = append(attrs, nl.Attr{
				Type:  gtp5gnl.URR_MEASUREMENT_METHOD,
				Value: nl.AttrU8(measureMethod),
			})
		case ie.ReportingTriggers:
			var v []byte
			v, err = i.ReportingTriggers()
			if err != nil {
				return nil, err
			}
			err = rptTrig.Unmarshal(v)
			if err != nil {
				return nil, err
			}
			attrs = append(attrs, nl.Attr{
				Type:  gtp5gnl.URR_REPORTING_TRIGGER,
				Value: nl.AttrU32(rptTrig.Flags),
			})
		case ie.MeasurementPeriod:
			measurePeriod, err = i.MeasurementPeriod()
			if err != nil {
				return nil, err
			}
			if measurePeriod <= 0 {
				return nil, errors.New("invalid measurement period")
			}
			// TODO: convert time.Duration -> ?
			attrs = append(attrs, nl.Attr{
				Type:  gtp5gnl.URR_MEASUREMENT_PERIOD,
				Value: nl.AttrU32(measurePeriod),
			})
		case ie.MeasurementInformation:
			measureInfoIE = i
			v, err := i.MeasurementInformation()
			if err != nil {
				return nil, err
			}
			attrs = append(attrs, nl.Attr{
				Type:  gtp5gnl.URR_MEASUREMENT_INFO,
				Value: nl.AttrU64(v),
			})
		case ie.VolumeThreshold:
			v, err := g.newVolumeThreshold(i)
			if err != nil {
				break
			}
			attrs = append(attrs, nl.Attr{
				Type:  gtp5gnl.URR_VOLUME_THRESHOLD,
				Value: v,
			})
		case ie.VolumeQuota:
			v, err := g.newVolumeQuota(i)
			if err != nil {
				break
			}
			attrs = append(attrs, nl.Attr{
				Type:  gtp5gnl.URR_VOLUME_QUOTA,
				Value: v,
			})
		}
	}

	if rptTrig.PERIO() && measurePeriod <= 0 {
		return nil, errors.New("invalid measurement period for PERIO trigger")
	}

	return &URRPlan{
		Op:               OpCreate,
		OID:              gtp5gnl.OID{lSeid, uint64(urrid)},
		Attrs:            attrs,
		OriginalIE:       req,
		URRID:            urrid,
		MeasureMethod:    measureMethod,
		ReportingTrigger: rptTrig,
		MeasurePeriod:    measurePeriod,
		MeasureInfoIE:    measureInfoIE,
	}, nil
}

// BuildUpdateURRPlan parses and validates UpdateURR IE without executing
func (g *Gtp5g) BuildUpdateURRPlan(lSeid uint64, req *ie.IE) (*URRPlan, error) {
	var urrid uint64
	var measureMethod uint8
	var measureInfoIE *ie.IE
	var attrs []nl.Attr

	ies, err := req.UpdateURR()
	if err != nil {
		return nil, err
	}

	for _, i := range ies {
		switch i.Type {
		case ie.URRID:
			v, err := i.URRID()
			if err != nil {
				return nil, err
			}
			urrid = uint64(v)
		case ie.MeasurementMethod:
			v, err := i.MeasurementMethod()
			if err != nil {
				return nil, err
			}
			measureMethod = v
			attrs = append(attrs, nl.Attr{
				Type:  gtp5gnl.URR_MEASUREMENT_METHOD,
				Value: nl.AttrU8(v),
			})
		case ie.ReportingTriggers:
			v, err := i.ReportingTriggers()
			if err != nil {
				return nil, err
			}
			var rptTrig report.ReportingTrigger
			err = rptTrig.Unmarshal(v)
			if err != nil {
				return nil, err
			}
			attrs = append(attrs, nl.Attr{
				Type:  gtp5gnl.URR_REPORTING_TRIGGER,
				Value: nl.AttrU32(rptTrig.Flags),
			})
		case ie.MeasurementPeriod:
			v, err := i.MeasurementPeriod()
			if err != nil {
				return nil, err
			}
			attrs = append(attrs, nl.Attr{
				Type:  gtp5gnl.URR_MEASUREMENT_PERIOD,
				Value: nl.AttrU32(v),
			})
		case ie.MeasurementInformation:
			measureInfoIE = i
			v, err := i.MeasurementInformation()
			if err != nil {
				return nil, err
			}
			attrs = append(attrs, nl.Attr{
				Type:  gtp5gnl.URR_MEASUREMENT_INFO,
				Value: nl.AttrU64(v),
			})
		case ie.VolumeThreshold:
			v, err := g.newVolumeThreshold(i)
			if err != nil {
				break
			}
			attrs = append(attrs, nl.Attr{
				Type:  gtp5gnl.URR_VOLUME_THRESHOLD,
				Value: v,
			})
		case ie.VolumeQuota:
			v, err := g.newVolumeQuota(i)
			if err != nil {
				break
			}
			attrs = append(attrs, nl.Attr{
				Type:  gtp5gnl.URR_VOLUME_QUOTA,
				Value: v,
			})
		}

		// TODO: should apply PERIO updateURR and receive final report from old URR
	}

	return &URRPlan{
		Op:            OpUpdate,
		OID:           gtp5gnl.OID{lSeid, urrid},
		Attrs:         attrs,
		OriginalIE:    req,
		URRID:         uint32(urrid),
		MeasureMethod: measureMethod,
		MeasureInfoIE: measureInfoIE,
	}, nil
}

func (g *Gtp5g) BuildRemoveURRPlan(lSeid uint64, req *ie.IE) (*URRPlan, error) {
	v, err := req.URRID()
	if err != nil {
		return nil, errors.New("not found URRID")
	}

	return &URRPlan{
		Op:         OpRemove,
		OID:        gtp5gnl.OID{lSeid, uint64(v)},
		Attrs:      nil,
		OriginalIE: req,
		URRID:      v,
	}, nil
}

func (g *Gtp5g) BuildQueryURRPlan(lSeid uint64, req *ie.IE) (*URRPlan, error) {
	v, err := req.URRID()
	if err != nil {
		return nil, errors.New("not found URRID")
	}

	return &URRPlan{
		Op:         OpRemove, // Query is not Create/Update/Remove, but we need a value
		OID:        gtp5gnl.OID{lSeid, uint64(v)},
		Attrs:      nil,
		OriginalIE: req,
		QueryURRID: v,
	}, nil
}

func (g *Gtp5g) BuildCreateBARPlan(lSeid uint64, req *ie.IE) (*BARPlan, error) {
	var barid uint64
	var attrs []nl.Attr

	ies, err := req.CreateBAR()
	if err != nil {
		return nil, err
	}

	for _, i := range ies {
		switch i.Type {
		case ie.BARID:
			v, err := i.BARID()
			if err != nil {
				return nil, err
			}
			barid = uint64(v)
		case ie.DownlinkDataNotificationDelay:
			v, err := i.DownlinkDataNotificationDelay()
			if err != nil {
				return nil, err
			}
			// TODO: convert time.Duration -> ?
			attrs = append(attrs, nl.Attr{
				Type:  gtp5gnl.BAR_DOWNLINK_DATA_NOTIFICATION_DELAY,
				Value: nl.AttrU8(v),
			})
		case ie.SuggestedBufferingPacketsCount:
			v, err := i.SuggestedBufferingPacketsCount()
			if err != nil {
				return nil, err
			}
			attrs = append(attrs, nl.Attr{
				Type:  gtp5gnl.BAR_BUFFERING_PACKETS_COUNT,
				Value: nl.AttrU16(v),
			})
		}
	}

	return &BARPlan{
		Op:         OpCreate,
		OID:        gtp5gnl.OID{lSeid, barid},
		Attrs:      attrs,
		OriginalIE: req,
		BARID:      uint8(barid),
	}, nil
}

func (g *Gtp5g) BuildUpdateBARPlan(lSeid uint64, req *ie.IE) (*BARPlan, error) {
	var barid uint64
	var attrs []nl.Attr

	ies, err := req.UpdateBAR()
	if err != nil {
		return nil, err
	}

	for _, i := range ies {
		switch i.Type {
		case ie.BARID:
			v, err := i.BARID()
			if err != nil {
				return nil, err
			}
			barid = uint64(v)
		case ie.DownlinkDataNotificationDelay:
			v, err := i.DownlinkDataNotificationDelay()
			if err != nil {
				return nil, err
			}
			// TODO: convert time.Duration -> ?
			attrs = append(attrs, nl.Attr{
				Type:  gtp5gnl.BAR_DOWNLINK_DATA_NOTIFICATION_DELAY,
				Value: nl.AttrU8(v),
			})
		case ie.SuggestedBufferingPacketsCount:
			v, err := i.SuggestedBufferingPacketsCount()
			if err != nil {
				return nil, err
			}
			attrs = append(attrs, nl.Attr{
				Type:  gtp5gnl.BAR_BUFFERING_PACKETS_COUNT,
				Value: nl.AttrU16(v),
			})
		}
	}

	return &BARPlan{
		Op:         OpUpdate,
		OID:        gtp5gnl.OID{lSeid, barid},
		Attrs:      attrs,
		OriginalIE: req,
		BARID:      uint8(barid),
	}, nil
}

func (g *Gtp5g) BuildRemoveBARPlan(lSeid uint64, req *ie.IE) (*BARPlan, error) {
	v, err := req.BARID()
	if err != nil {
		return nil, errors.New("not found BARID")
	}

	return &BARPlan{
		Op:         OpRemove,
		OID:        gtp5gnl.OID{lSeid, uint64(v)},
		Attrs:      nil,
		OriginalIE: req,
		BARID:      v,
	}, nil
}

// ExecuteModificationPlan executes all operations in the plan
// Uses best-effort execution: continues on failure, logs errors
func (g *Gtp5g) ExecuteModificationPlan(plan *ModificationPlan) (*ExecutionResult, error) {
	result := NewExecutionResult()

	for _, p := range plan.CreateFARs {
		if err := gtp5gnl.CreateFAROID(g.client, g.link.link, p.OID, p.Attrs); err != nil {
			g.log.Errorf("ExecuteModificationPlan: CreateFAR[%#x] failed: %v", p.FARID, err)
		}
	}

	for _, p := range plan.CreateQERs {
		if err := gtp5gnl.CreateQEROID(g.client, g.link.link, p.OID, p.Attrs); err != nil {
			g.log.Errorf("ExecuteModificationPlan: CreateQER[%#x] failed: %v", p.QERID, err)
		}
	}

	for _, p := range plan.CreateURRs {
		if p.ReportingTrigger.PERIO() && p.MeasurePeriod > 0 {
			g.ps.AddPeriodReportTimer(plan.SEID, p.URRID, p.MeasurePeriod)
		}
		if err := gtp5gnl.CreateURROID(g.client, g.link.link, p.OID, p.Attrs); err != nil {
			g.log.Errorf("ExecuteModificationPlan: CreateURR[%#x] failed: %v", p.URRID, err)
		}
	}

	for _, p := range plan.CreateBARs {
		if err := gtp5gnl.CreateBAROID(g.client, g.link.link, p.OID, p.Attrs); err != nil {
			g.log.Errorf("ExecuteModificationPlan: CreateBAR[%#x] failed: %v", p.BARID, err)
		}
	}

	for _, p := range plan.CreatePDRs {
		if err := gtp5gnl.CreatePDROID(g.client, g.link.link, p.OID, p.Attrs); err != nil {
			g.log.Errorf("ExecuteModificationPlan: CreatePDR[%#x] failed: %v", p.PDRID, err)
		}
	}

	for _, p := range plan.RemovePDRs {
		if err := gtp5gnl.RemovePDROID(g.client, g.link.link, p.OID); err != nil {
			g.log.Errorf("ExecuteModificationPlan: RemovePDR[%#x] failed: %v", p.PDRID, err)
		}
	}

	for _, p := range plan.RemoveBARs {
		if err := gtp5gnl.RemoveBAROID(g.client, g.link.link, p.OID); err != nil {
			g.log.Errorf("ExecuteModificationPlan: RemoveBAR[%#x] failed: %v", p.BARID, err)
		}
	}

	for _, p := range plan.RemoveURRs {
		g.ps.DelPeriodReportTimer(plan.SEID, p.URRID)
		rs, err := gtp5gnl.RemoveURROID(g.client, g.link.link, p.OID)
		if err != nil {
			g.log.Errorf("ExecuteModificationPlan: RemoveURR[%#x] failed: %v", p.URRID, err)
		}
		for _, r := range rs {
			result.USAReports = append(result.USAReports, g.convertUSAReport(r))
		}
	}

	for _, p := range plan.RemoveQERs {
		if err := gtp5gnl.RemoveQEROID(g.client, g.link.link, p.OID); err != nil {
			g.log.Errorf("ExecuteModificationPlan: RemoveQER[%#x] failed: %v", p.QERID, err)
		}
	}

	for _, p := range plan.RemoveFARs {
		if err := gtp5gnl.RemoveFAROID(g.client, g.link.link, p.OID); err != nil {
			g.log.Errorf("ExecuteModificationPlan: RemoveFAR[%#x] failed: %v", p.FARID, err)
		}
	}

	for _, p := range plan.UpdateFARs {
		if err := gtp5gnl.UpdateFAROID(g.client, g.link.link, p.OID, p.Attrs); err != nil {
			g.log.Errorf("ExecuteModificationPlan: UpdateFAR[%#x] failed: %v", p.FARID, err)
		}

		if p.ApplyAction != nil {
			g.applyAction(plan.SEID, int(p.FARID), *p.ApplyAction)
		}
	}

	for _, p := range plan.UpdateQERs {
		if err := gtp5gnl.UpdateQEROID(g.client, g.link.link, p.OID, p.Attrs); err != nil {
			g.log.Errorf("ExecuteModificationPlan: UpdateQER[%#x] failed: %v", p.QERID, err)
		}
	}

	for _, p := range plan.UpdateURRs {
		rs, err := gtp5gnl.UpdateURROID(g.client, g.link.link, p.OID, p.Attrs)
		if err != nil {
			g.log.Errorf("ExecuteModificationPlan: UpdateURR[%#x] failed: %v", p.URRID, err)
		}
		for _, r := range rs {
			result.USAReports = append(result.USAReports, g.convertUSAReport(r))
		}
	}

	for _, p := range plan.UpdateBARs {
		if err := gtp5gnl.UpdateBAROID(g.client, g.link.link, p.OID, p.Attrs); err != nil {
			g.log.Errorf("ExecuteModificationPlan: UpdateBAR[%#x] failed: %v", p.BARID, err)
		}
	}

	for _, p := range plan.UpdatePDRs {
		if err := gtp5gnl.UpdatePDROID(g.client, g.link.link, p.OID, p.Attrs); err != nil {
			g.log.Errorf("ExecuteModificationPlan: UpdatePDR[%#x] failed: %v", p.PDRID, err)
		}
	}

	// Execute Query operations
	for _, p := range plan.QueryURRs {
		rs, err := gtp5gnl.GetReportOID(g.client, g.link.link, p.OID)
		if err != nil {
			g.log.Errorf("ExecuteModificationPlan: QueryURR[%#x] failed: %v", p.QueryURRID, err)
			continue
		}
		for _, r := range rs {
			result.USAReports = append(result.USAReports, g.convertUSAReport(r))
		}
	}

	return result, nil
}

// ExecuteEstablishmentPlan executes Create operations for session establishment.
// Uses fail-fast semantics: returns error on first failure.
func (g *Gtp5g) ExecuteEstablishmentPlan(plan *ModificationPlan) (*ExecutionResult, error) {
	result := NewExecutionResult()

	for _, p := range plan.CreateFARs {
		if err := gtp5gnl.CreateFAROID(g.client, g.link.link, p.OID, p.Attrs); err != nil {
			return nil, errors.Wrapf(err, "EstablishmentPlan: CreateFAR[%#x] failed", p.FARID)
		}
	}

	for _, p := range plan.CreateQERs {
		if err := gtp5gnl.CreateQEROID(g.client, g.link.link, p.OID, p.Attrs); err != nil {
			return nil, errors.Wrapf(err, "EstablishmentPlan: CreateQER[%#x] failed", p.QERID)
		}
	}

	for _, p := range plan.CreateURRs {
		if p.ReportingTrigger.PERIO() && p.MeasurePeriod > 0 {
			g.ps.AddPeriodReportTimer(plan.SEID, p.URRID, p.MeasurePeriod)
		}
		if err := gtp5gnl.CreateURROID(g.client, g.link.link, p.OID, p.Attrs); err != nil {
			return nil, errors.Wrapf(err, "EstablishmentPlan: CreateURR[%#x] failed", p.URRID)
		}
	}

	for _, p := range plan.CreateBARs {
		if err := gtp5gnl.CreateBAROID(g.client, g.link.link, p.OID, p.Attrs); err != nil {
			return nil, errors.Wrapf(err, "EstablishmentPlan: CreateBAR[%#x] failed", p.BARID)
		}
	}

	for _, p := range plan.CreatePDRs {
		if err := gtp5gnl.CreatePDROID(g.client, g.link.link, p.OID, p.Attrs); err != nil {
			return nil, errors.Wrapf(err, "EstablishmentPlan: CreatePDR[%#x] failed", p.PDRID)
		}
	}

	return result, nil
}

// convertUSAReport converts gtp5gnl.USAReport to report.USAReport
func (g *Gtp5g) convertUSAReport(r gtp5gnl.USAReport) report.USAReport {
	usar := report.USAReport{
		URRID:       r.URRID,
		QueryUrrRef: r.QueryUrrRef,
		StartTime:   r.StartTime,
		EndTime:     r.EndTime,
	}
	usar.USARTrigger.Flags = r.USARTrigger
	usar.VolumMeasure = report.VolumeMeasure{
		TotalVolume:    r.VolMeasurement.TotalVolume,
		UplinkVolume:   r.VolMeasurement.UplinkVolume,
		DownlinkVolume: r.VolMeasurement.DownlinkVolume,
		TotalPktNum:    r.VolMeasurement.TotalPktNum,
		UplinkPktNum:   r.VolMeasurement.UplinkPktNum,
		DownlinkPktNum: r.VolMeasurement.DownlinkPktNum,
	}
	return usar
}
