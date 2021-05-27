package forwarder

import (
	"net"
	"os"

	"github.com/vishvananda/netlink"
	"github.com/wmnsk/go-pfcp/ie"
)

type Gtp5g struct {
	link *netlink.Gtp5g
	conn *net.UDPConn
	f    *os.File
}

func OpenGtp5g() (*Gtp5g, error) {
	g := new(Gtp5g)

	_, err := netlink.LinkByName("gtp5g0")
	if err == nil {
		return nil, err
	}

	laddr, err := net.ResolveUDPAddr("udp", "0.0.0.0:2152")
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return nil, err
	}

	// TODO: Duplicate fd
	f, err := conn.File()
	if err != nil {
		conn.Close()
		return nil, err
	}
	attr := netlink.NewLinkAttrs()
	attr.Name = "gtp5g0"
	link := &netlink.Gtp5g{LinkAttrs: attr, FD1: int(f.Fd())}
	err = netlink.LinkAdd(link)
	if err != nil {
		f.Close()
		conn.Close()
		return nil, err
	}

	err = netlink.LinkSetUp(link)
	if err != nil {
		netlink.LinkDel(link)
		f.Close()
		conn.Close()
		return nil, err
	}

	g.f = f
	g.conn = conn
	g.link = link

	return g, err
}

func (g *Gtp5g) Close() {
	netlink.LinkDel(g.link)
	g.conn.Close()
	g.f.Close()
}

func (g *Gtp5g) newSdfFilter(i *ie.IE) (*netlink.Gtp5gSdfFilter, error) {
	sdf := new(netlink.Gtp5gSdfFilter)

	v, err := i.SDFFilter()
	if err != nil {
		return nil, err
	}

	fields := 0

	if v.HasFD() {
		// TODO:
		// v.FlowDescription string
		sdf.Rule = &netlink.Gtp5gIpFilterRule{
			Action:    12,
			Direction: 13,
			Proto:     14,
			Src:       net.IPv4(15, 16, 17, 18),
			Smask:     net.IPv4(255, 255, 255, 0),
			Dest:      net.IPv4(19, 20, 21, 22),
			Dmask:     net.IPv4(255, 255, 0, 0),
			SportList: []uint32{23, 24, 25},
			DportList: []uint32{26, 27, 28},
		}
		fields++
	}
	if v.HasTTC() {
		// TODO:
		// v.ToSTrafficClass string
		var x uint16
		x = 29
		sdf.TosTrafficClass = &x
		fields++
	}
	if v.HasSPI() {
		// TODO:
		// v.SecurityParameterIndex string
		var x uint32
		x = 30
		sdf.SecurityParamIdx = &x
		fields++
	}
	if v.HasFL() {
		// TODO:
		// v.FlowLabel string
		var x uint32
		x = 31
		sdf.FlowLabel = &x
		fields++
	}
	if v.HasBID() {
		sdf.BiId = &v.SDFFilterID
		fields++
	}

	if fields == 0 {
		return nil, nil
	}

	return sdf, nil
}

func (g *Gtp5g) newPdi(i *ie.IE) (*netlink.Gtp5gPdi, error) {
	pdi := new(netlink.Gtp5gPdi)

	ies, err := i.PDI()
	if err != nil {
		return nil, err
	}
	fields := 0
	for _, x := range ies {
		switch x.Type {
		case ie.SourceInterface:
		case ie.FTEID:
			v, err := x.FTEID()
			if err != nil {
				break
			}
			pdi.FTeid = &netlink.Gtp5gLocalFTeid{
				Teid:         v.TEID,
				GtpuAddrIpv4: v.IPv4Address,
			}
			fields++
		case ie.NetworkInstance:
		case ie.UEIPAddress:
			v, err := x.UEIPAddress()
			if err != nil {
				break
			}
			pdi.UeAddrIpv4 = &v.IPv4Address
			fields++
		case ie.SDFFilter:
			v, err := g.newSdfFilter(x)
			if err != nil {
				break
			}
			pdi.Sdf = v
			fields++
		case ie.ApplicationID:
		}
	}

	if fields == 0 {
		return nil, nil
	}

	return pdi, nil
}

func (g *Gtp5g) CreatePDR(req *ie.IE) error {
	var pdr netlink.Gtp5gPdr

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
			pdr.Id = v
		case ie.Precedence:
			v, err := i.Precedence()
			if err != nil {
				break
			}
			pdr.Precedence = &v
		case ie.PDI:
			v, err := g.newPdi(i)
			if err != nil {
				break
			}
			pdr.Pdi = v
		case ie.OuterHeaderRemoval:
			v, err := i.OuterHeaderRemovalDescription()
			if err != nil {
				break
			}
			pdr.OuterHdrRemoval = &v
			// ignore GTPUExternsionHeaderDeletion
		case ie.FARID:
			v, err := i.FARID()
			if err != nil {
				break
			}
			pdr.FarId = &v
		case ie.QERID:
			v, err := i.QERID()
			if err != nil {
				break
			}
			pdr.QerId = &v
		}
	}

	// TODO:
	// Not in 3GPP spec, just used for routing
	// var roleAddrIpv4 net.IP
	// roleAddrIpv4 = net.IPv4(34, 35, 36, 37)
	// pdr.RoleAddrIpv4 = &roleAddrIpv4

	// TODO:
	// Not in 3GPP spec, just used for buffering
	// unixSockPath := "/tmp/free5gc_unix_sock"
	// pdr.UnixSockPath = &unixSockPath

	return netlink.Gtp5gAddPdr(g.link, &pdr)
}

func (g *Gtp5g) UpdatePDR(req *ie.IE) error {
	var pdr netlink.Gtp5gPdr

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
			pdr.Id = v
		case ie.Precedence:
			v, err := i.Precedence()
			if err != nil {
				break
			}
			pdr.Precedence = &v
		case ie.PDI:
			v, err := g.newPdi(i)
			if err != nil {
				break
			}
			pdr.Pdi = v
		case ie.OuterHeaderRemoval:
			v, err := i.OuterHeaderRemovalDescription()
			if err != nil {
				break
			}
			pdr.OuterHdrRemoval = &v
			// ignore GTPUExternsionHeaderDeletion
		case ie.FARID:
			v, err := i.FARID()
			if err != nil {
				break
			}
			pdr.FarId = &v
		case ie.QERID:
			v, err := i.QERID()
			if err != nil {
				break
			}
			pdr.QerId = &v
		}
	}

	return netlink.Gtp5gModPdr(g.link, &pdr)
}

func (g *Gtp5g) RemovePDR(req *ie.IE) error {
	var pdr netlink.Gtp5gPdr

	return netlink.Gtp5gDelPdr(g.link, &pdr)
}

func (g *Gtp5g) newForwardingParameter(ies []*ie.IE) (*netlink.Gtp5gForwardingParameter, error) {
	p := new(netlink.Gtp5gForwardingParameter)

	fields := 0
	for _, x := range ies {
		switch x.Type {
		case ie.DestinationInterface:
		case ie.NetworkInstance:
		case ie.OuterHeaderCreation:
			v, err := x.OuterHeaderCreation()
			if err != nil {
				break
			}
			p.HdrCreation = &netlink.Gtp5gOuterHeaderCreation{
				Desp: v.OuterHeaderCreationDescription,
			}
			if x.HasTEID() {
				p.HdrCreation.Teid = v.TEID
				// GTPv1-U port
				p.HdrCreation.Port = 2152
			} else {
				p.HdrCreation.Port = v.PortNumber
			}
			if x.HasIPv4() {
				p.HdrCreation.PeerAddrIpv4 = v.IPv4Address
			}
			fields++
		case ie.ForwardingPolicy:
			v, err := x.ForwardingPolicyIdentifier()
			if err != nil {
				break
			}
			p.FwdPolicy = &netlink.Gtp5gForwardingPolicy{
				Identifier: v,
			}
			fields++
		}
	}

	if fields == 0 {
		return nil, nil
	}

	return p, nil
}

func (g *Gtp5g) CreateFAR(req *ie.IE) error {
	var far netlink.Gtp5gFar

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
			far.Id = v
		case ie.ApplyAction:
			v, err := i.ApplyAction()
			if err != nil {
				return err
			}
			far.ApplyAction = v
		case ie.ForwardingParameters:
			xs, err := i.ForwardingParameters()
			if err != nil {
				return err
			}
			v, err := g.newForwardingParameter(xs)
			if err != nil {
				break
			}
			far.FwdParam = v
		}
	}

	return netlink.Gtp5gAddFar(g.link, &far)
}

func (g *Gtp5g) UpdateFAR(req *ie.IE) error {
	var far netlink.Gtp5gFar

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
			far.Id = v
		case ie.ApplyAction:
			v, err := i.ApplyAction()
			if err != nil {
				return err
			}
			far.ApplyAction = v
		case ie.UpdateForwardingParameters:
			xs, err := i.UpdateForwardingParameters()
			if err != nil {
				return err
			}
			v, err := g.newForwardingParameter(xs)
			if err != nil {
				break
			}
			far.FwdParam = v
		}
	}

	return netlink.Gtp5gModFar(g.link, &far)
}

func (g *Gtp5g) RemoveFAR(req *ie.IE) error {
	var far netlink.Gtp5gFar
	return netlink.Gtp5gDelFar(g.link, &far)
}

func (g *Gtp5g) CreateQER(req *ie.IE) error {
	var qer netlink.Gtp5gQer

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
			qer.Id = v
		case ie.QERCorrelationID:
			// C
			v, err := i.QERCorrelationID()
			if err != nil {
				break
			}
			qer.QerCorrId = v
		case ie.GateStatus:
			// M
			v, err := i.GateStatus()
			if err != nil {
				break
			}
			qer.UlDlGate = v
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
			qer.Mbr = netlink.Gtp5gMbr{
				UlHigh: uint32(ul >> 8),
				UlLow:  uint8(ul),
				DlHigh: uint32(dl >> 8),
				DlLow:  uint8(dl),
			}
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
			qer.Gbr = netlink.Gtp5gGbr{
				UlHigh: uint32(ul >> 8),
				UlLow:  uint8(ul),
				DlHigh: uint32(dl >> 8),
				DlLow:  uint8(dl),
			}
		case ie.QFI:
			// C
			v, err := i.QFI()
			if err != nil {
				break
			}
			qer.Qfi = v
		case ie.RQI:
			// C
			v, err := i.RQI()
			if err != nil {
				break
			}
			qer.Rqi = v
		case ie.PagingPolicyIndicator:
			// C
			v, err := i.PagingPolicyIndicator()
			if err != nil {
				break
			}
			qer.Ppi = v
		}
	}

	return netlink.Gtp5gAddQer(g.link, &qer)
}

func (g *Gtp5g) UpdateQER(req *ie.IE) error {
	var qer netlink.Gtp5gQer

	return netlink.Gtp5gModQer(g.link, &qer)
}

func (g *Gtp5g) RemoveQER(req *ie.IE) error {
	var qer netlink.Gtp5gQer

	return netlink.Gtp5gDelQer(g.link, &qer)
}
