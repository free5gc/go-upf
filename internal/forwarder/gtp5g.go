package forwarder

import (
	"net"
	"sync"
	"syscall"

	"github.com/hashicorp/go-version"
	"github.com/khirono/go-nl"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/free5gc/go-gtp5gnl"
	"github.com/free5gc/go-upf/internal/forwarder/buffnetlink"
	"github.com/free5gc/go-upf/internal/forwarder/perio"
	"github.com/free5gc/go-upf/internal/gtpv1"
	"github.com/free5gc/go-upf/internal/logger"
	"github.com/free5gc/go-upf/internal/report"
	logger_util "github.com/free5gc/util/logger"
)

const (
	expectedMinGtp5gVersion string = "0.9.3"
	expectedMaxGtp5gVersion string = "0.10.3"
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
		log: logger.FwderLog.WithField(logger_util.FieldCategory, "Gtp5g"),
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
	if g.iptables != nil {
		for _, err := range g.iptables.Cleanup() {
			logger.MainLog.Warnf("iptables cleanup err: %+v", err)
		}
	}
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
}

func (g *Gtp5g) checkVersion() error {
	info, err := gtp5gnl.GetVersionInfo(g.client)
	if err != nil {
		return err
	}

	return validateGtp5gVersionInfo(info)
}

func validateGtp5gVersionInfo(info *gtp5gnl.VersionInfo) error {
	if info == nil {
		return errors.New("gtp5g returned no version information")
	}
	if info.DriverVersion == "" {
		return errors.New("gtp5g returned an empty driver version")
	}

	expMinVer, err := version.NewVersion(expectedMinGtp5gVersion)
	if err != nil {
		return errors.Wrapf(err, "parse expectedMinGtp5gVersion err")
	}
	expMaxVer, err := version.NewVersion(expectedMaxGtp5gVersion)
	if err != nil {
		return errors.Wrapf(err, "parse expectedMaxGtp5gVersion err")
	}
	nowVer, err := version.NewVersion(info.DriverVersion)
	if err != nil {
		return errors.Wrapf(err, "Unable to parse gtp5g version(%s)", info.DriverVersion)
	}
	if nowVer.LessThan(expMinVer) || nowVer.GreaterThanOrEqual(expMaxVer) {
		return errors.Errorf(
			"gtp5g version(%v) should be %s <= version < %s , please update it",
			nowVer, expectedMinGtp5gVersion, expectedMaxGtp5gVersion)
	}

	if info.SharedMarkABI == nil {
		return errors.Errorf(
			"gtp5g version(%v) does not advertise shared mark ABI support",
			nowVer,
		)
	}
	if *info.SharedMarkABI != gtp5gnl.SHARED_MARK_ABI_VERSION {
		return errors.Errorf(
			"gtp5g shared mark ABI(%d) should be %d",
			*info.SharedMarkABI,
			gtp5gnl.SHARED_MARK_ABI_VERSION,
		)
	}

	return nil
}

func (g *Gtp5g) Link() *Gtp5gLink {
	return g.link
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

const bitsPerKilobit uint64 = 1000

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
