package pfcp

import (
	"fmt"
	"net"
	"time"

	"github.com/pkg/errors"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"

	"github.com/free5gc/go-upf/internal/logger"
	"github.com/free5gc/go-upf/internal/report"
	"github.com/free5gc/go-upf/pkg/factory"
)

func (s *PfcpServer) PeriodMeasurement(sess *Sess, ie *ie.IE) {

	trigger, err := ie.ReportingTriggers()
	logger.ReportLog.Info("trigger", trigger)

	if err != nil {
		return
	}

	period, err := ie.MeasurementPeriod()

	if err != nil {
		return
	}

	id, err := ie.URRID()
	if err != nil {
		return
	}
	sess.log.Errorf("IN perio report")
	//check for perio flag
	if trigger&256 == 256 && period > 0 {
		logger.ReportLog.Info("Reporting Trigger PERIO")
		perio, err := ie.MeasurementPeriod()

		if err != nil {
			sess.log.Errorf("Get period err: %+v", err)
			return
		}

		timer := time.NewTicker(perio)

		go func() {
			for {
				select {
				case <-timer.C:
					usar, err := sess.GetReport(ie)
					sess.log.Errorf("usar", usar)
					if err != nil {
						sess.log.Errorf("Est GetReport error: %+v", err)
						return
					}
					addr := fmt.Sprintf("%s:%d", sess.rnode.ID, factory.UpfPfcpDefaultPort)
					laddr, err := net.ResolveUDPAddr("udp", addr)
					if err != nil {
						return
					}

					s.ServeUSAReport(laddr, sess.LocalID, usar)
				case <-sess.EndPERIO[id]:
					sess.log.Info("End PERIOD MEASUREMENT for urr(%+v)", id)
					return

				}
			}
		}()

	}

}

func (s *PfcpServer) ServeReport(rp *report.SessReport) {
	s.log.Debugf("ServeReport: %v", rp)
	sess, err := s.lnode.Sess(rp.SEID)
	if err != nil {
		s.log.Errorln(err)
		return
	}

	addr := fmt.Sprintf("%s:%d", sess.rnode.ID, factory.UpfPfcpDefaultPort)
	laddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return
	}

	if rp.Action&report.BUFF != 0 && len(rp.BufPkt) > 0 {
		dldr, ok := rp.Report.(report.DLDReport)
		if ok {
			sess.Push(dldr.PDRID, rp.BufPkt)
		}
	}

	switch r := rp.Report.(type) {
	case report.DLDReport:
		if rp.Action&report.NOCP == 0 {
			return
		}
		err := s.ServeDLDReport(laddr, rp.SEID, r.PDRID)
		if err != nil {
			s.log.Errorln(err)
		}
	case report.USAReport:
		err := s.ServeUSAReport(laddr, rp.SEID, &r)
		if err != nil {
			s.log.Errorln(err)
		}
	default:
		s.log.Warnf("Unsupported Report(%d)", rp.Report.Type())
	}
}

func (s *PfcpServer) ServeDLDReport(addr net.Addr, lSeid uint64, pdrid uint16) error {
	s.log.Infoln("ServeDLDReport")

	sess, err := s.lnode.Sess(lSeid)
	if err != nil {
		return errors.Wrap(err, "ServeDLDReport")
	}

	req := message.NewSessionReportRequest(
		0,
		0,
		sess.RemoteID,
		0,
		0,
		ie.NewReportType(0, 0, 0, 1),
		ie.NewDownlinkDataReport(
			ie.NewPDRID(pdrid),
			/*
				ie.NewDownlinkDataServiceInformation(
					true,
					true,
					ppi,
					qfi,
				),
			*/
		),
	)

	err = s.sendReqTo(req, addr)
	return errors.Wrap(err, "ServeDLDReport")
}

func (s *PfcpServer) ServeUSAReport(addr net.Addr, lSeid uint64, usar *report.USAReport) error {

	sess, err := s.lnode.Sess(lSeid)
	if err != nil {
		return errors.Wrap(err, "ServeDLDReport")
	}

	tr := &usar.USARTrigger
	vm := &usar.VolMeasurement

	req := message.NewSessionReportRequest(
		0,
		0,
		sess.RemoteID,
		0,
		0,
		ie.NewReportType(0, 0, 1, 0),
		ie.NewUsageReportWithinSessionReportRequest(
			ie.NewURRID(usar.URRID),
			ie.NewURSEQN(usar.URSEQN),
			ie.NewUsageReportTrigger(
				tr.PERIO|tr.VOLTH<<1|tr.TIMTH<<2|tr.QUHTI<<3|tr.START<<4|tr.STOPT<<5|tr.DROTH<<6|tr.IMMER<<7,
				tr.VOLQU|tr.TIMQU<<1|tr.LIUSA<<2|tr.TERMR<<3|tr.MONIT<<4|tr.ENVCL<<5|tr.MACAR<<6|tr.EVETH<<7,
				tr.EVEQU|tr.TEBUR<<1|tr.IPMJL<<2|tr.QUVTI<<3|tr.EMRRE<<4,
			),
			ie.NewVolumeMeasurement(vm.Flag, vm.TotalVolume, vm.UplinkVolume, vm.DownlinkVolume,
				vm.TotalPktNum, vm.UplinkPktNum, vm.DownlinkPktNum),
			// TODO:
		),
	)

	err = s.sendReqTo(req, addr)
	return errors.Wrap(err, "ServeUSAReport")
}
