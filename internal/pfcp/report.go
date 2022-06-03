package pfcp

import (
	"fmt"
	"net"

	"github.com/pkg/errors"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"

	"github.com/free5gc/go-upf/internal/buff"
	"github.com/free5gc/go-upf/internal/report"
	"github.com/free5gc/go-upf/pkg/factory"
)

func (s *PfcpServer) ServeReport(r *report.SessReport) {
	s.log.Debugln("ServeReport")
	sess, err := s.lnode.Sess(r.SEID)
	if err != nil {
		s.log.Errorln(err)
		return
	}

	addr := fmt.Sprintf("%s:%d", sess.rnode.ID, factory.UpfPfcpDefaultPort)
	laddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return
	}

	if r.Action&buff.BUFF != 0 && len(r.BufPkt) > 0 {
		dldr, ok := r.Report.(report.DLDReport)
		if ok {
			sess.Push(dldr.PDRID, r.BufPkt)
		}
	}
	if r.Action&buff.NOCP != 0 && r.Report.Type() == report.DLDR {
		dldr := r.Report.(report.DLDReport)
		err := s.ServeDLDReport(laddr, r.SEID, dldr.PDRID)
		if err != nil {
			s.log.Errorln(err)
		}
	}

	switch r.Report.Type() {
	case report.USAR:
		usar := r.Report.(report.USAReport)
		err := s.ServeUSAReport(laddr, r.SEID, &usar)
		if err != nil {
			s.log.Errorln(err)
		}
	}
}

func (s *PfcpServer) ServeDLDReport(addr net.Addr, seid uint64, pdrid uint16) error {
	s.log.Infoln("ServeDLDReport")

	req := message.NewSessionReportRequest(
		0,
		0,
		seid,
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

	err := s.sendReqTo(req, addr, nil) // No waiting for rsp
	return errors.Wrap(err, "ServeDLDReport")
}

func (s *PfcpServer) ServeUSAReport(addr net.Addr, seid uint64, usar *report.USAReport) error {
	s.log.Infoln("ServeUSAReport")

	tr := &usar.USARTrigger
	req := message.NewSessionReportRequest(
		0,
		0,
		seid,
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
			// TODO:
		),
	)

	err := s.sendReqTo(req, addr, nil) // No waiting for rsp
	return errors.Wrap(err, "ServeUSAReport")
}
