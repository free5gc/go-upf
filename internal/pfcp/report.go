package pfcp

import (
	"fmt"
	"net"

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

	if r.Action&buff.BUFF != 0 && len(r.BufPkt) > 0 {
		dldr, ok := r.Report.(report.DLDReport)
		if ok {
			sess.Push(dldr.PDRID, r.BufPkt)
		}
	}
	if r.Action&buff.NOCP != 0 {
		addr := fmt.Sprintf("%s:%d", sess.rnode.ID, factory.UpfPfcpDefaultPort)
		laddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			return
		}

		switch r.Report.Type() {
		case report.DLDR:
			dldr := r.Report.(report.DLDReport)
			err := s.ServeDLDReport(laddr, r.SEID, dldr.PDRID)
			if err != nil {
				s.log.Errorln(err)
			}
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
	return err
}
