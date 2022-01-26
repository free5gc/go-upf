package pfcp

import (
	"net"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"

	"github.com/free5gc/go-upf/internal/logger"
	"github.com/free5gc/go-upf/internal/report"
)

func (s *PfcpServer) ServeReport(addr net.Addr, seid uint64, r report.Report) {
	logger.PfcpLog.Infoln(s.listen, "ServeReport")
	switch r.Type() {
	case report.DLDR:
		r := r.(report.DLDReport)
		err := s.ServeDLDReport(addr, seid, r.PDRID)
		if err != nil {
			logger.PfcpLog.Errorln(s.listen, err)
		}
	}
}

func (s *PfcpServer) ServeDLDReport(addr net.Addr, seid uint64, pdrid uint16) error {
	logger.PfcpLog.Infoln(s.listen, "ServeDLDReport")

	seq := uint32(1)
	msg := message.NewSessionReportRequest(
		0,
		0,
		seid,
		seq,
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

	b, err := msg.Marshal()
	if err != nil {
		return err
	}

	_, err = s.conn.WriteTo(b, addr)
	return err
}
