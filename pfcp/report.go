package pfcp

import (
	"net"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

func (s *PfcpServer) SendDLDataReport(addr net.Addr, seid uint64, pdrid uint16) error {
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
