package pfcp

import (
	"net"

	"github.com/tim-ywliu/go-pfcp/ie"
	"github.com/tim-ywliu/go-pfcp/message"
)

func (s *PfcpServer) handleHeartbeatRequest(req *message.HeartbeatRequest, addr net.Addr) {
	s.log.Infoln("handleHeartbeatRequest")

	rsp := message.NewHeartbeatResponse(
		req.Header.SequenceNumber,
		ie.NewRecoveryTimeStamp(s.recoveryTime),
	)

	err := s.sendRspTo(rsp, addr)
	if err != nil {
		s.log.Errorln(err)
		return
	}
}
