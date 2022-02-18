package pfcp

import (
	"net"

	"github.com/wmnsk/go-pfcp/message"
)

func (s *PfcpServer) handleHeartbeatRequest(msg *message.HeartbeatRequest, addr net.Addr) {
	s.log.Infoln("handleHeartbeatRequest")
}
