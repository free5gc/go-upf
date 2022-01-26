package pfcp

import (
	"net"

	"github.com/wmnsk/go-pfcp/message"

	"github.com/free5gc/go-upf/internal/logger"
)

func (s *PfcpServer) handleHeartbeatRequest(msg *message.HeartbeatRequest, addr net.Addr) {
	logger.PfcpLog.Infoln(s.listen, "handleHeartbeatRequest")
}
