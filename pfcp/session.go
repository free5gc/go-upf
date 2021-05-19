package pfcp

import (
	"net"

	"github.com/wmnsk/go-pfcp/message"

	"github.com/m-asama/upf/logger"
)

func (s *PfcpServer) handleSessionEstablishmentRequest(msg *message.SessionEstablishmentRequest, addr net.Addr) {
	logger.PfcpLog.Infoln(s.listen, "handleSessionEstablishmentRequest")
}

func (s *PfcpServer) handleSessionModificationRequest(msg *message.SessionModificationRequest, addr net.Addr) {
	logger.PfcpLog.Infoln(s.listen, "handleSessionModificationRequest")
}

func (s *PfcpServer) handleSessionDeletionRequest(msg *message.SessionDeletionRequest, addr net.Addr) {
	logger.PfcpLog.Infoln(s.listen, "handleSessionDeletionRequest")
}
