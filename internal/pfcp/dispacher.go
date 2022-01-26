package pfcp

import (
	"github.com/wmnsk/go-pfcp/message"

	"github.com/free5gc/go-upf/internal/logger"
)

func (s *PfcpServer) dispacher(startDispacher chan bool) {
	logger.PfcpLog.Infoln(s.listen, "dispacher waiting")
	ok := <-startDispacher
	if !ok {
		logger.PfcpLog.Infoln(s.listen, "dispacher start fail")
		return
	}
	logger.PfcpLog.Infoln(s.listen, "dispacher starting")
	buf := make([]byte, 1500)
	for {
		n, addr, err := s.conn.ReadFrom(buf)
		if err != nil {
			logger.PfcpLog.Errorf("%+v", err)
			break
		}
		msgtmp, err := message.Parse(buf[:n])
		if err != nil {
			logger.PfcpLog.Errorf("ignored undecodable message: %x, error: %s", buf[:n], err)
			continue
		}
		switch msg := msgtmp.(type) {
		case *message.HeartbeatRequest:
			s.handleHeartbeatRequest(msg, addr)
		case *message.AssociationSetupRequest:
			s.handleAssociationSetupRequest(msg, addr)
		case *message.AssociationUpdateRequest:
			s.handleAssociationUpdateRequest(msg, addr)
		case *message.AssociationReleaseRequest:
			s.handleAssociationReleaseRequest(msg, addr)
		case *message.SessionEstablishmentRequest:
			s.handleSessionEstablishmentRequest(msg, addr)
		case *message.SessionModificationRequest:
			s.handleSessionModificationRequest(msg, addr)
		case *message.SessionDeletionRequest:
			s.handleSessionDeletionRequest(msg, addr)
		}
	}
	logger.PfcpLog.Infoln(s.listen, "dispacher exit")
}
