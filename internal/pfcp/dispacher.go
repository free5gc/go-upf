package pfcp

import (
	"net"

	"github.com/pkg/errors"
	"github.com/wmnsk/go-pfcp/message"
)

func (s *PfcpServer) dispacher(buf []byte, addr net.Addr) error {
	msgtmp, err := message.Parse(buf)
	if err != nil {
		return errors.Wrap(err, "pfcp dispacher parse")
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
	default:
		return errors.Errorf("pfcp dispacher unknown msg type: %d", msgtmp.MessageType())
	}
	return nil
}
