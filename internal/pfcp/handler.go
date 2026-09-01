package pfcp

import (
	"net"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/wmnsk/go-pfcp/message"
)

type messageTransport interface {
	sendReqTo(message.Message, net.Addr) error
	sendRspTo(message.Message, net.Addr) error
}

// MessageHandler processes decoded PFCP messages against the local UPF state.
type MessageHandler struct {
	node      *LocalNode
	transport messageTransport
	log       *logrus.Entry
}

func newMessageHandler(
	node *LocalNode,
	transport messageTransport,
	log *logrus.Entry,
) *MessageHandler {
	return &MessageHandler{
		node:      node,
		transport: transport,
		log:       log,
	}
}

func (h *MessageHandler) HandleRequest(msg message.Message, addr net.Addr) error {
	switch req := msg.(type) {
	case *message.HeartbeatRequest:
		h.handleHeartbeatRequest(req, addr)
	case *message.AssociationSetupRequest:
		h.handleAssociationSetupRequest(req, addr)
	case *message.AssociationUpdateRequest:
		h.handleAssociationUpdateRequest(req, addr)
	case *message.AssociationReleaseRequest:
		h.handleAssociationReleaseRequest(req, addr)
	case *message.SessionEstablishmentRequest:
		h.handleSessionEstablishmentRequest(req, addr)
	case *message.SessionModificationRequest:
		h.handleSessionModificationRequest(req, addr)
	case *message.SessionDeletionRequest:
		h.handleSessionDeletionRequest(req, addr)
	default:
		return errors.Errorf("MessageHandler.HandleRequest: unknown message type: %d", msg.MessageType())
	}
	return nil
}

func (h *MessageHandler) HandleResponse(
	msg message.Message,
	addr net.Addr,
	req message.Message,
) error {
	switch rsp := msg.(type) {
	case *message.SessionReportResponse:
		h.handleSessionReportResponse(rsp, addr, req)
	default:
		return errors.Errorf("MessageHandler.HandleResponse: unknown message type: %d", msg.MessageType())
	}
	return nil
}

func (h *MessageHandler) HandleRequestTimeout(msg message.Message, addr net.Addr) error {
	switch req := msg.(type) {
	case *message.SessionReportRequest:
		h.handleSessionReportRequestTimeout(req, addr)
	default:
		return errors.Errorf(
			"MessageHandler.HandleRequestTimeout: unknown message type: %d",
			msg.MessageType(),
		)
	}
	return nil
}
