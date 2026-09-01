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

// Dispatcher routes decoded PFCP messages to local UPF service operations.
type Dispatcher struct {
	node      *LocalNode
	transport messageTransport
	log       *logrus.Entry
}

func newDispatcher(
	node *LocalNode,
	transport messageTransport,
	log *logrus.Entry,
) *Dispatcher {
	return &Dispatcher{
		node:      node,
		transport: transport,
		log:       log,
	}
}

func (d *Dispatcher) HandleRequest(msg message.Message, addr net.Addr) error {
	switch req := msg.(type) {
	case *message.HeartbeatRequest:
		d.handleHeartbeatRequest(req, addr)
	case *message.AssociationSetupRequest:
		d.handleAssociationSetupRequest(req, addr)
	case *message.AssociationUpdateRequest:
		d.handleAssociationUpdateRequest(req, addr)
	case *message.AssociationReleaseRequest:
		d.handleAssociationReleaseRequest(req, addr)
	case *message.SessionEstablishmentRequest:
		d.handleSessionEstablishmentRequest(req, addr)
	case *message.SessionModificationRequest:
		d.handleSessionModificationRequest(req, addr)
	case *message.SessionDeletionRequest:
		d.handleSessionDeletionRequest(req, addr)
	default:
		return errors.Errorf("Dispatcher.HandleRequest: unknown message type: %d", msg.MessageType())
	}
	return nil
}

func (d *Dispatcher) HandleResponse(
	msg message.Message,
	addr net.Addr,
	req message.Message,
) error {
	switch rsp := msg.(type) {
	case *message.SessionReportResponse:
		d.handleSessionReportResponse(rsp, addr, req)
	default:
		return errors.Errorf("Dispatcher.HandleResponse: unknown message type: %d", msg.MessageType())
	}
	return nil
}

func (d *Dispatcher) HandleRequestTimeout(msg message.Message, addr net.Addr) error {
	switch req := msg.(type) {
	case *message.SessionReportRequest:
		d.handleSessionReportRequestTimeout(req, addr)
	default:
		return errors.Errorf(
			"Dispatcher.HandleRequestTimeout: unknown message type: %d",
			msg.MessageType(),
		)
	}
	return nil
}
