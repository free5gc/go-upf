package pfcp

import (
	"net"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

func (h *MessageHandler) handleAssociationSetupRequest(
	req *message.AssociationSetupRequest,
	addr net.Addr,
) {
	h.log.Infoln("handleAssociationSetupRequest")

	// 1. Validate NodeID IE (Mandatory)
	if req.NodeID == nil {
		h.log.Errorf("Association Setup failed: mandatory IE missing: NodeID")
		return
	}

	// 2. Validate NodeID IE can be parsed correctly
	peerNodeID, err := req.NodeID.NodeID()
	if err != nil {
		h.log.Errorf("Association Setup failed: mandatory IE incorrect: NodeID parse error: %v", err)
		return
	}

	// 3. Validate NodeID is not empty
	if peerNodeID == "" {
		h.log.Errorf("Association Setup failed: mandatory IE incorrect: NodeID is empty")
		return
	}

	// 4. Validate RecoveryTimeStamp IE (Mandatory)
	if req.RecoveryTimeStamp == nil {
		h.log.Errorf("Association Setup failed: mandatory IE missing: RecoveryTimeStamp")
		return
	}

	// 5. Validate RecoveryTimeStamp can be parsed
	_, err = req.RecoveryTimeStamp.RecoveryTimeStamp()
	if err != nil {
		h.log.Errorf("Association Setup failed: mandatory IE incorrect: RecoveryTimeStamp parse error: %v", err)
		return
	}

	// deleting the existing PFCP association and associated PFCP sessions,
	// if a PFCP association was already established for the Node ID
	// received in the request, regardless of the Recovery Timestamp
	// received in the request.
	h.node.EstablishAssociation(peerNodeID, addr)

	rsp := message.NewAssociationSetupResponse(
		req.Header.SequenceNumber,
		newIeNodeID(h.node.NodeID),
		ie.NewCause(ie.CauseRequestAccepted),
		ie.NewRecoveryTimeStamp(h.node.RecoveryTime),
		// TODO:
		// ie.NewUPFunctionFeatures(),
	)

	err = h.transport.sendRspTo(rsp, addr)
	if err != nil {
		h.log.Errorln(err)
		return
	}
}

func (h *MessageHandler) handleAssociationUpdateRequest(
	req *message.AssociationUpdateRequest,
	addr net.Addr,
) {
	h.log.Infoln("handleAssociationUpdateRequest not supported")
}

func (h *MessageHandler) handleAssociationReleaseRequest(
	req *message.AssociationReleaseRequest,
	addr net.Addr,
) {
	h.log.Infoln("handleAssociationReleaseRequest not supported")
}

func newIeNodeID(nodeID string) *ie.IE {
	ip := net.ParseIP(nodeID)
	if ip != nil {
		if ip.To4() != nil {
			return ie.NewNodeID(nodeID, "", "")
		}
		return ie.NewNodeID("", nodeID, "")
	}
	return ie.NewNodeID("", "", nodeID)
}
