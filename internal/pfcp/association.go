package pfcp

import (
	"fmt"
	"net"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

func (s *PfcpServer) handleAssociationSetupRequest(
	req *message.AssociationSetupRequest,
	addr net.Addr,
) {
	s.log.Infoln("handleAssociationSetupRequest")

	cause, err := s.validateAssociationSetupRequest(req)
	if err != nil {
		s.log.Errorf("Association Setup Request validation failed: %v", err)

		// Send rejection response with appropriate cause
		rsp := message.NewAssociationSetupResponse(
			req.Header.SequenceNumber,
			newIeNodeID(s.nodeID),
			ie.NewCause(cause),
			ie.NewRecoveryTimeStamp(s.recoveryTime),
		)

		if sendErr := s.sendRspTo(rsp, addr); sendErr != nil {
			s.log.Errorln(sendErr)
		}
		return
	}

	rnodeid, _ := req.NodeID.NodeID()

	// deleting the existing PFCP association and associated PFCP sessions,
	// if a PFCP association was already established for the Node ID
	// received in the request, regardless of the Recovery Timestamp
	// received in the request.
	if node, ok := s.rnodes[rnodeid]; ok {
		s.log.Infof("delete node: %#+v\n", node)
		node.Reset()
		delete(s.rnodes, rnodeid)
	}
	node := s.NewNode(rnodeid, addr, s.driver)
	s.rnodes[rnodeid] = node

	rsp := message.NewAssociationSetupResponse(
		req.Header.SequenceNumber,
		newIeNodeID(s.nodeID),
		ie.NewCause(ie.CauseRequestAccepted),
		ie.NewRecoveryTimeStamp(s.recoveryTime),
		// TODO:
		// ie.NewUPFunctionFeatures(),
	)

	err = s.sendRspTo(rsp, addr)
	if err != nil {
		s.log.Errorln(err)
		return
	}
}

func (s *PfcpServer) validateAssociationSetupRequest(req *message.AssociationSetupRequest) (uint8, error) {
	// 1. Validate NodeID IE (Mandatory)
	if req.NodeID == nil {
		return ie.CauseMandatoryIEMissing, fmt.Errorf("mandatory IE missing: NodeID")
	}

	// 2. Validate NodeID IE can be parsed correctly
	nodeID, err := req.NodeID.NodeID()
	if err != nil {
		return ie.CauseMandatoryIEIncorrect, fmt.Errorf("mandatory IE incorrect: NodeID parse error: %v", err)
	}

	// 3. Validate NodeID is not empty
	if nodeID == "" {
		return ie.CauseMandatoryIEIncorrect, fmt.Errorf("mandatory IE incorrect: NodeID is empty")
	}

	// 4. Validate RecoveryTimeStamp IE (Mandatory)
	if req.RecoveryTimeStamp == nil {
		return ie.CauseMandatoryIEMissing, fmt.Errorf("mandatory IE missing: RecoveryTimeStamp")
	}

	// 5. Validate RecoveryTimeStamp can be parsed
	_, err = req.RecoveryTimeStamp.RecoveryTimeStamp()
	if err != nil {
		return ie.CauseMandatoryIEIncorrect, fmt.Errorf("mandatory IE incorrect: RecoveryTimeStamp parse error: %v", err)
	}

	// 6. Validate optional IEs if present
	if req.CPFunctionFeatures != nil {
		_, err = req.CPFunctionFeatures.CPFunctionFeatures()
		if err != nil {
			return ie.CauseInvalidLength, fmt.Errorf("invalid IE: CPFunctionFeatures parse error: %v", err)
		}
	}

	if req.UserPlaneIPResourceInformation != nil {
		for _, upiri := range req.UserPlaneIPResourceInformation {
			_, err = upiri.UserPlaneIPResourceInformation()
			if err != nil {
				return ie.CauseInvalidLength, fmt.Errorf("invalid IE: UserPlaneIPResourceInformation parse error: %v", err)
			}
		}
	}

	return ie.CauseRequestAccepted, nil
}

func (s *PfcpServer) handleAssociationUpdateRequest(
	req *message.AssociationUpdateRequest,
	addr net.Addr,
) {
	s.log.Infoln("handleAssociationUpdateRequest not supported")
}

func (s *PfcpServer) handleAssociationReleaseRequest(
	req *message.AssociationReleaseRequest,
	addr net.Addr,
) {
	s.log.Infoln("handleAssociationReleaseRequest not supported")
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
