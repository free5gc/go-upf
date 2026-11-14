package pfcp

import (
	"net"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

func (s *PfcpServer) handleAssociationSetupRequest(
	req *message.AssociationSetupRequest,
	addr net.Addr,
) {
	s.log.Infoln("handleAssociationSetupRequest")

	// 1. Validate NodeID IE (Mandatory)
	if req.NodeID == nil {
		s.log.Errorf("Association Setup failed: mandatory IE missing: NodeID")
		return
	}

	// 2. Validate NodeID IE can be parsed correctly
	rnodeid, err := req.NodeID.NodeID()
	if err != nil {
		s.log.Errorf("Association Setup failed: mandatory IE incorrect: NodeID parse error: %v", err)
		return
	}

	// 3. Validate NodeID is not empty
	if rnodeid == "" {
		s.log.Errorf("Association Setup failed: mandatory IE incorrect: NodeID is empty")
		return
	}

	// 4. Validate RecoveryTimeStamp IE (Mandatory)
	if req.RecoveryTimeStamp == nil {
		s.log.Errorf("Association Setup failed: mandatory IE missing: RecoveryTimeStamp")
		return
	}

	// 5. Validate RecoveryTimeStamp can be parsed
	_, err = req.RecoveryTimeStamp.RecoveryTimeStamp()
	if err != nil {
		s.log.Errorf("Association Setup failed: mandatory IE incorrect: RecoveryTimeStamp parse error: %v", err)
		return
	}

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

	// PDIU, octet 6 bit 2: Traffic Endpoints (TS 29.244 clause 5.2.1A.2); with a GTP-U address, FTUP, octet 5
	// bit 5: the UP function allocates the F-TEIDs (clause 5.5.1)
	features := []uint8{0x00, 0x02}
	if s.lnode.fteids.addr != nil {
		features[0] = 0x10
	}
	rsp := message.NewAssociationSetupResponse(
		req.Header.SequenceNumber,
		newIeNodeID(s.nodeID),
		ie.NewCause(ie.CauseRequestAccepted),
		ie.NewRecoveryTimeStamp(s.recoveryTime),
		ie.NewUPFunctionFeatures(features...),
	)

	err = s.sendRspTo(rsp, addr)
	if err != nil {
		s.log.Errorln(err)
		return
	}
}

func (s *PfcpServer) handleAssociationUpdateRequest(
	req *message.AssociationUpdateRequest,
	addr net.Addr,
) {
	s.log.Infoln("handleAssociationUpdateRequest")

	if req.NodeID == nil {
		s.log.Errorf("Association Update failed: mandatory IE missing: NodeID")
		s.sendAssociationUpdateResponse(req, addr, ie.CauseMandatoryIEMissing, ie.NewOffendingIE(ie.NodeID))
		return
	}
	rnodeid, err := req.NodeID.NodeID()
	if err != nil || rnodeid == "" {
		s.log.Errorf("Association Update failed: mandatory IE incorrect: NodeID[% x]", req.NodeID.Payload)
		s.sendAssociationUpdateResponse(req, addr, ie.CauseMandatoryIEIncorrect, ie.NewOffendingIE(ie.NodeID))
		return
	}

	node, ok := s.rnodes[rnodeid]
	if !ok {
		s.log.Warnf("Association Update rejected: no association with Node ID %q", rnodeid)
		s.sendAssociationUpdateResponse(req, addr, ie.CauseNoEstablishedPFCPAssociation)
		return
	}
	// A peer updates its own association only
	if !node.matchesPeer(addr) {
		s.log.Warnf("Association Update rejected: peer %v does not match Node ID %q", addr, rnodeid)
		s.sendAssociationUpdateResponse(req, addr, ie.CauseRequestRejected)
		return
	}
	// The UP function keeps no feature of the CP function, nor any other information that the request updates
	s.sendAssociationUpdateResponse(req, addr, ie.CauseRequestAccepted)
}

func (s *PfcpServer) sendAssociationUpdateResponse(
	req *message.AssociationUpdateRequest,
	addr net.Addr,
	cause uint8,
	ies ...*ie.IE,
) {
	rsp := message.NewAssociationUpdateResponse(
		req.Header.SequenceNumber,
		append([]*ie.IE{newIeNodeID(s.nodeID), ie.NewCause(cause)}, ies...)...,
	)
	if err := s.sendRspTo(rsp, addr); err != nil {
		s.log.Errorln(err)
	}
}

func (s *PfcpServer) handleAssociationReleaseRequest(
	req *message.AssociationReleaseRequest,
	addr net.Addr,
) {
	s.log.Infoln("handleAssociationReleaseRequest")

	if req.NodeID == nil {
		s.log.Errorf("Association Release failed: mandatory IE missing: NodeID")
		s.sendAssociationReleaseResponse(req, addr, ie.CauseMandatoryIEMissing, ie.NewOffendingIE(ie.NodeID))
		return
	}
	rnodeid, err := req.NodeID.NodeID()
	if err != nil || rnodeid == "" {
		s.log.Errorf("Association Release failed: mandatory IE incorrect: NodeID[% x]", req.NodeID.Payload)
		s.sendAssociationReleaseResponse(req, addr, ie.CauseMandatoryIEIncorrect, ie.NewOffendingIE(ie.NodeID))
		return
	}

	if node, ok := s.rnodes[rnodeid]; ok {
		// A peer releases its own association only
		if !node.matchesPeer(addr) {
			s.log.Warnf("Association Release rejected: peer %v does not match Node ID %q", addr, rnodeid)
			s.sendAssociationReleaseResponse(req, addr, ie.CauseRequestRejected)
			return
		}
		s.log.Infof("delete node: %#+v\n", node)
		node.Reset()
		delete(s.rnodes, rnodeid)
	}
	s.sendAssociationReleaseResponse(req, addr, ie.CauseRequestAccepted)
}

func (s *PfcpServer) sendAssociationReleaseResponse(
	req *message.AssociationReleaseRequest,
	addr net.Addr,
	cause uint8,
	ies ...*ie.IE,
) {
	rsp := message.NewAssociationReleaseResponse(
		req.Header.SequenceNumber,
		newIeNodeID(s.nodeID),
		ie.NewCause(cause),
		ies...,
	)
	if err := s.sendRspTo(rsp, addr); err != nil {
		s.log.Errorln(err)
	}
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
