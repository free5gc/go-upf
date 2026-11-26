package pfcp

import (
	"net"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

func (d *Dispatcher) handleAssociationSetupRequest(
	req *message.AssociationSetupRequest,
	addr net.Addr,
) {
	d.log.Infoln("handleAssociationSetupRequest")

	// 1. Validate NodeID IE (Mandatory)
	if req.NodeID == nil {
		d.log.Errorf("Association Setup failed: mandatory IE missing: NodeID")
		return
	}

	// 2. Validate NodeID IE can be parsed correctly
	peerNodeID, err := req.NodeID.NodeID()
	if err != nil {
		d.log.Errorf("Association Setup failed: mandatory IE incorrect: NodeID parse error: %v", err)
		return
	}

	// 3. Validate NodeID is not empty
	if peerNodeID == "" {
		d.log.Errorf("Association Setup failed: mandatory IE incorrect: NodeID is empty")
		return
	}

	// 4. Validate RecoveryTimeStamp IE (Mandatory)
	if req.RecoveryTimeStamp == nil {
		d.log.Errorf("Association Setup failed: mandatory IE missing: RecoveryTimeStamp")
		return
	}

	// 5. Validate RecoveryTimeStamp can be parsed
	_, err = req.RecoveryTimeStamp.RecoveryTimeStamp()
	if err != nil {
		d.log.Errorf("Association Setup failed: mandatory IE incorrect: RecoveryTimeStamp parse error: %v", err)
		return
	}

	// deleting the existing PFCP association and associated PFCP sessions,
	// if a PFCP association was already established for the Node ID
	// received in the request, regardless of the Recovery Timestamp
	// received in the request.
	d.node.EstablishAssociation(peerNodeID, addr)

	features := []uint8{0, 2}
	if d.node.fteids.addr != nil {
		features[0] = 0x10
	}
	rsp := message.NewAssociationSetupResponse(
		req.Header.SequenceNumber,
		newIeNodeID(d.node.NodeID),
		ie.NewCause(ie.CauseRequestAccepted),
		ie.NewRecoveryTimeStamp(d.node.RecoveryTime),
		ie.NewUPFunctionFeatures(features...),
	)

	err = d.transport.sendRspTo(rsp, addr)
	if err != nil {
		d.log.Errorln(err)
		return
	}
}

func (d *Dispatcher) handleAssociationUpdateRequest(
	req *message.AssociationUpdateRequest,
	addr net.Addr,
) {
	d.log.Infoln("handleAssociationUpdateRequest")

	if req.NodeID == nil {
		d.log.Errorf("Association Update failed: mandatory IE missing: NodeID")
		d.sendAssociationUpdateResponse(req, addr, ie.CauseMandatoryIEMissing, ie.NewOffendingIE(ie.NodeID))
		return
	}
	rnodeid, err := req.NodeID.NodeID()
	if err != nil || rnodeid == "" {
		d.log.Errorf("Association Update failed: mandatory IE incorrect: NodeID[% x]", req.NodeID.Payload)
		d.sendAssociationUpdateResponse(req, addr, ie.CauseMandatoryIEIncorrect, ie.NewOffendingIE(ie.NodeID))
		return
	}

	node, ok := d.node.Association(rnodeid)
	if !ok {
		d.log.Warnf("Association Update rejected: no association with Node ID %q", rnodeid)
		d.sendAssociationUpdateResponse(req, addr, ie.CauseNoEstablishedPFCPAssociation)
		return
	}
	// A peer updates its own association only
	if !node.matchesPeer(addr) {
		d.log.Warnf("Association Update rejected: peer %v does not match Node ID %q", addr, rnodeid)
		d.sendAssociationUpdateResponse(req, addr, ie.CauseRequestRejected)
		return
	}
	// The UP function keeps no feature of the CP function, nor any other information that the request updates
	d.sendAssociationUpdateResponse(req, addr, ie.CauseRequestAccepted)
}

func (d *Dispatcher) sendAssociationUpdateResponse(
	req *message.AssociationUpdateRequest,
	addr net.Addr,
	cause uint8,
	ies ...*ie.IE,
) {
	rsp := message.NewAssociationUpdateResponse(
		req.Header.SequenceNumber,
		append([]*ie.IE{newIeNodeID(d.node.NodeID), ie.NewCause(cause)}, ies...)...,
	)
	if err := d.transport.sendRspTo(rsp, addr); err != nil {
		d.log.Errorln(err)
	}
}

func (d *Dispatcher) handleAssociationReleaseRequest(
	req *message.AssociationReleaseRequest,
	addr net.Addr,
) {
	d.log.Infoln("handleAssociationReleaseRequest")

	if req.NodeID == nil {
		d.log.Errorf("Association Release failed: mandatory IE missing: NodeID")
		d.sendAssociationReleaseResponse(req, addr, ie.CauseMandatoryIEMissing, ie.NewOffendingIE(ie.NodeID))
		return
	}
	rnodeid, err := req.NodeID.NodeID()
	if err != nil || rnodeid == "" {
		d.log.Errorf("Association Release failed: mandatory IE incorrect: NodeID[% x]", req.NodeID.Payload)
		d.sendAssociationReleaseResponse(req, addr, ie.CauseMandatoryIEIncorrect, ie.NewOffendingIE(ie.NodeID))
		return
	}

	if node, ok := d.node.Association(rnodeid); ok {
		// A peer releases its own association only
		if !node.matchesPeer(addr) {
			d.log.Warnf("Association Release rejected: peer %v does not match Node ID %q", addr, rnodeid)
			d.sendAssociationReleaseResponse(req, addr, ie.CauseRequestRejected)
			return
		}
		d.node.DeleteAssociation(rnodeid)
	}
	d.sendAssociationReleaseResponse(req, addr, ie.CauseRequestAccepted)
}

func (d *Dispatcher) sendAssociationReleaseResponse(
	req *message.AssociationReleaseRequest,
	addr net.Addr,
	cause uint8,
	ies ...*ie.IE,
) {
	rsp := message.NewAssociationReleaseResponse(
		req.Header.SequenceNumber,
		newIeNodeID(d.node.NodeID),
		ie.NewCause(cause),
		ies...,
	)
	if err := d.transport.sendRspTo(rsp, addr); err != nil {
		d.log.Errorln(err)
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
