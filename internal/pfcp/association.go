package pfcp

import (
	"net"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

func (s *PfcpServer) handleAssociationSetupRequest(req *message.AssociationSetupRequest, addr net.Addr) {
	s.log.Infoln("handleAssociationSetupRequest")

	if req.NodeID == nil {
		s.log.Errorln("not found NodeID")
		return
	}
	nodeid, err := req.NodeID.NodeID()
	if err != nil {
		s.log.Errorln(err)
		return
	}
	s.log.Infof("nodeid: %v\n", nodeid)

	// deleting the existing PFCP association and associated PFCP sessions,
	// if a PFCP association was already established for the Node ID
	// received in the request, regardless of the Recovery Timestamp
	// received in the request.
	if ni, ok := s.nodes.Load(nodeid); ok {
		if node, ok := ni.(*Node); ok {
			s.log.Infof("delete node: %#+v\n", node)
			node.Reset()
		}
		s.nodes.Delete(ni)
	}
	node := s.NewNode(nodeid, s.driver)
	s.nodes.Store(nodeid, node)

	var pfcpaddr string
	if addr, ok := s.conn.LocalAddr().(*net.UDPAddr); ok {
		pfcpaddr = addr.IP.String()
	}

	rsp := message.NewAssociationSetupResponse(
		req.Header.SequenceNumber,
		ie.NewNodeID(pfcpaddr, "", ""),
		ie.NewCause(ie.CauseRequestAccepted),
		ie.NewRecoveryTimeStamp(s.recoveryTime),
		// TODO:
		// ie.NewUPFunctionFeatures(),
	)

	b, err := rsp.Marshal()
	if err != nil {
		s.log.Errorln(err)
		return
	}

	_, err = s.conn.WriteTo(b, addr)
	if err != nil {
		s.log.Errorln(err)
		return
	}
}

func (s *PfcpServer) handleAssociationUpdateRequest(msg *message.AssociationUpdateRequest, addr net.Addr) {
	s.log.Infoln("handleAssociationUpdateRequest")
}

func (s *PfcpServer) handleAssociationReleaseRequest(msg *message.AssociationReleaseRequest, addr net.Addr) {
	s.log.Infoln("handleAssociationReleaseRequest")
}
