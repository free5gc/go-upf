package pfcp

import (
	"net"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"

	"github.com/free5gc/go-upf/internal/logger"
)

func (s *PfcpServer) handleAssociationSetupRequest(req *message.AssociationSetupRequest, addr net.Addr) {
	logger.PfcpLog.Infoln(s.listen, "handleAssociationSetupRequest")

	if req.NodeID == nil {
		logger.PfcpLog.Errorln(s.listen, "not found NodeID")
		return
	}
	nodeid, err := req.NodeID.NodeID()
	if err != nil {
		logger.PfcpLog.Errorln(s.listen, err)
		return
	}
	logger.PfcpLog.Infof("%v nodeid: %v\n", s.listen, nodeid)

	// deleting the existing PFCP association and associated PFCP sessions,
	// if a PFCP association was already established for the Node ID
	// received in the request, regardless of the Recovery Timestamp
	// received in the request.
	if ni, ok := s.nodes.Load(nodeid); ok {
		if node, ok := ni.(*Node); ok {
			logger.PfcpLog.Infof("delete node: %#+v\n", node)
			node.Reset()
		}
		s.nodes.Delete(ni)
	}
	node := NewNode(nodeid, s.driver)
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
		logger.PfcpLog.Errorln(s.listen, err)
		return
	}

	_, err = s.conn.WriteTo(b, addr)
	if err != nil {
		logger.PfcpLog.Errorln(s.listen, err)
		return
	}
}

func (s *PfcpServer) handleAssociationUpdateRequest(msg *message.AssociationUpdateRequest, addr net.Addr) {
	logger.PfcpLog.Infoln(s.listen, "handleAssociationUpdateRequest")
}

func (s *PfcpServer) handleAssociationReleaseRequest(msg *message.AssociationReleaseRequest, addr net.Addr) {
	logger.PfcpLog.Infoln(s.listen, "handleAssociationReleaseRequest")
}
