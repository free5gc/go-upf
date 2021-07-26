package pfcp

import (
	"net"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"

	"github.com/m-asama/upf/logger"
)

func (s *PfcpServer) handleSessionEstablishmentRequest(req *message.SessionEstablishmentRequest, addr net.Addr) {
	// TODO: error response
	logger.PfcpLog.Infoln(s.listen, "handleSessionEstablishmentRequest")

	if req.NodeID == nil {
		logger.PfcpLog.Errorln("not found NodeID")
		return
	}
	nodeid, err := req.NodeID.NodeID()
	if err != nil {
		logger.PfcpLog.Errorln(s.listen, err)
		return
	}
	logger.PfcpLog.Infof("nodeid: %v\n", nodeid)

	ni, ok := s.nodes.Load(nodeid)
	if !ok {
		logger.PfcpLog.Errorf("not found NodeID %v\n", nodeid)
		return
	}
	node, ok := ni.(*Node)
	if !ok {
		logger.PfcpLog.Errorf("not found NodeID %v\n", nodeid)
		return
	}

	if req.CPFSEID == nil {
		logger.PfcpLog.Errorln("not found CP F-SEID")
		return
	}
	fseid, err := req.CPFSEID.FSEID()
	if err != nil {
		logger.PfcpLog.Errorln(err)
		return
	}
	logger.PfcpLog.Infof("seid: %v\n", fseid.SEID)

	// allocate a session
	sess := node.New(fseid.SEID)

	// TODO: rollback transaction
	for _, i := range req.CreateFAR {
		err := sess.CreateFAR(i)
		if err != nil {
			logger.PfcpLog.Errorln(s.listen, err)
		}
	}

	for _, i := range req.CreateQER {
		err := sess.CreateQER(i)
		if err != nil {
			logger.PfcpLog.Errorln(s.listen, err)
		}
	}

	for _, i := range req.CreatePDR {
		err := sess.CreatePDR(i)
		if err != nil {
			logger.PfcpLog.Errorln(s.listen, err)
		}
	}

	var v4 net.IP
	var v6 net.IP

	var pfcpaddr string
	if addr, ok := s.conn.LocalAddr().(*net.UDPAddr); ok {
		v4 = addr.IP
		pfcpaddr = v4.String()
	}

	rsp := message.NewSessionEstablishmentResponse(
		0,             // mp
		0,             // fo
		sess.RemoteID, // seid
		req.Header.SequenceNumber,
		0, // pri
		ie.NewNodeID(pfcpaddr, "", ""),
		ie.NewCause(ie.CauseRequestAccepted),
		ie.NewFSEID(sess.LocalID, v4, v6),
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

func (s *PfcpServer) handleSessionModificationRequest(req *message.SessionModificationRequest, addr net.Addr) {
	// TODO: error response
	logger.PfcpLog.Infoln(s.listen, "handleSessionModificationRequest")

	var nodeid string
	if raddr, ok := addr.(*net.UDPAddr); ok {
		nodeid = raddr.IP.String()
	}
	logger.PfcpLog.Infof("nodeid: %v\n", nodeid)

	ni, ok := s.nodes.Load(nodeid)
	if !ok {
		logger.PfcpLog.Errorf("not found NodeID %v\n", nodeid)
		return
	}
	node, ok := ni.(*Node)
	if !ok {
		logger.PfcpLog.Errorf("not found NodeID %v\n", nodeid)
		return
	}

	sess, ok := node.Sess(req.Header.SEID)
	if !ok {
		logger.PfcpLog.Errorf("not found SEID %v\n", req.Header.SEID)
		return
	}

	for _, i := range req.CreateFAR {
		err := sess.CreateFAR(i)
		if err != nil {
			logger.PfcpLog.Errorln(s.listen, err)
		}
	}

	for _, i := range req.CreateQER {
		err := sess.CreateQER(i)
		if err != nil {
			logger.PfcpLog.Errorln(s.listen, err)
		}
	}

	for _, i := range req.CreatePDR {
		err := sess.CreatePDR(i)
		if err != nil {
			logger.PfcpLog.Errorln(s.listen, err)
		}
	}

	for _, i := range req.RemoveFAR {
		err := sess.RemoveFAR(i)
		if err != nil {
			logger.PfcpLog.Errorln(s.listen, err)
		}
	}

	for _, i := range req.RemoveQER {
		err := sess.RemoveQER(i)
		if err != nil {
			logger.PfcpLog.Errorln(s.listen, err)
		}
	}

	for _, i := range req.RemovePDR {
		err := sess.RemovePDR(i)
		if err != nil {
			logger.PfcpLog.Errorln(s.listen, err)
		}
	}

	for _, i := range req.UpdateFAR {
		err := sess.UpdateFAR(i)
		if err != nil {
			logger.PfcpLog.Errorln(s.listen, err)
		}
	}

	for _, i := range req.UpdateQER {
		err := sess.UpdateQER(i)
		if err != nil {
			logger.PfcpLog.Errorln(s.listen, err)
		}
	}

	for _, i := range req.UpdatePDR {
		err := sess.UpdatePDR(i)
		if err != nil {
			logger.PfcpLog.Errorln(s.listen, err)
		}
	}

	rsp := message.NewSessionModificationResponse(
		0,             // mp
		0,             // fo
		sess.RemoteID, // seid
		req.Header.SequenceNumber,
		0, // pri
		ie.NewCause(ie.CauseRequestAccepted),
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

func (s *PfcpServer) handleSessionDeletionRequest(req *message.SessionDeletionRequest, addr net.Addr) {
	// TODO: error response
	logger.PfcpLog.Infoln(s.listen, "handleSessionDeletionRequest")

	var nodeid string
	if raddr, ok := addr.(*net.UDPAddr); ok {
		nodeid = raddr.IP.String()
	}
	logger.PfcpLog.Infof("nodeid: %v\n", nodeid)

	ni, ok := s.nodes.Load(nodeid)
	if !ok {
		logger.PfcpLog.Errorf("not found NodeID %v\n", nodeid)
		return
	}
	node, ok := ni.(*Node)
	if !ok {
		logger.PfcpLog.Errorf("not found NodeID %v\n", nodeid)
		return
	}

	sess, ok := node.Sess(req.Header.SEID)
	if !ok {
		logger.PfcpLog.Errorf("not found SEID %v\n", req.Header.SEID)
		return
	}

	node.Delete(req.Header.SEID)

	rsp := message.NewSessionDeletionResponse(
		0,             // mp
		0,             // fo
		sess.RemoteID, // seid
		req.Header.SequenceNumber,
		0, // pri
		ie.NewCause(ie.CauseRequestAccepted),
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
