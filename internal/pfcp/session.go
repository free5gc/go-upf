package pfcp

import (
	"net"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

func (s *PfcpServer) handleSessionEstablishmentRequest(req *message.SessionEstablishmentRequest, addr net.Addr) {
	// TODO: error response
	s.log.Infoln("handleSessionEstablishmentRequest")

	if req.NodeID == nil {
		s.log.Errorln("not found NodeID")
		return
	}
	rnodeid, err := req.NodeID.NodeID()
	if err != nil {
		s.log.Errorln(err)
		return
	}
	s.log.Debugf("remote nodeid: %v\n", rnodeid)

	node, ok := s.rnodes[rnodeid]
	if !ok {
		s.log.Errorf("not found NodeID %v\n", rnodeid)
		return
	}

	if req.CPFSEID == nil {
		s.log.Errorln("not found CP F-SEID")
		return
	}
	fseid, err := req.CPFSEID.FSEID()
	if err != nil {
		s.log.Errorln(err)
		return
	}
	s.log.Debugf("seid: %v\n", fseid.SEID)

	// allocate a session
	sess := node.NewSess(fseid.SEID)

	sess.HandleReport(s.ServeReport)

	// TODO: rollback transaction
	for _, i := range req.CreateFAR {
		err = sess.CreateFAR(i)
		if err != nil {
			sess.log.Errorln(err)
		}
	}

	for _, i := range req.CreateQER {
		err = sess.CreateQER(i)
		if err != nil {
			sess.log.Errorln(err)
		}
	}

	for _, i := range req.CreatePDR {
		err = sess.CreatePDR(i)
		if err != nil {
			sess.log.Errorln(err)
		}
	}

	var v4 net.IP
	var v6 net.IP

	rsp := message.NewSessionEstablishmentResponse(
		0,             // mp
		0,             // fo
		sess.RemoteID, // seid
		req.Header.SequenceNumber,
		0, // pri
		newIeNodeID(s.nodeID),
		ie.NewCause(ie.CauseRequestAccepted),
		ie.NewFSEID(sess.LocalID, v4, v6),
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

func (s *PfcpServer) handleSessionModificationRequest(req *message.SessionModificationRequest, addr net.Addr) {
	// TODO: error response
	s.log.Infoln("handleSessionModificationRequest")

	var nodeid string
	if raddr, ok := addr.(*net.UDPAddr); ok {
		nodeid = raddr.IP.String()
	}
	s.log.Debugf("nodeid: %v\n", nodeid)

	node, ok := s.rnodes[nodeid]
	if !ok {
		s.log.Errorf("not found NodeID %v\n", nodeid)
		return
	}

	sess, err := node.Sess(req.Header.SEID)
	if err != nil {
		node.log.Errorln(err)
		return
	}

	for _, i := range req.CreateFAR {
		err = sess.CreateFAR(i)
		if err != nil {
			sess.log.Errorln(err)
		}
	}

	for _, i := range req.CreateQER {
		err = sess.CreateQER(i)
		if err != nil {
			sess.log.Errorln(err)
		}
	}

	for _, i := range req.CreatePDR {
		err = sess.CreatePDR(i)
		if err != nil {
			sess.log.Errorln(err)
		}
	}

	for _, i := range req.RemoveFAR {
		err = sess.RemoveFAR(i)
		if err != nil {
			sess.log.Errorln(err)
		}
	}

	for _, i := range req.RemoveQER {
		err = sess.RemoveQER(i)
		if err != nil {
			sess.log.Errorln(err)
		}
	}

	for _, i := range req.RemovePDR {
		err = sess.RemovePDR(i)
		if err != nil {
			sess.log.Errorln(err)
		}
	}

	for _, i := range req.UpdateFAR {
		err = sess.UpdateFAR(i)
		if err != nil {
			sess.log.Errorln(err)
		}
	}

	for _, i := range req.UpdateQER {
		err = sess.UpdateQER(i)
		if err != nil {
			sess.log.Errorln(err)
		}
	}

	for _, i := range req.UpdatePDR {
		err = sess.UpdatePDR(i)
		if err != nil {
			sess.log.Errorln(err)
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
		s.log.Errorln(err)
		return
	}

	_, err = s.conn.WriteTo(b, addr)
	if err != nil {
		s.log.Errorln(err)
		return
	}
}

func (s *PfcpServer) handleSessionDeletionRequest(req *message.SessionDeletionRequest, addr net.Addr) {
	// TODO: error response
	s.log.Infoln("handleSessionDeletionRequest")

	var nodeid string
	if raddr, ok := addr.(*net.UDPAddr); ok {
		nodeid = raddr.IP.String()
	}
	s.log.Debugf("nodeid: %v\n", nodeid)

	node, ok := s.rnodes[nodeid]
	if !ok {
		s.log.Errorf("not found NodeID %v\n", nodeid)
		return
	}

	sess, err := node.Sess(req.Header.SEID)
	if err != nil {
		node.log.Errorln(err)
		return
	}

	node.DeleteSess(req.Header.SEID)

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
		s.log.Errorln(err)
		return
	}

	_, err = s.conn.WriteTo(b, addr)
	if err != nil {
		s.log.Errorln(err)
		return
	}
}

func (s *PfcpServer) handleSessionReportResponse(rsp *message.SessionReportResponse, addr net.Addr) {
	s.log.Infoln("handleSessionReportResponse")

	var nodeid string
	if raddr, ok := addr.(*net.UDPAddr); ok {
		nodeid = raddr.IP.String()
	}
	s.log.Debugf("nodeid: %v\n", nodeid)

	node, ok := s.rnodes[nodeid]
	if !ok {
		s.log.Errorf("not found NodeID %v\n", nodeid)
		return
	}

	s.log.Debugf("seid: %v\n", rsp.Header.SEID)

	sess, err := node.Sess(rsp.Header.SEID)
	if err != nil {
		node.log.Errorln(err)
		return
	}

	s.log.Debugf("sess: %#+v\n", sess)
}
