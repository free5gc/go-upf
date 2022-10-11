package pfcp

import (
	"net"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"

	"github.com/free5gc/go-upf/internal/report"
)

func (s *PfcpServer) handleSessionEstablishmentRequest(
	req *message.SessionEstablishmentRequest,
	addr net.Addr,
) {
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

	rnode, ok := s.rnodes[rnodeid]
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
	s.log.Debugf("fseid.SEID: %#x\n", fseid.SEID)

	// allocate a session
	sess := rnode.NewSess(fseid.SEID)

	// TODO: rollback transaction
	for _, i := range req.CreateFAR {
		err = sess.CreateFAR(i)
		if err != nil {
			sess.log.Errorf("Est CreateFAR error: %+v", err)
		}
	}

	for _, i := range req.CreateQER {
		err = sess.CreateQER(i)
		if err != nil {
			sess.log.Errorf("Est CreateQER error: %+v", err)
		}
	}

	for _, i := range req.CreateURR {
		err = sess.CreateURR(i)
		if err != nil {
			sess.log.Errorf("Est CreateURR error: %+v", err)
		}
	}

	if req.CreateBAR != nil {
		err = sess.CreateBAR(req.CreateBAR)
		if err != nil {
			sess.log.Errorf("Est CreateBAR error: %+v", err)
		}
	}

	for _, i := range req.CreatePDR {
		err = sess.CreatePDR(i)
		if err != nil {
			sess.log.Errorf("Est CreatePDR error: %+v", err)
		}
	}

	var v4 net.IP
	addrv4, err := net.ResolveIPAddr("ip4", s.nodeID)
	if err == nil {
		v4 = addrv4.IP.To4()
	}
	// TODO: support v6
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

	err = s.sendRspTo(rsp, addr)
	if err != nil {
		s.log.Errorln(err)
		return
	}
}

func (s *PfcpServer) handleSessionModificationRequest(
	req *message.SessionModificationRequest,
	addr net.Addr,
) {
	// TODO: error response
	s.log.Infoln("handleSessionModificationRequest")

	sess, err := s.lnode.Sess(req.SEID())
	if err != nil {
		s.log.Errorf("handleSessionModificationRequest: %v", err)
		rsp := message.NewSessionModificationResponse(
			0, // mp
			0, // fo
			0, // seid
			req.Header.SequenceNumber,
			0, // pri
			ie.NewCause(ie.CauseSessionContextNotFound),
		)

		err = s.sendRspTo(rsp, addr)
		if err != nil {
			s.log.Errorln(err)
			return
		}
		return
	}

	if req.NodeID != nil {
		// TS 29.244 7.5.4:
		// This IE shall be present if a new SMF in an SMF Set,
		// with one PFCP association per SMF and UPF (see clause 5.22.3),
		// takes over the control of the PFCP session.
		// When present, it shall contain the unique identifier of the new SMF.
		rnodeid, err1 := req.NodeID.NodeID()
		if err1 != nil {
			s.log.Errorln(err)
			return
		}
		s.log.Debugf("new remote nodeid: %v\n", rnodeid)
		s.UpdateNodeID(sess.rnode, rnodeid)
	}

	for _, i := range req.CreateFAR {
		err = sess.CreateFAR(i)
		if err != nil {
			sess.log.Errorf("Mod CreateFAR error: %+v", err)
		}
	}

	for _, i := range req.CreateQER {
		err = sess.CreateQER(i)
		if err != nil {
			sess.log.Errorf("Mod CreateQER error: %+v", err)
		}
	}

	for _, i := range req.CreateURR {
		err = sess.CreateURR(i)
		if err != nil {
			sess.log.Errorf("Mod CreateURR error: %+v", err)
		}
	}

	if req.CreateBAR != nil {
		err = sess.CreateBAR(req.CreateBAR)
		if err != nil {
			sess.log.Errorf("Mod CreateBAR error: %+v", err)
		}
	}

	for _, i := range req.CreatePDR {
		err = sess.CreatePDR(i)
		if err != nil {
			sess.log.Errorf("Mod CreatePDR error: %+v", err)
		}
	}

	for _, i := range req.RemoveFAR {
		err = sess.RemoveFAR(i)
		if err != nil {
			sess.log.Errorf("Mod RemoveFAR error: %+v", err)
		}
	}

	for _, i := range req.RemoveQER {
		err = sess.RemoveQER(i)
		if err != nil {
			sess.log.Errorf("Mod RemoveQER error: %+v", err)
		}
	}

	var usars []report.USAReport
	for _, i := range req.RemoveURR {
		rs, err1 := sess.RemoveURR(i)
		if err1 != nil {
			sess.log.Errorf("Mod RemoveURR error: %+v", err1)
			continue
		}
		if rs != nil {
			usars = append(usars, rs...)
		}
	}

	if req.RemoveBAR != nil {
		err = sess.RemoveBAR(req.RemoveBAR)
		if err != nil {
			sess.log.Errorf("Mod RemoveBAR error: %+v", err)
		}
	}

	for _, i := range req.RemovePDR {
		err = sess.RemovePDR(i)
		if err != nil {
			sess.log.Errorf("Mod RemovePDR error: %+v", err)
		}
	}

	for _, i := range req.UpdateFAR {
		err = sess.UpdateFAR(i)
		if err != nil {
			sess.log.Errorf("Mod UpdateFAR error: %+v", err)
		}
	}

	for _, i := range req.UpdateQER {
		err = sess.UpdateQER(i)
		if err != nil {
			sess.log.Errorf("Mod UpdateQER error: %+v", err)
		}
	}

	for _, i := range req.UpdateURR {
		rs, err1 := sess.UpdateURR(i)
		if err1 != nil {
			sess.log.Errorf("Mod UpdateURR error: %+v", err1)
			continue
		}
		if rs != nil {
			usars = append(usars, rs...)
		}
	}

	if req.UpdateBAR != nil {
		err = sess.UpdateBAR(req.UpdateBAR)
		if err != nil {
			sess.log.Errorf("Mod UpdateBAR error: %+v", err)
		}
	}

	for _, i := range req.UpdatePDR {
		err = sess.UpdatePDR(i)
		if err != nil {
			sess.log.Errorf("Mod UpdatePDR error: %+v", err)
		}
	}

	for _, i := range req.QueryURR {
		usar, err1 := sess.QueryURR(i)
		if err1 != nil {
			sess.log.Errorf("Mod QueryURR error: %+v", err1)
			continue
		}
		if usar != nil {
			usars = append(usars, usar...)
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
	for _, r := range usars {
		urrInfo, ok := sess.URRIDs[r.URRID]
		if !ok {
			sess.log.Warnf("Sess Mod: URRInfo[%#x] not found", r.URRID)
			continue
		}
		r.URSEQN = sess.URRSeq(r.URRID)
		rsp.UsageReport = append(rsp.UsageReport,
			ie.NewUsageReportWithinSessionModificationResponse(
				r.IEsWithinSessModRsp(
					urrInfo.MeasureMethod, urrInfo.MeasureInformation)...,
			))

		if urrInfo.removed {
			delete(sess.URRIDs, r.URRID)
		}
	}

	err = s.sendRspTo(rsp, addr)
	if err != nil {
		s.log.Errorln(err)
		return
	}
}

func (s *PfcpServer) handleSessionDeletionRequest(
	req *message.SessionDeletionRequest,
	addr net.Addr,
) {
	// TODO: error response
	s.log.Infoln("handleSessionDeletionRequest")

	lSeid := req.SEID()
	sess, err := s.lnode.Sess(lSeid)
	if err != nil {
		s.log.Errorf("handleSessionDeletionRequest: %v", err)
		rsp := message.NewSessionDeletionResponse(
			0, // mp
			0, // fo
			0, // seid
			req.Header.SequenceNumber,
			0, // pri
			ie.NewCause(ie.CauseSessionContextNotFound),
			ie.NewReportType(0, 0, 1, 0),
		)

		err = s.sendRspTo(rsp, addr)
		if err != nil {
			s.log.Errorln(err)
			return
		}
		return
	}

	usars := sess.rnode.DeleteSess(lSeid)

	rsp := message.NewSessionDeletionResponse(
		0,             // mp
		0,             // fo
		sess.RemoteID, // seid
		req.Header.SequenceNumber,
		0, // pri
		ie.NewCause(ie.CauseRequestAccepted),
	)
	for _, r := range usars {
		urrInfo, ok := sess.URRIDs[r.URRID]
		if !ok {
			sess.log.Warnf("Sess Del: URRInfo[%#x] not found", r.URRID)
			continue
		}
		r.URSEQN = sess.URRSeq(r.URRID)
		rsp.UsageReport = append(rsp.UsageReport,
			ie.NewUsageReportWithinSessionDeletionResponse(
				r.IEsWithinSessDelRsp(
					urrInfo.MeasureMethod, urrInfo.MeasureInformation)...,
			))

		if urrInfo.removed {
			delete(sess.URRIDs, r.URRID)
		}
	}

	err = s.sendRspTo(rsp, addr)
	if err != nil {
		s.log.Errorln(err)
		return
	}
}

func (s *PfcpServer) handleSessionReportResponse(
	rsp *message.SessionReportResponse,
	addr net.Addr,
	req message.Message,
) {
	s.log.Infoln("handleSessionReportResponse")

	s.log.Debugf("seid: %#x\n", rsp.SEID())
	if rsp.Header.SEID == 0 {
		s.log.Warnf("rsp SEID is 0; no this session on remote; delete it on local")
		sess, err := s.lnode.RemoteSess(req.SEID(), addr)
		if err != nil {
			s.log.Errorln(err)
			return
		}
		sess.rnode.DeleteSess(sess.LocalID)
		return
	}

	sess, err := s.lnode.Sess(rsp.SEID())
	if err != nil {
		s.log.Errorln(err)
		return
	}

	s.log.Debugf("sess: %#+v\n", sess)
}

func (s *PfcpServer) handleSessionReportRequestTimeout(
	req *message.SessionReportRequest,
	addr net.Addr,
) {
	s.log.Warnf("handleSessionReportRequestTimeout: SEID[%#x]", req.SEID())
	// TODO?
}
