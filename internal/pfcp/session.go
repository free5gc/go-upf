package pfcp

import (
	"net"

	"github.com/pkg/errors"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"

	"github.com/free5gc/go-upf/internal/forwarder"
	"github.com/free5gc/go-upf/internal/report"
)

func (s *PfcpServer) handleSessionEstablishmentRequest(
	req *message.SessionEstablishmentRequest,
	addr net.Addr,
) {
	s.log.Infoln("handleSessionEstablishmentRequest")

	if req.NodeID == nil {
		s.log.Errorln("not found NodeID")
		s.sendSessEstFailRsp(req, addr, ie.CauseMandatoryIEMissing)
		return
	}
	rnodeid, err := req.NodeID.NodeID()
	if err != nil {
		s.log.Errorln(err)
		s.sendSessEstFailRsp(req, addr, ie.CauseMandatoryIEMissing)
		return
	}
	s.log.Debugf("remote nodeid: %v\n", rnodeid)

	rnode, ok := s.rnodes[rnodeid]
	if !ok {
		s.log.Errorf("not found NodeID %v\n", rnodeid)
		s.sendSessEstFailRsp(req, addr, ie.CauseNoEstablishedPFCPAssociation)
		return
	}

	if req.CPFSEID == nil {
		s.log.Errorln("not found CP F-SEID")
		s.sendSessEstFailRsp(req, addr, ie.CauseMandatoryIEMissing)
		return
	}
	fseid, err := req.CPFSEID.FSEID()
	if err != nil {
		s.log.Errorln(err)
		s.sendSessEstFailRsp(req, addr, ie.CauseMandatoryIEMissing)
		return
	}
	s.log.Debugf("fseid.SEID: %#x\n", fseid.SEID)

	// allocate a session
	sess := rnode.NewSess(fseid.SEID)

	// ========================================================================
	// PHASE 1: Validation - Build all plans and validate without execution
	// ========================================================================
	plan := forwarder.NewModificationPlan(sess.LocalID)

	for _, i := range req.CreateFAR {
		p, err1 := sess.ValidateCreateFAR(i)
		if err1 != nil {
			sess.log.Errorf("Est ValidateCreateFAR error: %v", err1)
			cause := pfcpCauseFromError(err1)
			s.sendSessEstFailRsp(req, addr, cause)
			rnode.DeleteSess(sess.LocalID)
			return
		}
		plan.CreateFARs = append(plan.CreateFARs, p)
	}

	for _, i := range req.CreateQER {
		p, err1 := sess.ValidateCreateQER(i)
		if err1 != nil {
			sess.log.Errorf("Est ValidateCreateQER error: %v", err1)
			cause := pfcpCauseFromError(err1)
			s.sendSessEstFailRsp(req, addr, cause)
			rnode.DeleteSess(sess.LocalID)
			return
		}
		plan.CreateQERs = append(plan.CreateQERs, p)
	}

	for _, i := range req.CreateURR {
		p, err1 := sess.ValidateCreateURR(i)
		if err1 != nil {
			sess.log.Errorf("Est ValidateCreateURR error: %v", err1)
			cause := pfcpCauseFromError(err1)
			s.sendSessEstFailRsp(req, addr, cause)
			rnode.DeleteSess(sess.LocalID)
			return
		}
		plan.CreateURRs = append(plan.CreateURRs, p)
	}

	if req.CreateBAR != nil {
		p, err1 := sess.ValidateCreateBAR(req.CreateBAR)
		if err1 != nil {
			sess.log.Errorf("Est ValidateCreateBAR error: %v", err1)
			cause := pfcpCauseFromError(err1)
			s.sendSessEstFailRsp(req, addr, cause)
			rnode.DeleteSess(sess.LocalID)
			return
		}
		plan.CreateBARs = append(plan.CreateBARs, p)
	}

	for _, i := range req.CreatePDR {
		p, err1 := sess.ValidateCreatePDR(i, plan)
		if err1 != nil {
			sess.log.Errorf("Est ValidateCreatePDR error: %v", err1)
			cause := pfcpCauseFromError(err1)
			s.sendSessEstFailRsp(req, addr, cause)
			rnode.DeleteSess(sess.LocalID)
			return
		}
		plan.CreatePDRs = append(plan.CreatePDRs, p)
	}

	// ========================================================================
	// PHASE 2: Execution - Execute all Create operations (fail-fast)
	// ========================================================================
	if _, err1 := sess.rnode.driver.ExecuteEstablishmentPlan(plan); err1 != nil {
		sess.log.Errorf("Est execution error: %v", err1)
		s.sendSessEstFailRsp(req, addr, ie.CauseRuleCreationModificationFailure)
		rnode.DeleteSess(sess.LocalID)
		return
	}

	// ========================================================================
	// PHASE 3: Apply - Update session internal state
	// ========================================================================
	for _, p := range plan.CreateFARs {
		sess.ApplyCreateFAR(p)
	}
	for _, p := range plan.CreateQERs {
		sess.ApplyCreateQER(p)
	}
	for _, p := range plan.CreateURRs {
		sess.ApplyCreateURR(p)
	}
	for _, p := range plan.CreateBARs {
		sess.ApplyCreateBAR(p)
	}

	CreatedPDRList := make([]*ie.IE, 0)
	for _, p := range plan.CreatePDRs {
		sess.ApplyCreatePDR(p)

		ueIPAddress := getUEAddressFromPDR(p.OriginalIE)
		pdrId := getPDRIDFromPDR(p.OriginalIE)

		if ueIPAddress != nil {
			ueIPv4 := ueIPAddress.IPv4Address.String()
			CreatedPDRList = append(CreatedPDRList, ie.NewCreatedPDR(
				ie.NewPDRID(pdrId),
				ie.NewUEIPAddress(2, ueIPv4, "", 0, 0),
			))
		}
	}

	var v4 net.IP
	addrv4, err := net.ResolveIPAddr("ip4", s.nodeID)
	if err == nil {
		v4 = addrv4.IP.To4()
	}
	// TODO: support v6
	var v6 net.IP

	ies := make([]*ie.IE, 0)
	ies = append(ies, CreatedPDRList...)
	ies = append(ies,
		newIeNodeID(s.nodeID),
		ie.NewCause(ie.CauseRequestAccepted),
		ie.NewFSEID(sess.LocalID, v4, v6))

	rsp := message.NewSessionEstablishmentResponse(
		0,             // mp
		0,             // fo
		sess.RemoteID, // seid
		req.Header.SequenceNumber,
		0, // pri
		ies...,
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

		err1 := s.sendRspTo(rsp, addr)
		if err1 != nil {
			s.log.Errorln(err1)
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
			s.log.Errorln(err1)
			return
		}
		s.log.Debugf("new remote nodeid: %v\n", rnodeid)
		s.UpdateNodeID(sess.rnode, rnodeid)
	}

	// ========================================================================
	// PHASE 1: Validation - Build all plans and validate without execution
	// ========================================================================
	plan := forwarder.NewModificationPlan(sess.LocalID)

	for _, i := range req.CreateFAR {
		p, err1 := sess.ValidateCreateFAR(i)
		if err1 != nil {
			sess.log.Errorf("Mod ValidateCreateFAR error: %v", err1)
			cause := pfcpCauseFromError(err1)
			s.sendSessModFailRsp(req, sess, addr, cause)
			return
		}
		plan.CreateFARs = append(plan.CreateFARs, p)
	}

	for _, i := range req.CreateQER {
		p, err1 := sess.ValidateCreateQER(i)
		if err1 != nil {
			sess.log.Errorf("Mod ValidateCreateQER error: %v", err1)
			cause := pfcpCauseFromError(err1)
			s.sendSessModFailRsp(req, sess, addr, cause)
			return
		}
		plan.CreateQERs = append(plan.CreateQERs, p)
	}

	for _, i := range req.CreateURR {
		p, err1 := sess.ValidateCreateURR(i)
		if err1 != nil {
			sess.log.Errorf("Mod ValidateCreateURR error: %v", err1)
			cause := pfcpCauseFromError(err1)
			s.sendSessModFailRsp(req, sess, addr, cause)
			return
		}
		plan.CreateURRs = append(plan.CreateURRs, p)
	}

	if req.CreateBAR != nil {
		p, err1 := sess.ValidateCreateBAR(req.CreateBAR)
		if err1 != nil {
			sess.log.Errorf("Mod ValidateCreateBAR error: %v", err1)
			cause := pfcpCauseFromError(err1)
			s.sendSessModFailRsp(req, sess, addr, cause)
			return
		}
		plan.CreateBARs = append(plan.CreateBARs, p)
	}

	for _, i := range req.CreatePDR {
		p, err1 := sess.ValidateCreatePDR(i, plan)
		if err1 != nil {
			sess.log.Errorf("Mod ValidateCreatePDR error: %v", err1)
			cause := pfcpCauseFromError(err1)
			s.sendSessModFailRsp(req, sess, addr, cause)
			return
		}
		plan.CreatePDRs = append(plan.CreatePDRs, p)
	}

	for _, i := range req.UpdateFAR {
		p, err1 := sess.ValidateUpdateFAR(i, plan)
		if err1 != nil {
			sess.log.Errorf("Mod ValidateUpdateFAR error: %v", err1)
			cause := pfcpCauseFromError(err1)
			s.sendSessModFailRsp(req, sess, addr, cause)
			return
		}
		plan.UpdateFARs = append(plan.UpdateFARs, p)
	}

	for _, i := range req.UpdateQER {
		p, err1 := sess.ValidateUpdateQER(i, plan)
		if err1 != nil {
			sess.log.Errorf("Mod ValidateUpdateQER error: %v", err1)
			cause := pfcpCauseFromError(err1)
			s.sendSessModFailRsp(req, sess, addr, cause)
			return
		}
		plan.UpdateQERs = append(plan.UpdateQERs, p)
	}

	for _, i := range req.UpdateURR {
		p, err1 := sess.ValidateUpdateURR(i, plan)
		if err1 != nil {
			sess.log.Errorf("Mod ValidateUpdateURR error: %v", err1)
			cause := pfcpCauseFromError(err1)
			s.sendSessModFailRsp(req, sess, addr, cause)
			return
		}
		plan.UpdateURRs = append(plan.UpdateURRs, p)
	}

	if req.UpdateBAR != nil {
		p, err1 := sess.ValidateUpdateBAR(req.UpdateBAR, plan)
		if err1 != nil {
			sess.log.Errorf("Mod ValidateUpdateBAR error: %v", err1)
			cause := pfcpCauseFromError(err1)
			s.sendSessModFailRsp(req, sess, addr, cause)
			return
		}
		plan.UpdateBARs = append(plan.UpdateBARs, p)
	}

	for _, i := range req.UpdatePDR {
		p, err1 := sess.ValidateUpdatePDR(i, plan)
		if err1 != nil {
			sess.log.Errorf("Mod ValidateUpdatePDR error: %v", err1)
			cause := pfcpCauseFromError(err1)
			s.sendSessModFailRsp(req, sess, addr, cause)
			return
		}
		plan.UpdatePDRs = append(plan.UpdatePDRs, p)
	}

	for _, i := range req.QueryURR {
		p, err1 := sess.ValidateQueryURR(i, plan)
		if err1 != nil {
			sess.log.Errorf("Mod ValidateQueryURR error: %v", err1)
			cause := pfcpCauseFromError(err1)
			s.sendSessModFailRsp(req, sess, addr, cause)
			return
		}
		plan.QueryURRs = append(plan.QueryURRs, p)
	}

	for _, i := range req.RemoveFAR {
		p, err1 := sess.ValidateRemoveFAR(i, plan)
		if err1 != nil {
			sess.log.Errorf("Mod ValidateRemoveFAR error: %v", err1)
			cause := pfcpCauseFromError(err1)
			s.sendSessModFailRsp(req, sess, addr, cause)
			return
		}
		plan.RemoveFARs = append(plan.RemoveFARs, p)
	}

	for _, i := range req.RemoveQER {
		p, err1 := sess.ValidateRemoveQER(i, plan)
		if err1 != nil {
			sess.log.Errorf("Mod ValidateRemoveQER error: %v", err1)
			cause := pfcpCauseFromError(err1)
			s.sendSessModFailRsp(req, sess, addr, cause)
			return
		}
		plan.RemoveQERs = append(plan.RemoveQERs, p)
	}

	for _, i := range req.RemoveURR {
		p, err1 := sess.ValidateRemoveURR(i, plan)
		if err1 != nil {
			sess.log.Errorf("Mod ValidateRemoveURR error: %v", err1)
			cause := pfcpCauseFromError(err1)
			s.sendSessModFailRsp(req, sess, addr, cause)
			return
		}
		plan.RemoveURRs = append(plan.RemoveURRs, p)
	}

	if req.RemoveBAR != nil {
		p, err1 := sess.ValidateRemoveBAR(req.RemoveBAR, plan)
		if err1 != nil {
			sess.log.Errorf("Mod ValidateRemoveBAR error: %v", err1)
			cause := pfcpCauseFromError(err1)
			s.sendSessModFailRsp(req, sess, addr, cause)
			return
		}
		plan.RemoveBARs = append(plan.RemoveBARs, p)
	}

	for _, i := range req.RemovePDR {
		p, err1 := sess.ValidateRemovePDR(i, plan)
		if err1 != nil {
			sess.log.Errorf("Mod ValidateRemovePDR error: %v", err1)
			cause := pfcpCauseFromError(err1)
			s.sendSessModFailRsp(req, sess, addr, cause)
			return
		}
		plan.RemovePDRs = append(plan.RemovePDRs, p)
	}
	// Validate mutual exclusion across operations
	if err1 := validateMutualExclusion(plan); err1 != nil {
		sess.log.Errorf("Mod mutual exclusion validation error: %v", err1)
		cause := pfcpCauseFromError(err1)
		s.sendSessModFailRsp(req, sess, addr, cause)
		return
	}

	// ========================================================================
	// PHASE 2: Execution - Execute all operations via gtp5gnl (best-effort)
	// ========================================================================
	execResult, err1 := sess.rnode.driver.ExecuteModificationPlan(plan)
	if err1 != nil {
		s.log.Errorf("Execute Modification Plan err: %v", err1)
	}

	// ========================================================================
	// PHASE 3: Apply - Update session internal state
	// ========================================================================
	var usars []report.USAReport

	// Apply Create operations
	for _, p := range plan.CreateFARs {
		sess.ApplyCreateFAR(p)
	}
	for _, p := range plan.CreateQERs {
		sess.ApplyCreateQER(p)
	}
	for _, p := range plan.CreateURRs {
		sess.ApplyCreateURR(p)
	}
	for _, p := range plan.CreateBARs {
		sess.ApplyCreateBAR(p)
	}
	for _, p := range plan.CreatePDRs {
		sess.ApplyCreatePDR(p)
	}

	// Apply Update operations (collect USAReports from PDR URR disassociation)
	// UpdateFAR has no state change
	// UpdateQER has no state change
	for _, p := range plan.UpdateURRs {
		sess.ApplyUpdateURR(p)
	}
	// UpdateBAR has no state change
	for _, p := range plan.UpdatePDRs {
		rs := sess.ApplyUpdatePDR(p)
		if len(rs) > 0 {
			usars = append(usars, rs...)
		}
	}

	// Apply Query operations - QueryURR has no state change

	// Apply Remove operations (collect USAReports from PDR disassociation)
	for _, p := range plan.RemovePDRs {
		rs := sess.ApplyRemovePDR(p)
		if len(rs) > 0 {
			usars = append(usars, rs...)
		}
	}
	for _, p := range plan.RemoveBARs {
		sess.ApplyRemoveBAR(p)
	}
	for _, p := range plan.RemoveURRs {
		sess.ApplyRemoveURR(p)
	}
	for _, p := range plan.RemoveQERs {
		sess.ApplyRemoveQER(p)
	}
	for _, p := range plan.RemoveFARs {
		sess.ApplyRemoveFAR(p)
	}

	// Collect USAReports from execution result (RemoveURR, UpdateURR, QueryURR)
	if execResult != nil && len(execResult.USAReports) > 0 {
		for i := range execResult.USAReports {
			r := &execResult.USAReports[i]

			for _, p := range plan.RemoveURRs {
				if p.URRID == r.URRID {
					r.USARTrigger.Flags |= report.USAR_TRIG_TERMR
					break
				}
			}

			for _, p := range plan.QueryURRs {
				if p.QueryURRID == r.URRID {
					r.USARTrigger.Flags |= report.USAR_TRIG_IMMER
					break
				}
			}
		}
		usars = append(usars, execResult.USAReports...)
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
	}

	// Cleanup removed URRs
	sess.CleanupRemovedURRs()

	if err := s.sendRspTo(rsp, addr); err != nil {
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
		// indicates usage report being reported for a URR due to the termination of the PFCP session
		r.USARTrigger.Flags |= report.USAR_TRIG_TERMR
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

// getUEAddressFromPDR returns the UEIPaddress() from the PDR IE.
func getUEAddressFromPDR(pdr *ie.IE) *ie.UEIPAddressFields {
	ies, err := pdr.CreatePDR()
	if err != nil {
		return nil
	}

	for _, i := range ies {
		// only care about PDI
		if i.Type == ie.PDI {
			ies, err := i.PDI()
			if err != nil {
				return nil
			}
			for _, x := range ies {
				if x.Type == ie.UEIPAddress {
					fields, err := x.UEIPAddress()
					if err != nil {
						return nil
					}
					return fields
				}
			}
		}
	}
	return nil
}

func getPDRIDFromPDR(pdr *ie.IE) uint16 {
	ies, err := pdr.CreatePDR()
	if err != nil {
		return 0
	}

	for _, i := range ies {
		if i.Type == ie.PDRID {
			id, err := i.PDRID()
			if err != nil {
				return 0
			}
			return id
		}
	}
	return 0
}

func (s *PfcpServer) sendSessEstFailRsp(
	req *message.SessionEstablishmentRequest,
	addr net.Addr,
	cause uint8,
) {
	rsp := message.NewSessionEstablishmentResponse(
		0, // mp
		0, // fo
		0, // seid (session not created)
		req.Header.SequenceNumber,
		0, // pri
		ie.NewCause(cause),
	)
	if err := s.sendRspTo(rsp, addr); err != nil {
		s.log.Errorln(err)
	}
}

func (s *PfcpServer) sendSessModFailRsp(
	req *message.SessionModificationRequest,
	sess *Sess,
	addr net.Addr,
	cause uint8,
) {
	rsp := message.NewSessionModificationResponse(
		0,             // mp
		0,             // fo
		sess.RemoteID, // seid
		req.Header.SequenceNumber,
		0, // pri
		ie.NewCause(cause),
	)
	err := s.sendRspTo(rsp, addr)
	if err != nil {
		s.log.Errorln(err)
	}
}

func pfcpCauseFromError(err error) uint8 {
	switch {
	case errors.Is(err, ErrMissingMandatoryIE):
		return ie.CauseMandatoryIEMissing

	case errors.Is(err, ErrMissingConditionalIE):
		return ie.CauseConditionalIEMissing

	case errors.Is(err, ErrRuleNotFound) ||
		errors.Is(err, ErrRuleCreationModificationFailed) ||
		errors.Is(err, ErrMutualExclusionConflict):
		return ie.CauseRuleCreationModificationFailure

	default:
		return ie.CauseSystemFailure
	}
}

// validateMutualExclusion checks for conflicting operations on the same rule within a single request.
// Conflicts detected:
// - Remove + Update same ID (update will fail after remove)
// - Remove + Query same URR ID (query will fail after remove)
// - Remove + Remove same ID (duplicate remove)
// - Create + Create same ID (duplicate create)
// Allowed combinations:
// - Create + Update same ID
// - Create + Remove same ID
func validateMutualExclusion(plan *forwarder.ModificationPlan) error {
	// Helper to check duplicates in a slice
	checkDuplicates := func(ids []uint32, opName string) error {
		seen := make(map[uint32]bool)
		for _, id := range ids {
			if seen[id] {
				return errors.Wrapf(ErrMutualExclusionConflict, "duplicate %s for ID %d", opName, id)
			}
			seen[id] = true
		}
		return nil
	}

	// Helper to check overlap between two ID slices
	checkOverlap := func(ids1, ids2 []uint32, op1Name, op2Name string) error {
		set := make(map[uint32]bool)
		for _, id := range ids1 {
			set[id] = true
		}
		for _, id := range ids2 {
			if set[id] {
				return errors.Wrapf(ErrMutualExclusionConflict, "%s and %s conflict for ID %d", op1Name, op2Name, id)
			}
		}
		return nil
	}

	// Collect IDs from plans
	collectPDRIDs := func(plans []*forwarder.PDRPlan) []uint32 {
		ids := make([]uint32, 0, len(plans))
		for _, p := range plans {
			ids = append(ids, uint32(p.PDRID))
		}
		return ids
	}
	collectFARIDs := func(plans []*forwarder.FARPlan) []uint32 {
		ids := make([]uint32, 0, len(plans))
		for _, p := range plans {
			ids = append(ids, p.FARID)
		}
		return ids
	}
	collectQERIDs := func(plans []*forwarder.QERPlan) []uint32 {
		ids := make([]uint32, 0, len(plans))
		for _, p := range plans {
			ids = append(ids, p.QERID)
		}
		return ids
	}
	collectURRIDs := func(plans []*forwarder.URRPlan) []uint32 {
		ids := make([]uint32, 0, len(plans))
		for _, p := range plans {
			ids = append(ids, p.URRID)
		}
		return ids
	}
	collectQueryURRIDs := func(plans []*forwarder.URRPlan) []uint32 {
		ids := make([]uint32, 0, len(plans))
		for _, p := range plans {
			ids = append(ids, p.QueryURRID)
		}
		return ids
	}
	collectBARIDs := func(plans []*forwarder.BARPlan) []uint32 {
		ids := make([]uint32, 0, len(plans))
		for _, p := range plans {
			ids = append(ids, uint32(p.BARID))
		}
		return ids
	}

	// === PDR checks ===
	createPDRIDs := collectPDRIDs(plan.CreatePDRs)
	removePDRIDs := collectPDRIDs(plan.RemovePDRs)
	updatePDRIDs := collectPDRIDs(plan.UpdatePDRs)

	if err := checkDuplicates(createPDRIDs, "CreatePDR"); err != nil {
		return err
	}
	if err := checkDuplicates(removePDRIDs, "RemovePDR"); err != nil {
		return err
	}
	if err := checkOverlap(removePDRIDs, updatePDRIDs, "RemovePDR", "UpdatePDR"); err != nil {
		return err
	}

	// === FAR checks ===
	createFARIDs := collectFARIDs(plan.CreateFARs)
	removeFARIDs := collectFARIDs(plan.RemoveFARs)
	updateFARIDs := collectFARIDs(plan.UpdateFARs)

	if err := checkDuplicates(createFARIDs, "CreateFAR"); err != nil {
		return err
	}
	if err := checkDuplicates(removeFARIDs, "RemoveFAR"); err != nil {
		return err
	}
	if err := checkOverlap(removeFARIDs, updateFARIDs, "RemoveFAR", "UpdateFAR"); err != nil {
		return err
	}

	// === QER checks ===
	createQERIDs := collectQERIDs(plan.CreateQERs)
	removeQERIDs := collectQERIDs(plan.RemoveQERs)
	updateQERIDs := collectQERIDs(plan.UpdateQERs)

	if err := checkDuplicates(createQERIDs, "CreateQER"); err != nil {
		return err
	}
	if err := checkDuplicates(removeQERIDs, "RemoveQER"); err != nil {
		return err
	}
	if err := checkOverlap(removeQERIDs, updateQERIDs, "RemoveQER", "UpdateQER"); err != nil {
		return err
	}

	// === URR checks ===
	createURRIDs := collectURRIDs(plan.CreateURRs)
	removeURRIDs := collectURRIDs(plan.RemoveURRs)
	updateURRIDs := collectURRIDs(plan.UpdateURRs)
	queryURRIDs := collectQueryURRIDs(plan.QueryURRs)

	if err := checkDuplicates(createURRIDs, "CreateURR"); err != nil {
		return err
	}
	if err := checkDuplicates(removeURRIDs, "RemoveURR"); err != nil {
		return err
	}
	if err := checkOverlap(removeURRIDs, updateURRIDs, "RemoveURR", "UpdateURR"); err != nil {
		return err
	}
	if err := checkOverlap(removeURRIDs, queryURRIDs, "RemoveURR", "QueryURR"); err != nil {
		return err
	}

	// === BAR checks ===
	createBARIDs := collectBARIDs(plan.CreateBARs)
	removeBARIDs := collectBARIDs(plan.RemoveBARs)
	updateBARIDs := collectBARIDs(plan.UpdateBARs)

	if err := checkDuplicates(createBARIDs, "CreateBAR"); err != nil {
		return err
	}
	if err := checkDuplicates(removeBARIDs, "RemoveBAR"); err != nil {
		return err
	}
	if err := checkOverlap(removeBARIDs, updateBARIDs, "RemoveBAR", "UpdateBAR"); err != nil {
		return err
	}

	return nil
}
