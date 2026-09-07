package pfcp

import (
	"net"

	"github.com/pkg/errors"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"

	"github.com/free5gc/go-upf/internal/report"
	"github.com/free5gc/go-upf/internal/rules"
)

func (d *Dispatcher) handleSessionEstablishmentRequest(
	req *message.SessionEstablishmentRequest,
	addr net.Addr,
) {
	d.log.Infoln("handleSessionEstablishmentRequest")

	if req.NodeID == nil {
		d.log.Errorln("not found NodeID")
		d.sendSessEstFailRsp(req, addr, ie.CauseMandatoryIEMissing)
		return
	}
	peerNodeID, err := req.NodeID.NodeID()
	if err != nil {
		d.log.Errorln(err)
		d.sendSessEstFailRsp(req, addr, ie.CauseMandatoryIEMissing)
		return
	}
	d.log.Debugf("peer Node ID: %v\n", peerNodeID)

	association, ok := d.node.Association(peerNodeID)
	if !ok {
		d.log.Errorf("not found NodeID %v\n", peerNodeID)
		d.sendSessEstFailRsp(req, addr, ie.CauseNoEstablishedPFCPAssociation)
		return
	}

	if req.CPFSEID == nil {
		d.log.Errorln("not found CP F-SEID")
		d.sendSessEstFailRsp(req, addr, ie.CauseMandatoryIEMissing)
		return
	}
	fseid, err := req.CPFSEID.FSEID()
	if err != nil {
		d.log.Errorln(err)
		d.sendSessEstFailRsp(req, addr, ie.CauseMandatoryIEMissing)
		return
	}
	d.log.Debugf("fseid.SEID: %#x\n", fseid.SEID)

	// allocate a session
	sess := d.node.CreateSession(association, fseid.SEID)

	// ========================================================================
	// PHASE 1: Planning and prospective-state validation.
	// No Session rule state or kernel state is mutated in this phase.
	// ========================================================================
	// 1A: Parse the request and build one request-level plan.
	changes, err1 := sess.BuildEstablishmentPlan(req)
	if err1 != nil {
		sess.log.Errorf("Est plan build error: %v", err1)
		cause := pfcpCauseFromError(err1)
		d.sendSessEstFailRsp(req, addr, cause)
		d.node.DeleteSession(sess.LocalID)
		return
	}

	// 1B: Validate the complete post-request rule state. The datapath prepares rollback.
	ruleState, err1 := sess.ValidateRuleState(changes)
	if err1 != nil {
		sess.log.Errorf("Est rule-state validation error: %v", err1)
		cause := pfcpCauseFromError(err1)
		d.sendSessEstFailRsp(req, addr, cause)
		d.node.DeleteSession(sess.LocalID)
		return
	}

	// ========================================================================
	// PHASE 2: Execution - Execute all Create operations (fail-fast)
	// ========================================================================
	_, err1 = sess.datapath.Establish(changes)
	if err1 != nil {
		sess.log.Errorf("Est execution error: %v", err1)
		d.sendSessEstFailRsp(req, addr, ie.CauseRuleCreationModificationFailure)
		d.node.DeleteSession(sess.LocalID)
		return
	}

	// ========================================================================
	// PHASE 3: Commit - Publish only kernel-applied state
	// ========================================================================
	ruleState.Commit()

	CreatedPDRList := createdPDRResponseIEs(changes)

	var v4 net.IP
	addrv4, err := net.ResolveIPAddr("ip4", d.node.NodeID)
	if err == nil {
		v4 = addrv4.IP.To4()
	}
	// TODO: support v6
	var v6 net.IP

	ies := make([]*ie.IE, 0)
	ies = append(ies, CreatedPDRList...)
	ies = append(ies,
		newIeNodeID(d.node.NodeID),
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

	err = d.transport.sendRspTo(rsp, addr)
	if err != nil {
		d.log.Errorln(err)
		return
	}
}

func (d *Dispatcher) handleSessionModificationRequest(
	req *message.SessionModificationRequest,
	addr net.Addr,
) {
	d.log.Infoln("handleSessionModificationRequest")

	sess, err := d.node.Session(req.SEID())
	if err != nil {
		d.log.Errorf("handleSessionModificationRequest: %v", err)
		rsp := message.NewSessionModificationResponse(
			0, // mp
			0, // fo
			0, // seid
			req.Header.SequenceNumber,
			0, // pri
			ie.NewCause(ie.CauseSessionContextNotFound),
		)

		err1 := d.transport.sendRspTo(rsp, addr)
		if err1 != nil {
			d.log.Errorln(err1)
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
		peerNodeID, err1 := req.NodeID.NodeID()
		if err1 != nil {
			d.log.Errorln(err1)
			return
		}
		d.log.Debugf("new peer Node ID: %v\n", peerNodeID)
		d.node.UpdateAssociationPeerNodeID(sess.association, peerNodeID)
	}

	// ========================================================================
	// PHASE 1: Planning and prospective-state validation.
	// No Session rule state or kernel state is mutated in this phase.
	// ========================================================================
	// 1A: Parse the request and build one request-level plan.
	changes, err1 := sess.BuildModificationPlan(req)
	if err1 != nil {
		sess.log.Errorf("Mod plan build error: %v", err1)
		cause := pfcpCauseFromError(err1)
		d.sendSessModFailRsp(req, sess, addr, cause)
		return
	}

	// 1B: Validate the complete post-request rule state. The datapath prepares rollback.
	ruleState, err1 := sess.ValidateRuleState(changes)
	if err1 != nil {
		sess.log.Errorf("Mod rule-state validation error: %v", err1)
		cause := pfcpCauseFromError(err1)
		d.sendSessModFailRsp(req, sess, addr, cause)
		return
	}

	// ========================================================================
	// PHASE 2: Execution - The datapath compiles and executes semantic changes.
	// Failed transactions are not published to Session.
	// ========================================================================
	execResult, err1 := sess.datapath.Modify(changes)
	if err1 != nil {
		// The executor has already rolled back every successful operation. Session
		// still represents the pre-request kernel state, so nothing is committed.
		sess.log.Errorf("Mod execution error: %v", err1)
		d.sendSessModFailRsp(req, sess, addr, ie.CauseRuleCreationModificationFailure)
		return
	}

	// ========================================================================
	// PHASE 3: Commit - Publish the fully applied request.
	// ========================================================================
	usars := ruleState.Commit()

	// Collect USAReports from execution result (RemoveURR, UpdateURR, QueryURR)
	if execResult != nil && len(execResult.USAReports) > 0 {
		for i := range execResult.USAReports {
			r := &execResult.USAReports[i]

			for _, id := range changes.RemoveURRs {
				if id == r.URRID {
					r.USARTrigger.Flags |= report.USAR_TRIG_TERMR
					break
				}
			}

			for _, id := range changes.QueryURRs {
				if id == r.URRID {
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
			sess.log.Warnf("Session Mod: URRInfo[%#x] not found", r.URRID)
			continue
		}
		r.URSEQN = sess.URRSeq(r.URRID)
		rsp.UsageReport = append(rsp.UsageReport,
			ie.NewUsageReportWithinSessionModificationResponse(
				r.IEsWithinSessModRsp(
					urrInfo.measurementMethod(), urrInfo.measurementInformation())...,
			))
	}

	// Cleanup removed URRs
	sess.CleanupRemovedURRs()

	if err := d.transport.sendRspTo(rsp, addr); err != nil {
		d.log.Errorln(err)
		return
	}
}

func (d *Dispatcher) handleSessionDeletionRequest(
	req *message.SessionDeletionRequest,
	addr net.Addr,
) {
	// TODO: error response
	d.log.Infoln("handleSessionDeletionRequest")

	lSeid := req.SEID()
	sess, err := d.node.Session(lSeid)
	if err != nil {
		d.log.Errorf("handleSessionDeletionRequest: %v", err)
		rsp := message.NewSessionDeletionResponse(
			0, // mp
			0, // fo
			0, // seid
			req.Header.SequenceNumber,
			0, // pri
			ie.NewCause(ie.CauseSessionContextNotFound),
			ie.NewReportType(0, 0, 1, 0),
		)

		err = d.transport.sendRspTo(rsp, addr)
		if err != nil {
			d.log.Errorln(err)
			return
		}
		return
	}

	usars := d.node.DeleteSession(lSeid)

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
			sess.log.Warnf("Session Del: URRInfo[%#x] not found", r.URRID)
			continue
		}
		r.URSEQN = sess.URRSeq(r.URRID)
		// indicates usage report being reported for a URR due to the termination of the PFCP session
		r.USARTrigger.Flags |= report.USAR_TRIG_TERMR
		rsp.UsageReport = append(rsp.UsageReport,
			ie.NewUsageReportWithinSessionDeletionResponse(
				r.IEsWithinSessDelRsp(
					urrInfo.measurementMethod(), urrInfo.measurementInformation())...,
			))

		if urrInfo.removed {
			delete(sess.URRIDs, r.URRID)
		}
	}

	err = d.transport.sendRspTo(rsp, addr)
	if err != nil {
		d.log.Errorln(err)
		return
	}
}

func (d *Dispatcher) handleSessionReportResponse(
	rsp *message.SessionReportResponse,
	addr net.Addr,
	req message.Message,
) {
	d.log.Infoln("handleSessionReportResponse")

	d.log.Debugf("seid: %#x\n", rsp.SEID())
	if rsp.Header.SEID == 0 {
		if rsp.Cause == nil {
			d.log.Errorf("rsp SEID is 0 without Cause IE")
			return
		}
		cause, err := rsp.Cause.Cause()
		if err != nil {
			d.log.Errorf("rsp SEID is 0 with invalid Cause IE: %v", err)
			return
		}
		if cause != ie.CauseSessionContextNotFound {
			d.log.Errorf("rsp SEID is 0 with unexpected cause[%d]", cause)
			return
		}

		d.log.Warnf("rsp SEID is 0 and cause is Session context not found; delete local session")
		sess, err := d.node.FindSessionByRemoteSEID(req.SEID(), addr)
		if err != nil {
			d.log.Errorln(err)
			return
		}
		d.node.DeleteSession(sess.LocalID)
		return
	}

	sess, err := d.node.Session(rsp.SEID())
	if err != nil {
		d.log.Errorln(err)
		return
	}

	d.log.Debugf("sess: %#+v\n", sess)
}

func (d *Dispatcher) handleSessionReportRequestTimeout(
	req *message.SessionReportRequest,
	addr net.Addr,
) {
	d.log.Warnf("handleSessionReportRequestTimeout: SEID[%#x]", req.SEID())
	// TODO?
}

// createdPDRResponseIEs uses decoded PFCP metadata, never a datapath plan or IE retained by the driver.
func createdPDRResponseIEs(changes *rules.RuleChangeSet) []*ie.IE {
	var result []*ie.IE
	for _, p := range changes.CreatePDRs {
		if p.PDI == nil || p.PDI.UEIPAddress == nil {
			continue
		}
		result = append(result, ie.NewCreatedPDR(ie.NewPDRID(p.PDRID),
			ie.NewUEIPAddress(2, p.PDI.UEIPAddress.IPv4Address.String(), "", 0, 0)))
	}
	return result
}

func (d *Dispatcher) sendSessEstFailRsp(
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
	if err := d.transport.sendRspTo(rsp, addr); err != nil {
		d.log.Errorln(err)
	}
}

func (d *Dispatcher) sendSessModFailRsp(
	req *message.SessionModificationRequest,
	sess *Session,
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
	err := d.transport.sendRspTo(rsp, addr)
	if err != nil {
		d.log.Errorln(err)
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
