package pfcp

import (
	"net"
	"time"

	"github.com/pkg/errors"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"

	"github.com/free5gc/go-upf/internal/ees"
	"github.com/free5gc/go-upf/internal/report"
	"github.com/free5gc/go-upf/internal/rules"
)

// hasPeerAssociation checks the current association records using the
// transport address instead of trusting the Node ID supplied by a request.
func (d *Dispatcher) hasPeerAssociation(addr net.Addr) bool {
	for _, node := range d.node.associations {
		if node.matchesPeer(addr) {
			return true
		}
	}
	return false
}

func (d *Dispatcher) ownsSession(sess *Session, addr net.Addr) bool {
	return d.ownsAssociation(sess.association, addr)
}

func (d *Dispatcher) ownsAssociation(association *PFCPAssociation, addr net.Addr) bool {
	return association.matchesPeer(addr) && d.node.associations[association.PeerNodeID] == association
}

func (d *Dispatcher) eesSnapshot(sess *Session) (func(report.SessReport, ees.SessionContext), ees.SessionContext) {
	if d.eesHandler != nil {
		if handler := d.eesHandler(); handler != nil {
			return handler, sess.identitySnapshot()
		}
	}
	return nil, ees.SessionContext{}
}

func (d *Dispatcher) handleSessionEstablishmentRequest(
	req *message.SessionEstablishmentRequest,
	addr net.Addr,
) {
	d.log.Infoln("handleSessionEstablishmentRequest")

	if !d.hasPeerAssociation(addr) {
		d.sendSessEstFailRsp(req, addr, ie.CauseNoEstablishedPFCPAssociation)
		return
	}

	if req.NodeID == nil {
		d.log.Errorln("not found NodeID")
		d.sendSessEstFailRsp(req, addr, ie.CauseMandatoryIEMissing, ie.NewOffendingIE(ie.NodeID))
		return
	}
	rnodeid, err := req.NodeID.NodeID()
	if err != nil || rnodeid == "" {
		d.log.Errorf("Session Establishment failed: mandatory IE incorrect: NodeID[% x]", req.NodeID.Payload)
		d.sendSessEstFailRsp(req, addr, ie.CauseMandatoryIEIncorrect, ie.NewOffendingIE(ie.NodeID))
		return
	}
	d.log.Debugf("remote nodeid: %v\n", rnodeid)

	rnode, ok := d.node.Association(rnodeid)
	if !ok {
		d.log.Errorf("not found NodeID %v\n", rnodeid)
		d.sendSessEstFailRsp(req, addr, ie.CauseNoEstablishedPFCPAssociation)
		return
	}
	if !rnode.matchesPeer(addr) {
		d.log.Warnf("Session Establishment rejected: peer %v does not match Node ID %q", addr, rnodeid)
		d.sendSessEstFailRsp(req, addr, ie.CauseRequestRejected)
		return
	}

	if req.CPFSEID == nil {
		d.log.Errorln("not found CP F-SEID")
		d.sendSessEstFailRsp(req, addr, ie.CauseMandatoryIEMissing, ie.NewOffendingIE(ie.FSEID))
		return
	}
	fseid, err := req.CPFSEID.FSEID()
	if err != nil {
		d.log.Errorln(err)
		d.sendSessEstFailRsp(req, addr, ie.CauseMandatoryIEIncorrect, ie.NewOffendingIE(ie.FSEID))
		return
	}
	d.log.Debugf("fseid.SEID: %#x\n", fseid.SEID)

	// allocate a session
	sess := d.node.CreateSession(rnode, fseid.SEID)
	fteids := sess.newFTEIDRequest(req.PFCPSEReqFlags != nil && req.PFCPSEReqFlags.HasRESTI(),
		req.CreatePDR, req.CreateTrafficEndpoint)
	defer fteids.release()

	resolved := *req
	resolved.CreatePDR, err = fteids.prepareCreate(req.CreateTrafficEndpoint, req.CreatePDR)
	var changes *rules.RuleChangeSet
	err1 := err
	if err1 == nil {
		changes, err1 = sess.ParseEstablishmentChanges(&resolved)
	}
	if err1 == nil {
		_, err1 = sess.applyRuleChanges(changes, true, fteids)
	}
	if err1 != nil {
		sess.log.Errorf("Establishment rules: %v", err1)
		cause, additionalIEs := ruleErrorResponse(err1)
		d.sendSessEstFailRsp(req, addr, cause, additionalIEs...)
		d.node.DeleteSession(sess.LocalID)
		return
	}

	d.node.publishEESIdentity(sess)
	createdPDRs := createdPDRResponseIEs(changes, fteids)

	var v4 net.IP
	addrv4, err := net.ResolveIPAddr("ip4", d.node.NodeID)
	if err == nil {
		v4 = addrv4.IP.To4()
	}
	// TODO: support v6
	var v6 net.IP

	ies := make([]*ie.IE, 0)
	ies = append(ies, createdPDRs...)
	ies = append(ies, fteids.createdEndpoints()...)
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

	if !d.hasPeerAssociation(addr) {
		d.sendSessModFailRsp(req, nil, addr, ie.CauseNoEstablishedPFCPAssociation)
		return
	}

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

	if !d.ownsSession(sess, addr) {
		d.sendSessModFailRsp(req, nil, addr, ie.CauseRequestRejected)
		return
	}
	if sess.closing {
		d.sendSessModFailRsp(req, sess, addr, ie.CauseRuleCreationModificationFailure)
		return
	}
	if req.NodeID != nil {
		nodeID, err := req.NodeID.NodeID()
		if err != nil || nodeID == "" {
			d.sendSessModFailRsp(req, sess, addr, ie.CauseMandatoryIEIncorrect, ie.NewOffendingIE(ie.NodeID))
			return
		}
		// A claimed Node ID cannot authorize takeover of this association.
		if nodeID != sess.association.PeerNodeID {
			d.sendSessModFailRsp(req, sess, addr, ie.CauseRequestRejected)
			return
		}
	}
	eesHandler, identity := d.eesSnapshot(sess)
	fteids := sess.newFTEIDRequest(false,
		req.CreatePDR, req.UpdatePDR, req.CreateTrafficEndpoint, req.UpdateTrafficEndpoint)
	defer fteids.release()
	resolved, err1 := fteids.prepareModification(req)
	var changes *rules.RuleChangeSet
	if err1 == nil {
		changes, err1 = sess.ParseModificationChanges(resolved)
	}
	var usars []report.USAReport
	if err1 == nil {
		usars, err1 = sess.applyRuleChanges(changes, false, fteids)
	}
	if err1 != nil {
		sess.log.Errorf("Modification rules: %v", err1)
		cause, additionalIEs := ruleErrorResponse(err1)
		d.sendSessModFailRsp(req, sess, addr, cause, additionalIEs...)
		return
	}

	d.node.publishEESIdentity(sess)
	rsp := message.NewSessionModificationResponse(
		0,             // mp
		0,             // fo
		sess.RemoteID, // seid
		req.Header.SequenceNumber,
		0, // pri
		ie.NewCause(ie.CauseRequestAccepted),
	)
	rsp.CreatedUpdatedTrafficEndpoint = fteids.createdEndpoints()
	for _, pdr := range changes.CreatePDRs {
		if teid, ok := fteids.created[pdr.PDRID]; ok {
			rsp.CreatedPDR = append(rsp.CreatedPDR,
				ie.NewCreatedPDR(ie.NewPDRID(pdr.PDRID), fteids.fteid(teid)))
		}
	}
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

	if eesHandler != nil && identity.UeIPv4Addr == "" {
		identity = sess.identitySnapshot()
	}
	deliverEESUsage(eesHandler, sess.LocalID, identity, usars)

	// Cleanup removed URRs
	sess.CleanupRemovedURRs()

	if err := d.transport.sendRspTo(rsp, addr); err != nil {
		d.log.Errorln(err)
		return
	}
}

// Retain completed deletions longer than the SMF's overall retry deadline.
const deletionReplayWindow = time.Minute

type completedDeletion struct {
	association *PFCPAssociation
	remoteSEID  uint64
	reports     []*ie.IE
	expiresAt   time.Time
}

func (d *Dispatcher) replaySessionDeletion(
	req *message.SessionDeletionRequest, addr net.Addr, deletion completedDeletion,
) {
	if !d.ownsAssociation(deletion.association, addr) {
		d.sendSessDelFailRsp(req, addr, ie.CauseRequestRejected)
		return
	}
	rsp := message.NewSessionDeletionResponse(
		0, 0, deletion.remoteSEID, req.Sequence(), 0, ie.NewCause(ie.CauseRequestAccepted),
	)
	rsp.UsageReport = deletion.reports
	if err := d.transport.sendRspTo(rsp, addr); err != nil {
		d.log.Errorln(err)
	}
}

func (d *Dispatcher) handleSessionDeletionRequest(
	req *message.SessionDeletionRequest,
	addr net.Addr,
) {
	d.log.Infoln("handleSessionDeletionRequest")
	if !d.hasPeerAssociation(addr) {
		d.sendSessDelFailRsp(req, addr, ie.CauseNoEstablishedPFCPAssociation)
		return
	}

	lSeid := req.SEID()
	if deletion, ok := d.completedDeletions[lSeid]; ok {
		d.replaySessionDeletion(req, addr, deletion)
		return
	}
	sess, err := d.node.Session(lSeid)
	if err != nil {
		d.log.Errorf("handleSessionDeletionRequest: %v", err)
		d.sendSessDelFailRsp(req, addr, ie.CauseSessionContextNotFound)
		return
	}
	if !d.ownsSession(sess, addr) {
		d.sendSessDelFailRsp(req, addr, ie.CauseRequestRejected)
		return
	}

	eesHandler, identity := d.eesSnapshot(sess)
	usars, cleanupErr := d.node.deleteSessionByRequest(sess)
	cause := ie.CauseRequestAccepted
	if cleanupErr != nil {
		cause = ie.CauseSystemFailure
		sess.log.Errorf("Session cleanup pending: %v", cleanupErr)
	}

	rsp := message.NewSessionDeletionResponse(
		0,             // mp
		0,             // fo
		sess.RemoteID, // seid
		req.Header.SequenceNumber,
		0, // pri
		ie.NewCause(cause),
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

	if cleanupErr == nil {
		d.completedDeletions[lSeid] = completedDeletion{
			association: sess.association,
			remoteSEID:  sess.RemoteID,
			reports:     rsp.UsageReport,
			expiresAt:   time.Now().Add(deletionReplayWindow),
		}
		deliverEESUsage(eesHandler, lSeid, identity, usars)
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

	var reportingSession *Session
	if bound, ok := req.(*sessionReportRequest); ok {
		current, err := d.node.Session(bound.session.LocalID)
		if err != nil || current != bound.session {
			return // The reporting Session has already been cleaned up.
		}
		reportingSession = current
	}

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
		if reportingSession == nil {
			var err error
			reportingSession, err = d.node.FindSessionByRemoteSEID(req.SEID(), addr)
			if err != nil {
				d.log.Errorln(err)
				return
			}
		}
		d.node.DeleteSession(reportingSession.LocalID)
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
func createdPDRResponseIEs(changes *rules.RuleChangeSet, fteids *fteidRequest) []*ie.IE {
	var result []*ie.IE
	for _, p := range changes.CreatePDRs {
		ies := []*ie.IE{ie.NewPDRID(p.PDRID)}
		if fteids != nil {
			if teid, ok := fteids.created[p.PDRID]; ok {
				ies = append(ies, fteids.fteid(teid))
			}
		}
		if p.PDI != nil && p.PDI.UEIPAddress != nil {
			ies = append(ies, ie.NewUEIPAddress(2, p.PDI.UEIPAddress.IPv4Address.String(), "", 0, 0))
		}
		if len(ies) > 1 {
			result = append(result, ie.NewCreatedPDR(ies...))
		}
	}
	return result
}

func (d *Dispatcher) sendSessEstFailRsp(
	req *message.SessionEstablishmentRequest,
	addr net.Addr,
	cause uint8,
	additionalIEs ...*ie.IE,
) {
	var peerSEID uint64
	if req.CPFSEID != nil {
		if fseid, err := req.CPFSEID.FSEID(); err == nil {
			peerSEID = fseid.SEID
		}
	}
	ies := append([]*ie.IE{newIeNodeID(d.node.NodeID), ie.NewCause(cause)}, additionalIEs...)
	rsp := message.NewSessionEstablishmentResponse(
		0, // mp
		0, // fo
		peerSEID,
		req.Header.SequenceNumber,
		0, // pri
		ies...,
	)
	if err := d.transport.sendRspTo(rsp, addr); err != nil {
		d.log.Errorln(err)
	}
}

func (d *Dispatcher) sendSessDelFailRsp(req *message.SessionDeletionRequest, addr net.Addr, cause uint8) {
	rsp := message.NewSessionDeletionResponse(0, 0, 0, req.Header.SequenceNumber, 0, ie.NewCause(cause))
	if err := d.transport.sendRspTo(rsp, addr); err != nil {
		d.log.Errorln(err)
	}
}

func (d *Dispatcher) sendSessModFailRsp(
	req *message.SessionModificationRequest,
	sess *Session,
	addr net.Addr,
	cause uint8,
	additionalIEs ...*ie.IE,
) {
	var seid uint64
	if sess != nil {
		seid = sess.RemoteID
	}
	ies := append([]*ie.IE{ie.NewCause(cause)}, additionalIEs...)
	rsp := message.NewSessionModificationResponse(
		0, // mp
		0, // fo
		seid,
		req.Header.SequenceNumber,
		0, // pri
		ies...,
	)
	err := d.transport.sendRspTo(rsp, addr)
	if err != nil {
		d.log.Errorln(err)
	}
}

func ruleErrorResponse(err error) (uint8, []*ie.IE) {
	var ieErr *ruleIEError
	switch {
	case errors.As(err, &ieErr):
		return ieErr.cause, []*ie.IE{ie.NewOffendingIE(ieErr.ieType)}

	case errors.Is(err, ErrMissingMandatoryIE):
		return ie.CauseMandatoryIEMissing, nil

	case errors.Is(err, ErrMissingConditionalIE):
		return ie.CauseConditionalIEMissing, nil

	case errors.Is(err, ErrInvalidFTEIDAllocation):
		return ie.CauseInvalidFTEIDAllocationOption, nil

	case errors.Is(err, ErrFTEIDInUse):
		return ie.CauseRequestRejected, nil

	case errors.Is(err, ErrRuleNotFound) ||
		errors.Is(err, ErrRuleCreationModificationFailed) ||
		errors.Is(err, ErrMutualExclusionConflict):
		return ie.CauseRuleCreationModificationFailure, nil

	default:
		return ie.CauseSystemFailure, nil
	}
}
