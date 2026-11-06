package pfcp

// UPF-owned EES monitoring URRs (opt-in, ees.upfUrrEnabled).
//
// For subscriptions that read the UPF-owned source, the UPF creates one URR in
// each matched PFCP session, links it to every PDR of the session and records
// which subscriptions own it. The URR is removed when no subscription owns it
// any more. Only the PFCP loop goroutine changes these rules, so API handlers
// never wait on the PFCP loop. The SMF never sees this URR: its reports are
// removed from Session Report, Modification and Deletion messages, and SMF
// requests that reference its ID are rejected.

import (
	"sort"
	"time"

	"github.com/pkg/errors"
	"github.com/wmnsk/go-pfcp/ie"

	"github.com/free5gc/go-upf/internal/ees"
	"github.com/free5gc/go-upf/internal/forwarder"
	"github.com/free5gc/go-upf/internal/report"
)

// eesURRIDBase is the first UPF-owned URR ID. TS 29.244 clause 8.2.36: bit 8
// of the URR ID set means "predefined in the UP function", so the SMF does
// not allocate IDs in this range.
const eesURRIDBase uint32 = 0xF0000001

// eesURRReconcileInterval also picks up sessions established after a
// subscription was created.
const eesURRReconcileInterval = time.Second

var errEESOwnedURR = errors.Wrap(ErrRuleCreationModificationFailed, "URR ID is owned by the UPF for EES")

// eesOwnedURR is a URR the UPF created for EES in one session.
type eesOwnedURR struct {
	id     uint32
	period time.Duration
	// owners are the IDs of the subscriptions this URR currently serves.
	owners map[string]struct{}
}

// linkedTo reports whether the PDR in an Update PDR request is measured by
// this URR. Runs in the PFCP loop.
func (o *eesOwnedURR) linkedTo(s *Sess, req *ie.IE) bool {
	pdrID, err := req.PDRID()
	if err != nil {
		return false
	}
	info := s.PDRIDs[pdrID]
	if info == nil {
		return false
	}
	_, ok := info.RelatedURRIDs[o.id]
	return ok
}

// checkNotEESURR rejects SMF requests that create or touch a UPF-owned URR.
func (s *Sess) checkNotEESURR(urrID uint32) error {
	if own := s.eesURR; own != nil && own.id == urrID {
		return errEESOwnedURR
	}
	if s.rnode != nil && s.rnode.local != nil && s.rnode.local.eesURRs && urrID >= eesURRIDBase {
		return errEESOwnedURR
	}
	return nil
}

// pdrChildren returns the sub-IEs of a Create/Update PDR IE, or nil.
func pdrChildren(rule *ie.IE) []*ie.IE {
	var children []*ie.IE
	var err error
	switch rule.Type {
	case ie.CreatePDR:
		children, err = rule.CreatePDR()
	case ie.UpdatePDR:
		children, err = rule.UpdatePDR()
	}
	if err != nil {
		return nil
	}
	return children
}

func pdrHasURRID(rule *ie.IE) bool {
	for _, child := range pdrChildren(rule) {
		if child.Type == ie.URRID {
			return true
		}
	}
	return false
}

// withPDRURRID returns a copy of a Create/Update PDR IE that also lists urrID.
func withPDRURRID(rule *ie.IE, urrID uint32) *ie.IE {
	children := pdrChildren(rule)
	for _, child := range children {
		if child.Type == ie.URRID {
			if id, err := child.URRID(); err == nil && id == urrID {
				return rule
			}
		}
	}
	fields := append(append(make([]*ie.IE, 0, len(children)+1), children...), ie.NewURRID(urrID))
	if rule.Type == ie.CreatePDR {
		return ie.NewCreatePDR(fields...)
	}
	return ie.NewUpdatePDR(fields...)
}

// EnableUPFOwnedURRs turns on the opt-in UPF-owned URR source. Call it before
// Start. store must be the EES subscription store.
func (s *PfcpServer) EnableUPFOwnedURRs(store *ees.SubscriptionStore, period time.Duration) {
	if period <= 0 {
		period = time.Second
	}
	s.eesURRStore, s.eesURRPeriod, s.eesURRWatch = store, period, store.Watch()
	s.lnode.eesURRs = true
}

// UPFOwnedURRsEnabled reports whether EnableUPFOwnedURRs was called.
func (s *PfcpServer) UPFOwnedURRsEnabled() bool { return s.eesURRStore != nil }

// reconcileEESURRs makes the UPF-owned URRs match the current UPF-source
// subscriptions. Runs only in the PFCP loop. A failed step keeps the recorded
// state of what is installed and is retried on the next run.
func (s *PfcpServer) reconcileEESURRs() {
	if s.eesURRStore == nil {
		return
	}
	var subscriptions []*ees.Subscription
	for _, sub := range s.eesURRStore.AllSubscriptions() {
		if sub.UsesUPFURR() {
			subscriptions = append(subscriptions, sub)
		}
	}
	s.lnode.mu.RLock()
	sessions := make([]*Sess, 0, len(s.lnode.sess))
	for _, sess := range s.lnode.sess {
		if sess != nil {
			sessions = append(sessions, sess)
		}
	}
	s.lnode.mu.RUnlock()

	for _, sess := range sessions {
		if sess.eesURR == nil && len(subscriptions) == 0 {
			continue
		}
		identity := sess.identitySnapshot()
		owners := make(map[string]struct{})
		for _, sub := range subscriptions {
			if ees.MatchesTarget(sub, identity) {
				owners[sub.ID] = struct{}{}
			}
		}
		if err := s.syncEESURR(sess, owners); err != nil {
			s.log.Warnf("EES UPF-owned URR on SEID %#x not reconciled yet: %v", sess.LocalID, err)
		}
	}
}

func (s *PfcpServer) syncEESURR(sess *Sess, owners map[string]struct{}) error {
	if len(owners) == 0 {
		if sess.eesURR == nil {
			return nil
		}
		return s.removeEESURR(sess)
	}
	if sess.eesURR == nil {
		if err := s.createEESURR(sess); err != nil {
			return err
		}
	}
	own := sess.eesURR
	if !sameOwners(own.owners, owners) {
		sess.mu.Lock()
		own.owners = owners
		sess.mu.Unlock()
		sess.log.Infof("EES UPF-owned URR %#x owners: %v", own.id, sortedOwners(owners))
	}
	for _, pdrID := range sortedPDRIDs(sess) {
		if _, linked := sess.PDRIDs[pdrID].RelatedURRIDs[own.id]; linked {
			continue
		}
		if err := s.setEESURRLink(sess, pdrID, true); err != nil {
			return err
		}
	}
	return nil
}

func (s *PfcpServer) createEESURR(sess *Sess) error {
	id := eesURRIDBase
	for ; id != 0; id++ {
		if _, used := sess.URRIDs[id]; !used {
			break
		}
	}
	if id == 0 {
		return errors.New("no free UPF-owned URR ID")
	}
	req := ie.NewCreateURR(ie.NewURRID(id),
		ie.NewMeasurementMethod(0, 1, 0),    // VOLUM
		ie.NewReportingTriggers(0x01, 0x00), // PERIO
		ie.NewMeasurementPeriod(s.eesURRPeriod),
		ie.NewMeasurementInformation(0x10)) // MNOP: also count packets (TS 29.244 8.2.68)
	urr, err := s.driver.BuildCreateURRPlan(sess.LocalID, req)
	if err != nil {
		return errors.Wrap(err, "build CreateURR")
	}
	plan := forwarder.NewModificationPlan(sess.LocalID)
	plan.CreateURRs = []*forwarder.URRPlan{urr}
	if _, err = s.driver.ExecuteModificationPlan(plan); err != nil {
		return errors.Wrap(err, "CreateURR")
	}
	sess.ApplyCreateURR(urr)
	sess.mu.Lock()
	sess.eesURR = &eesOwnedURR{id: id, period: s.eesURRPeriod, owners: map[string]struct{}{}}
	sess.mu.Unlock()
	sess.log.Infof("EES UPF-owned URR %#x created (period %v)", id, s.eesURRPeriod)
	return nil
}

// setEESURRLink adds the UPF-owned URR to, or removes it from, one PDR.
// gtp5g replaces a PDR's whole URR list, so the request lists every URR the
// forwarder has for that PDR, not only the ones in session bookkeeping.
func (s *PfcpServer) setEESURRLink(sess *Sess, pdrID uint16, link bool) error {
	own := sess.eesURR
	info := sess.PDRIDs[pdrID]
	wanted := make(map[uint32]struct{}, len(info.fwdURRIDs)+1)
	for id := range info.fwdURRIDs {
		if id != own.id {
			wanted[id] = struct{}{}
		}
	}
	if link {
		wanted[own.id] = struct{}{}
	}
	if len(wanted) > 0 {
		fields := []*ie.IE{ie.NewPDRID(pdrID)}
		for _, id := range sortedURRIDs(wanted) {
			fields = append(fields, ie.NewURRID(id))
		}
		pdr, err := s.driver.BuildUpdatePDRPlan(sess.LocalID, ie.NewUpdatePDR(fields...))
		if err != nil {
			return errors.Wrapf(err, "build UpdatePDR %d", pdrID)
		}
		plan := forwarder.NewModificationPlan(sess.LocalID)
		plan.Strict = true
		plan.UpdatePDRs = []*forwarder.PDRPlan{pdr}
		if _, err = s.driver.ExecuteModificationPlan(plan); err != nil {
			return errors.Wrapf(err, "UpdatePDR %d", pdrID)
		}
	}
	// An empty list cannot be sent (an omitted list means "unchanged"), so a
	// PDR whose only URR is the UPF-owned one keeps a reference that the
	// following Remove URR leaves dangling, as with an SMF Remove URR.
	sess.mu.Lock()
	defer sess.mu.Unlock()
	if len(wanted) > 0 {
		info.fwdURRIDs = wanted
	}
	_, linked := info.RelatedURRIDs[own.id]
	urrInfo := sess.URRIDs[own.id]
	switch {
	case link && !linked:
		info.RelatedURRIDs[own.id] = struct{}{}
		if urrInfo != nil {
			urrInfo.refPdrNum++
		}
	case !link && linked:
		delete(info.RelatedURRIDs, own.id)
		if urrInfo != nil && urrInfo.refPdrNum > 0 {
			urrInfo.refPdrNum--
		}
	}
	return nil
}

func (s *PfcpServer) removeEESURR(sess *Sess) error {
	own := sess.eesURR
	for _, pdrID := range sortedPDRIDs(sess) {
		if _, linked := sess.PDRIDs[pdrID].RelatedURRIDs[own.id]; !linked {
			continue
		}
		if err := s.setEESURRLink(sess, pdrID, false); err != nil {
			return err
		}
	}
	identity := sess.identitySnapshot() // still carries the URR for its final report
	urr, err := s.driver.BuildRemoveURRPlan(sess.LocalID, ie.NewRemoveURR(ie.NewURRID(own.id)))
	if err != nil {
		return errors.Wrap(err, "build RemoveURR")
	}
	plan := forwarder.NewModificationPlan(sess.LocalID)
	plan.Strict = true
	plan.RemoveURRs = []*forwarder.URRPlan{urr}
	result, err := s.driver.ExecuteModificationPlan(plan)
	if err != nil {
		return errors.Wrap(err, "RemoveURR")
	}
	sess.mu.Lock()
	delete(sess.URRIDs, own.id)
	sess.eesURR = nil
	sess.mu.Unlock()
	sess.log.Infof("EES UPF-owned URR %#x removed (no owner left)", own.id)

	if result != nil && len(result.USAReports) > 0 {
		for i := range result.USAReports {
			result.USAReports[i].USARTrigger.Flags |= report.USAR_TRIG_TERMR
		}
		deliverEESUsage(s.eesHandler(), sess.LocalID, identity, result.USAReports)
	}
	return nil
}

// withoutEESURR drops usage of UPF-owned URRs (all IDs from eesURRIDBase
// up, which the SMF may not use in this mode) so that it never reaches the
// SMF. Without UPF-owned URRs it returns usages unchanged.
func (s *PfcpServer) withoutEESURR(usages []report.USAReport) []report.USAReport {
	if s.eesURRStore == nil {
		return usages
	}
	kept := make([]report.USAReport, 0, len(usages))
	for _, usage := range usages {
		if usage.URRID < eesURRIDBase {
			kept = append(kept, usage)
		}
	}
	return kept
}

// withoutEESURRReports is withoutEESURR for a forwarder report; other report
// types are kept. It returns a new slice.
func (s *PfcpServer) withoutEESURRReports(sr report.SessReport) []report.Report {
	kept := make([]report.Report, 0, len(sr.Reports))
	for _, r := range sr.Reports {
		if usage, ok := r.(report.USAReport); ok && usage.URRID >= eesURRIDBase {
			continue
		}
		kept = append(kept, r)
	}
	return kept
}

func sameOwners(a, b map[string]struct{}) bool {
	if len(a) != len(b) {
		return false
	}
	for id := range a {
		if _, ok := b[id]; !ok {
			return false
		}
	}
	return true
}

func sortedOwners(owners map[string]struct{}) []string {
	ids := make([]string, 0, len(owners))
	for id := range owners {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func sortedPDRIDs(sess *Sess) []uint16 {
	ids := make([]uint16, 0, len(sess.PDRIDs))
	for id := range sess.PDRIDs {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}

func sortedURRIDs(set map[uint32]struct{}) []uint32 {
	ids := make([]uint32, 0, len(set))
	for id := range set {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}
