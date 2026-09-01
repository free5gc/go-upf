package pfcp

import (
	"sort"

	"github.com/pkg/errors"

	"github.com/free5gc/go-upf/internal/forwarder"
	"github.com/free5gc/go-upf/internal/report"
)

// RuleState is the validated, effective session rule state produced by a PFCP
// request. It stores only changed PDR/QER values and removal tombstones;
// unchanged rules are read directly from Session.
type RuleState struct {
	sess *Session
	plan *forwarder.ModificationPlan

	createdFARs map[uint32]struct{}
	createdURRs map[uint32]struct{}

	removedPDRs map[uint16]struct{}
	removedFARs map[uint32]struct{}
	removedQERs map[uint32]struct{}
	removedURRs map[uint32]struct{}

	pdrOverrides map[uint16]*PDRInfo
	qerOverrides map[uint32]*QERInfo

	affectedPDRs map[uint16]struct{}
}

func newRuleState(
	sess *Session,
	plan *forwarder.ModificationPlan,
) *RuleState {
	return &RuleState{
		sess: sess,
		plan: plan,

		createdFARs: make(map[uint32]struct{}),
		createdURRs: make(map[uint32]struct{}),

		removedPDRs: make(map[uint16]struct{}),
		removedFARs: make(map[uint32]struct{}),
		removedQERs: make(map[uint32]struct{}),
		removedURRs: make(map[uint32]struct{}),

		pdrOverrides: make(map[uint16]*PDRInfo),
		qerOverrides: make(map[uint32]*QERInfo),

		affectedPDRs: make(map[uint16]struct{}),
	}
}

// ValidateRuleState builds and validates the effective state for the complete
// request without modifying Session. The returned state can be used by resolvers
// and committed only after successful kernel execution.
func (s *Session) ValidateRuleState(
	plan *forwarder.ModificationPlan,
) (*RuleState, error) {
	if plan == nil {
		return nil, errors.Wrap(ErrRuleCreationModificationFailed, "nil ModificationPlan")
	}

	state := newRuleState(s, plan)
	if err := state.validateOperations(); err != nil {
		return nil, err
	}
	state.buildOverlays()
	if err := state.validateReferences(); err != nil {
		return nil, err
	}
	state.findAffectedPDRs()

	return state, nil
}

// Plan returns the parsed operations and netlink attributes that correspond to
// this effective rule view.
func (state *RuleState) Plan() *forwarder.ModificationPlan {
	return state.plan
}

// PDR returns the effective PDR after all request operations. The returned value
// is read-only and remains owned by RuleState or its base session.
func (state *RuleState) PDR(id uint16) (*PDRInfo, bool) {
	if _, removed := state.removedPDRs[id]; removed {
		return nil, false
	}
	if info, changed := state.pdrOverrides[id]; changed {
		return info, true
	}
	info, exists := state.sess.PDRIDs[id]
	return info, exists
}

// QER returns the effective QER after all request operations. The returned value
// is read-only and remains owned by RuleState or its base session.
func (state *RuleState) QER(id uint32) (*QERInfo, bool) {
	if _, removed := state.removedQERs[id]; removed {
		return nil, false
	}
	if info, changed := state.qerOverrides[id]; changed {
		return info, true
	}
	info, exists := state.sess.QERIDs[id]
	return info, exists
}

// RangePDR visits every PDR in the effective final state without copying
// unchanged PDRs into a second session-wide map.
func (state *RuleState) RangePDR(
	visit func(id uint16, info *PDRInfo) error,
) error {
	for id, info := range state.sess.PDRIDs {
		if _, removed := state.removedPDRs[id]; removed {
			continue
		}
		if _, overridden := state.pdrOverrides[id]; overridden {
			continue
		}
		if err := visit(id, info); err != nil {
			return err
		}
	}
	for id, info := range state.pdrOverrides {
		if _, removed := state.removedPDRs[id]; removed {
			continue
		}
		if err := visit(id, info); err != nil {
			return err
		}
	}
	return nil
}

// AffectedPDRIDs returns a deterministic list for future FlowQoS resolution.
// It includes directly changed PDRs and PDRs that reference a changed QER.
func (state *RuleState) AffectedPDRIDs() []uint16 {
	ids := make([]uint16, 0, len(state.affectedPDRs))
	for id := range state.affectedPDRs {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}

// Commit applies the already validated plan to Session after kernel execution.
// It preserves the existing URR reporting/refcount side effects.
func (state *RuleState) Commit() []report.USAReport {
	plan := state.plan
	sess := state.sess

	for _, rule := range plan.CreateFARs {
		sess.ApplyCreateFAR(rule)
	}
	for _, rule := range plan.CreateQERs {
		sess.ApplyCreateQER(rule)
	}
	for _, rule := range plan.CreateURRs {
		sess.ApplyCreateURR(rule)
	}
	for _, rule := range plan.CreateBARs {
		sess.ApplyCreateBAR(rule)
	}
	for _, rule := range plan.CreatePDRs {
		sess.ApplyCreatePDR(rule)
	}

	for _, rule := range plan.UpdateQERs {
		sess.ApplyUpdateQER(rule)
	}
	for _, rule := range plan.UpdateURRs {
		sess.ApplyUpdateURR(rule)
	}

	var reports []report.USAReport
	for _, rule := range plan.UpdatePDRs {
		reports = append(reports, sess.ApplyUpdatePDR(rule)...)
	}
	for _, rule := range plan.RemovePDRs {
		reports = append(reports, sess.ApplyRemovePDR(rule)...)
	}

	for _, rule := range plan.RemoveBARs {
		sess.ApplyRemoveBAR(rule)
	}
	for _, rule := range plan.RemoveURRs {
		sess.ApplyRemoveURR(rule)
	}
	for _, rule := range plan.RemoveQERs {
		sess.ApplyRemoveQER(rule)
	}
	for _, rule := range plan.RemoveFARs {
		sess.ApplyRemoveFAR(rule)
	}

	return reports
}

type ruleOperations[K comparable] struct {
	created map[K]struct{}
	removed map[K]struct{}
}

func validateRuleOperations[K comparable, P any](
	ruleName string,
	currentExists func(K) bool,
	creates []P,
	updates []P,
	removes []P,
	idOf func(P) K,
) (ruleOperations[K], error) {
	operations := ruleOperations[K]{
		created: make(map[K]struct{}, len(creates)),
		removed: make(map[K]struct{}, len(removes)),
	}
	updated := make(map[K]struct{}, len(updates))

	for _, rule := range creates {
		id := idOf(rule)
		if _, duplicate := operations.created[id]; duplicate {
			return ruleOperations[K]{}, errors.Wrapf(
				ErrMutualExclusionConflict,
				"duplicate Create%s for ID %v",
				ruleName,
				id,
			)
		}
		operations.created[id] = struct{}{}
	}
	for _, rule := range updates {
		updated[idOf(rule)] = struct{}{}
	}
	for _, rule := range removes {
		id := idOf(rule)
		if _, duplicate := operations.removed[id]; duplicate {
			return ruleOperations[K]{}, errors.Wrapf(
				ErrMutualExclusionConflict,
				"duplicate Remove%s for ID %v",
				ruleName,
				id,
			)
		}
		if _, conflict := updated[id]; conflict {
			return ruleOperations[K]{}, errors.Wrapf(
				ErrMutualExclusionConflict,
				"Remove%s and Update%s conflict for ID %v",
				ruleName,
				ruleName,
				id,
			)
		}
		operations.removed[id] = struct{}{}
	}

	for id := range operations.created {
		if currentExists(id) {
			return ruleOperations[K]{}, errors.Wrapf(
				ErrRuleCreationModificationFailed,
				"Create%s targets existing ID %v",
				ruleName,
				id,
			)
		}
	}

	available := func(id K) bool {
		if _, exists := operations.created[id]; exists {
			return true
		}
		return currentExists(id)
	}
	for _, rule := range updates {
		id := idOf(rule)
		if !available(id) {
			return ruleOperations[K]{}, errors.Wrapf(
				ErrRuleNotFound,
				"Update%s ID %v",
				ruleName,
				id,
			)
		}
	}
	for _, rule := range removes {
		id := idOf(rule)
		if !available(id) {
			return ruleOperations[K]{}, errors.Wrapf(
				ErrRuleNotFound,
				"Remove%s ID %v",
				ruleName,
				id,
			)
		}
	}

	return operations, nil
}

func (state *RuleState) validateOperations() error {
	pdrOperations, err := validateRuleOperations(
		"PDR",
		func(id uint16) bool {
			_, exists := state.sess.PDRIDs[id]
			return exists
		},
		state.plan.CreatePDRs,
		state.plan.UpdatePDRs,
		state.plan.RemovePDRs,
		func(rule *forwarder.PDRPlan) uint16 { return rule.PDRID },
	)
	if err != nil {
		return err
	}
	state.removedPDRs = pdrOperations.removed

	farOperations, err := validateRuleOperations(
		"FAR",
		func(id uint32) bool {
			_, exists := state.sess.FARIDs[id]
			return exists
		},
		state.plan.CreateFARs,
		state.plan.UpdateFARs,
		state.plan.RemoveFARs,
		func(rule *forwarder.FARPlan) uint32 { return rule.FARID },
	)
	if err != nil {
		return err
	}
	state.createdFARs = farOperations.created
	state.removedFARs = farOperations.removed

	qerOperations, err := validateRuleOperations(
		"QER",
		func(id uint32) bool {
			_, exists := state.sess.QERIDs[id]
			return exists
		},
		state.plan.CreateQERs,
		state.plan.UpdateQERs,
		state.plan.RemoveQERs,
		func(rule *forwarder.QERPlan) uint32 { return rule.QERID },
	)
	if err != nil {
		return err
	}
	state.removedQERs = qerOperations.removed

	urrOperations, err := validateRuleOperations(
		"URR",
		func(id uint32) bool {
			_, exists := state.sess.URRIDs[id]
			return exists
		},
		state.plan.CreateURRs,
		state.plan.UpdateURRs,
		state.plan.RemoveURRs,
		func(rule *forwarder.URRPlan) uint32 { return rule.URRID },
	)
	if err != nil {
		return err
	}
	state.createdURRs = urrOperations.created
	state.removedURRs = urrOperations.removed

	for _, query := range state.plan.QueryURRs {
		id := query.QueryURRID
		if _, removed := state.removedURRs[id]; removed {
			return errors.Wrapf(
				ErrMutualExclusionConflict,
				"RemoveURR and QueryURR conflict for ID %d",
				id,
			)
		}
		_, created := state.createdURRs[id]
		_, current := state.sess.URRIDs[id]
		if !created && !current {
			return errors.Wrapf(ErrRuleNotFound, "QueryURR ID %v", id)
		}
	}

	_, err = validateRuleOperations(
		"BAR",
		func(id uint8) bool {
			_, exists := state.sess.BARIDs[id]
			return exists
		},
		state.plan.CreateBARs,
		state.plan.UpdateBARs,
		state.plan.RemoveBARs,
		func(rule *forwarder.BARPlan) uint8 { return rule.BARID },
	)
	return err
}

func (state *RuleState) buildOverlays() {
	for _, rule := range state.plan.CreatePDRs {
		state.pdrOverrides[rule.PDRID] = newPDRInfo(rule)
		state.affectedPDRs[rule.PDRID] = struct{}{}
	}
	for _, rule := range state.plan.UpdatePDRs {
		current, _ := state.PDR(rule.PDRID)
		state.pdrOverrides[rule.PDRID] = mergePDRInfo(current, rule)
		state.affectedPDRs[rule.PDRID] = struct{}{}
	}

	for _, rule := range state.plan.CreateQERs {
		state.qerOverrides[rule.QERID] = newQERInfo(rule.DesiredState)
	}
	for _, rule := range state.plan.UpdateQERs {
		current, _ := state.QER(rule.QERID)
		state.qerOverrides[rule.QERID] = mergeQERInfo(current, rule.DesiredState)
	}

	for id := range state.removedPDRs {
		state.affectedPDRs[id] = struct{}{}
	}
}

func effectiveExists[K comparable](
	id K,
	currentExists bool,
	created map[K]struct{},
	removed map[K]struct{},
) bool {
	if _, deleted := removed[id]; deleted {
		return false
	}
	if _, added := created[id]; added {
		return true
	}
	return currentExists
}

func (state *RuleState) farExists(id uint32) bool {
	_, current := state.sess.FARIDs[id]
	return effectiveExists(id, current, state.createdFARs, state.removedFARs)
}

func (state *RuleState) qerExists(id uint32) bool {
	_, exists := state.QER(id)
	return exists
}

func (state *RuleState) urrExists(id uint32) bool {
	_, current := state.sess.URRIDs[id]
	return effectiveExists(id, current, state.createdURRs, state.removedURRs)
}

func (state *RuleState) validatePDRReferences(
	pdrID uint16,
	info *PDRInfo,
) error {
	if info.HasFARID && !state.farExists(info.FARID) {
		return errors.Wrapf(
			ErrRuleCreationModificationFailed,
			"PDR %d references missing FAR %d",
			pdrID,
			info.FARID,
		)
	}
	for qerID := range info.RelatedQERIDs {
		if !state.qerExists(qerID) {
			return errors.Wrapf(
				ErrRuleCreationModificationFailed,
				"PDR %d references missing QER %d",
				pdrID,
				qerID,
			)
		}
	}
	for urrID := range info.RelatedURRIDs {
		if !state.urrExists(urrID) {
			return errors.Wrapf(
				ErrRuleCreationModificationFailed,
				"PDR %d references missing URR %d",
				pdrID,
				urrID,
			)
		}
	}
	return nil
}

func (state *RuleState) validateReferences() error {
	if len(state.removedFARs) > 0 || len(state.removedQERs) > 0 || len(state.removedURRs) > 0 {
		return state.RangePDR(state.validatePDRReferences)
	}

	for id, info := range state.pdrOverrides {
		if _, removed := state.removedPDRs[id]; removed {
			continue
		}
		if err := state.validatePDRReferences(id, info); err != nil {
			return err
		}
	}
	return nil
}

func referencesAnyQER(info *PDRInfo, qerIDs map[uint32]struct{}) bool {
	for id := range info.RelatedQERIDs {
		if _, changed := qerIDs[id]; changed {
			return true
		}
	}
	return false
}

func (state *RuleState) findAffectedPDRs() {
	changedQERs := make(map[uint32]struct{},
		len(state.plan.CreateQERs)+len(state.plan.UpdateQERs)+len(state.plan.RemoveQERs))
	for _, rule := range state.plan.CreateQERs {
		changedQERs[rule.QERID] = struct{}{}
	}
	for _, rule := range state.plan.UpdateQERs {
		changedQERs[rule.QERID] = struct{}{}
	}
	for _, rule := range state.plan.RemoveQERs {
		changedQERs[rule.QERID] = struct{}{}
	}

	if len(changedQERs) == 0 {
		return
	}

	// Directly changed PDRs were marked while building overlays. This single pass adds
	// otherwise unchanged PDRs affected by a QER operation and retains the old
	// side of any PDR rewire for future resolver cleanup.
	for id, info := range state.sess.PDRIDs {
		if referencesAnyQER(info, changedQERs) {
			state.affectedPDRs[id] = struct{}{}
		}
	}
}
