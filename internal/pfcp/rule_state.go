package pfcp

import (
	"sort"

	"github.com/pkg/errors"

	"github.com/free5gc/go-upf/internal/rules"
)

// RuleState is a request-scoped candidate, not a second live session. Only
// changed configurations are copied. Unchanged values read through to Session.
// Views are read-only; the caller must serialize validation, execution and commit
// against other changes to the same session.
type RuleState struct {
	sess         *Session
	urrRefDeltas map[uint32]int
	pdrOverrides map[uint16]*rules.PDRConfig
	removedPDRs  map[uint16]struct{}
	farOverrides map[uint32]*rules.FARConfig
	removedFARs  map[uint32]struct{}
	qerOverrides map[uint32]*rules.QERConfig
	removedQERs  map[uint32]struct{}
	urrOverrides map[uint32]*rules.URRConfig
	removedURRs  map[uint32]struct{}
	barOverrides map[uint8]*rules.BARConfig
	removedBARs  map[uint8]struct{}
}

// ValidateRuleState checks the complete request without changing Session or
// calling the datapath. Commit is valid only after successful execution.
func (s *Session) ValidateRuleState(changes *rules.RuleChangeSet) (*RuleState, error) {
	if changes == nil {
		return nil, errors.Wrap(ErrRuleCreationModificationFailed, "nil RuleChangeSet")
	}
	if changes.SEID != s.LocalID {
		return nil, errors.Wrap(ErrRuleCreationModificationFailed, "session ID mismatch")
	}
	state := &RuleState{sess: s}
	if err := state.validateOperations(changes); err != nil {
		return nil, err
	}
	state.buildOverlays(changes)
	if err := state.validateReferences(); err != nil {
		return nil, err
	}
	state.buildURRReferenceDeltas()
	return state, nil
}

func (state *RuleState) validateOperations(changes *rules.RuleChangeSet) error {
	s := state.sess
	opsPDR, err := validateRuleOperations(
		"PDR",
		func(id uint16) bool { _, ok := s.PDRIDs[id]; return ok },
		changes.CreatePDRs, changes.UpdatePDRs, changes.RemovePDRs,
		func(c rules.PDRConfig) uint16 { return c.PDRID },
		func(p rules.PDRPatch) uint16 { return p.PDRID },
	)
	if err != nil {
		return err
	}
	state.removedPDRs = opsPDR.removed
	state.pdrOverrides = make(map[uint16]*rules.PDRConfig)
	opsFAR, err := validateRuleOperations(
		"FAR",
		func(id uint32) bool { _, ok := s.FARIDs[id]; return ok },
		changes.CreateFARs, changes.UpdateFARs, changes.RemoveFARs,
		func(c rules.FARConfig) uint32 { return c.FARID },
		func(p rules.FARPatch) uint32 { return p.FARID },
	)
	if err != nil {
		return err
	}
	state.removedFARs = opsFAR.removed
	state.farOverrides = make(map[uint32]*rules.FARConfig)
	opsQER, err := validateRuleOperations(
		"QER",
		func(id uint32) bool { _, ok := s.QERIDs[id]; return ok },
		changes.CreateQERs, changes.UpdateQERs, changes.RemoveQERs,
		func(c rules.QERConfig) uint32 { return c.QERID },
		func(p rules.QERPatch) uint32 { return p.QERID },
	)
	if err != nil {
		return err
	}
	state.removedQERs = opsQER.removed
	state.qerOverrides = make(map[uint32]*rules.QERConfig)
	opsURR, err := validateRuleOperations(
		"URR",
		func(id uint32) bool { _, ok := s.URRIDs[id]; return ok },
		changes.CreateURRs, changes.UpdateURRs, changes.RemoveURRs,
		func(c rules.URRConfig) uint32 { return c.URRID },
		func(p rules.URRPatch) uint32 { return p.URRID },
	)
	if err != nil {
		return err
	}
	state.removedURRs = opsURR.removed
	state.urrOverrides = make(map[uint32]*rules.URRConfig)
	opsBAR, err := validateRuleOperations(
		"BAR",
		func(id uint8) bool { _, ok := s.BARIDs[id]; return ok },
		changes.CreateBARs, changes.UpdateBARs, changes.RemoveBARs,
		func(c rules.BARConfig) uint8 { return c.BARID },
		func(p rules.BARPatch) uint8 { return p.BARID },
	)
	if err != nil {
		return err
	}
	state.removedBARs = opsBAR.removed
	state.barOverrides = make(map[uint8]*rules.BARConfig)
	for _, id := range changes.QueryURRs {
		if _, removed := state.removedURRs[id]; removed {
			return errors.Wrapf(ErrMutualExclusionConflict, "RemoveURR and QueryURR conflict for ID %d", id)
		}
		if _, created := opsURR.created[id]; !created {
			if _, current := s.URRIDs[id]; !current {
				return errors.Wrapf(ErrRuleNotFound, "QueryURR ID %d", id)
			}
		}
	}
	return nil
}

// buildOverlays merges each update once and owns all changed values.
func (state *RuleState) buildOverlays(changes *rules.RuleChangeSet) {
	for _, c := range changes.CreatePDRs {
		n := c.Clone()
		state.pdrOverrides[c.PDRID] = &n
	}
	for _, p := range changes.UpdatePDRs {
		c, _ := state.PDR(p.PDRID)
		n := c.Merge(p)
		state.pdrOverrides[p.PDRID] = &n
	}
	for _, c := range changes.CreateFARs {
		n := c.Clone()
		state.farOverrides[c.FARID] = &n
	}
	for _, p := range changes.UpdateFARs {
		c, _ := state.FAR(p.FARID)
		n := c.Merge(p)
		state.farOverrides[p.FARID] = &n
	}
	for _, c := range changes.CreateQERs {
		n := c.Clone()
		state.qerOverrides[c.QERID] = &n
	}
	for _, p := range changes.UpdateQERs {
		c, _ := state.QER(p.QERID)
		n := c.Merge(p)
		state.qerOverrides[p.QERID] = &n
	}
	for _, c := range changes.CreateURRs {
		n := c.Clone()
		state.urrOverrides[c.URRID] = &n
	}
	for _, p := range changes.UpdateURRs {
		c, _ := state.URR(p.URRID)
		n := c.Merge(p)
		state.urrOverrides[p.URRID] = &n
	}
	for _, c := range changes.CreateBARs {
		n := c.Clone()
		state.barOverrides[c.BARID] = &n
	}
	for _, p := range changes.UpdateBARs {
		c, _ := state.BAR(p.BARID)
		n := c.Merge(p)
		state.barOverrides[p.BARID] = &n
	}
}

// PDR returns a read-only effective configuration.
func (state *RuleState) PDR(id uint16) (*rules.PDRConfig, bool) {
	if _, removed := state.removedPDRs[id]; removed {
		return nil, false
	}
	if c, changed := state.pdrOverrides[id]; changed {
		return c, true
	}
	c, ok := state.sess.PDRIDs[id]
	return c, ok
}

// FAR returns a read-only effective configuration.
func (state *RuleState) FAR(id uint32) (*rules.FARConfig, bool) {
	if _, removed := state.removedFARs[id]; removed {
		return nil, false
	}
	if c, changed := state.farOverrides[id]; changed {
		return c, true
	}
	c, ok := state.sess.FARIDs[id]
	return c, ok
}

// QER returns a read-only effective configuration.
func (state *RuleState) QER(id uint32) (*rules.QERConfig, bool) {
	if _, removed := state.removedQERs[id]; removed {
		return nil, false
	}
	if c, changed := state.qerOverrides[id]; changed {
		return c, true
	}
	c, ok := state.sess.QERIDs[id]
	return c, ok
}

// URR returns a read-only effective configuration.
func (state *RuleState) URR(id uint32) (*rules.URRConfig, bool) {
	if _, removed := state.removedURRs[id]; removed {
		return nil, false
	}
	if c, changed := state.urrOverrides[id]; changed {
		return c, true
	}
	c, ok := state.sess.URRIDs[id]
	if !ok {
		return nil, false
	}
	return &c.Config, true
}

// BAR returns a read-only effective configuration.
func (state *RuleState) BAR(id uint8) (*rules.BARConfig, bool) {
	if _, removed := state.removedBARs[id]; removed {
		return nil, false
	}
	if c, changed := state.barOverrides[id]; changed {
		return c, true
	}
	c, ok := state.sess.BARIDs[id]
	return c, ok
}

// RangePDR visits every PDR in the effective final state without copying
// unchanged PDRs into a second session-wide map.
func (state *RuleState) RangePDR(
	visit func(id uint16, info *rules.PDRConfig) error,
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

type ruleOperations[K comparable] struct {
	created map[K]struct{}
	removed map[K]struct{}
}

func validateRuleOperations[K comparable, C, U any](
	ruleName string,
	currentExists func(K) bool,
	creates []C,
	updates []U,
	removes []K,
	createID func(C) K,
	updateID func(U) K,
) (ruleOperations[K], error) {
	operations := ruleOperations[K]{
		created: make(map[K]struct{}, len(creates)),
		removed: make(map[K]struct{}, len(removes)),
	}
	updated := make(map[K]struct{}, len(updates))

	for _, rule := range creates {
		id := createID(rule)
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
		updated[updateID(rule)] = struct{}{}
	}
	for _, id := range removes {
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
		id := updateID(rule)
		if !available(id) {
			return ruleOperations[K]{}, errors.Wrapf(
				ErrRuleNotFound,
				"Update%s ID %v",
				ruleName,
				id,
			)
		}
	}
	for _, id := range removes {
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

func (state *RuleState) validateReferences() error {
	validate := func(id uint16, c *rules.PDRConfig) error {
		if c.FARID != nil {
			if _, ok := state.FAR(*c.FARID); !ok {
				return errors.Wrapf(ErrRuleCreationModificationFailed, "PDR %d references missing FAR %d", id, *c.FARID)
			}
		}
		for _, qid := range c.QERIDs {
			if _, ok := state.QER(qid); !ok {
				return errors.Wrapf(ErrRuleCreationModificationFailed, "PDR %d references missing QER %d", id, qid)
			}
		}
		for _, uid := range c.URRIDs {
			if _, ok := state.URR(uid); !ok {
				return errors.Wrapf(ErrRuleCreationModificationFailed, "PDR %d references missing URR %d", id, uid)
			}
		}
		return nil
	}
	if len(state.removedFARs) > 0 || len(state.removedQERs) > 0 || len(state.removedURRs) > 0 {
		return state.RangePDR(validate)
	}
	for id, c := range state.pdrOverrides {
		if _, removed := state.removedPDRs[id]; removed {
			continue
		}
		if err := validate(id, c); err != nil {
			return err
		}
	}
	return nil
}

// buildURRReferenceDeltas compares old and final relationships once per changed
// PDR. Repeated URR IDs count as one reference; transfers have a net zero delta.
func (state *RuleState) buildURRReferenceDeltas() {
	state.urrRefDeltas = make(map[uint32]int)
	accumulate := func(id uint16) {
		if old := state.sess.PDRIDs[id]; old != nil {
			for uid := range uint32Set(old.URRIDs) {
				state.urrRefDeltas[uid]--
			}
		}
		if next, exists := state.PDR(id); exists {
			for uid := range uint32Set(next.URRIDs) {
				state.urrRefDeltas[uid]++
			}
		}
	}
	for id := range state.pdrOverrides {
		accumulate(id)
	}
	for id := range state.removedPDRs {
		if _, changed := state.pdrOverrides[id]; !changed {
			accumulate(id)
		}
	}
}

func (state *RuleState) terminalURRIDs() []uint32 {
	var ids []uint32
	for id, delta := range state.urrRefDeltas {
		current := state.sess.URRIDs[id]
		if current != nil && current.refPdrNum > 0 && int(current.refPdrNum)+delta == 0 {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}

func uint32Set(ids []uint32) map[uint32]struct{} {
	set := make(map[uint32]struct{}, len(ids))
	for _, id := range ids {
		set[id] = struct{}{}
	}
	return set
}
