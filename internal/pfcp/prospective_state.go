package pfcp

import (
	"github.com/pkg/errors"

	"github.com/free5gc/go-upf/internal/forwarder"
)

type pdrReferenceState struct {
	FARID        uint32
	FARIDPresent bool
	URRIDs       map[uint32]struct{}
	QERIDs       map[uint32]struct{}
}

type prospectiveRuleState struct {
	PDRs map[uint16]*pdrReferenceState
	FARs map[uint32]struct{}
	QERs map[uint32]struct{}
	URRs map[uint32]struct{}
	BARs map[uint8]struct{}
}

func cloneUint32Set(src map[uint32]struct{}) map[uint32]struct{} {
	dst := make(map[uint32]struct{}, len(src))
	for id := range src {
		dst[id] = struct{}{}
	}
	return dst
}

func currentPDRSet(sess *Sess) map[uint16]struct{} {
	set := make(map[uint16]struct{}, len(sess.PDRIDs))
	for id := range sess.PDRIDs {
		set[id] = struct{}{}
	}
	return set
}

func currentFARSet(sess *Sess) map[uint32]struct{} {
	set := make(map[uint32]struct{}, len(sess.FARIDs))
	for id := range sess.FARIDs {
		set[id] = struct{}{}
	}
	return set
}

func currentQERSet(sess *Sess) map[uint32]struct{} {
	set := make(map[uint32]struct{}, len(sess.QERIDs))
	for id := range sess.QERIDs {
		set[id] = struct{}{}
	}
	return set
}

func currentURRSet(sess *Sess) map[uint32]struct{} {
	set := make(map[uint32]struct{}, len(sess.URRIDs))
	for id := range sess.URRIDs {
		set[id] = struct{}{}
	}
	return set
}

func currentBARSet(sess *Sess) map[uint8]struct{} {
	set := make(map[uint8]struct{}, len(sess.BARIDs))
	for id := range sess.BARIDs {
		set[id] = struct{}{}
	}
	return set
}

func validateRuleOperations[K comparable, P any](
	ruleName string,
	current map[K]struct{},
	creates []P,
	updates []P,
	removes []P,
	idOf func(P) K,
) (map[K]struct{}, error) {
	available := make(map[K]struct{}, len(current)+len(creates))
	for id := range current {
		available[id] = struct{}{}
	}

	for _, rule := range creates {
		id := idOf(rule)
		if _, exists := available[id]; exists {
			return nil, errors.Wrapf(
				ErrRuleCreationModificationFailed,
				"Create%s targets existing ID %v",
				ruleName,
				id,
			)
		}
		available[id] = struct{}{}
	}

	for _, rule := range updates {
		id := idOf(rule)
		if _, exists := available[id]; !exists {
			return nil, errors.Wrapf(ErrRuleNotFound, "Update%s ID %v", ruleName, id)
		}
	}

	for _, rule := range removes {
		id := idOf(rule)
		if _, exists := available[id]; !exists {
			return nil, errors.Wrapf(ErrRuleNotFound, "Remove%s ID %v", ruleName, id)
		}
	}

	return available, nil
}

func (s *Sess) validateOperationTargets(plan *forwarder.ModificationPlan) error {
	if _, err := validateRuleOperations(
		"PDR",
		currentPDRSet(s),
		plan.CreatePDRs,
		plan.UpdatePDRs,
		plan.RemovePDRs,
		func(p *forwarder.PDRPlan) uint16 { return p.PDRID },
	); err != nil {
		return err
	}

	if _, err := validateRuleOperations(
		"FAR",
		currentFARSet(s),
		plan.CreateFARs,
		plan.UpdateFARs,
		plan.RemoveFARs,
		func(p *forwarder.FARPlan) uint32 { return p.FARID },
	); err != nil {
		return err
	}

	if _, err := validateRuleOperations(
		"QER",
		currentQERSet(s),
		plan.CreateQERs,
		plan.UpdateQERs,
		plan.RemoveQERs,
		func(p *forwarder.QERPlan) uint32 { return p.QERID },
	); err != nil {
		return err
	}

	availableURRs, err := validateRuleOperations(
		"URR",
		currentURRSet(s),
		plan.CreateURRs,
		plan.UpdateURRs,
		plan.RemoveURRs,
		func(p *forwarder.URRPlan) uint32 { return p.URRID },
	)
	if err != nil {
		return err
	}
	for _, query := range plan.QueryURRs {
		if _, exists := availableURRs[query.QueryURRID]; !exists {
			return errors.Wrapf(ErrRuleNotFound, "QueryURR ID %v", query.QueryURRID)
		}
	}

	_, err = validateRuleOperations(
		"BAR",
		currentBARSet(s),
		plan.CreateBARs,
		plan.UpdateBARs,
		plan.RemoveBARs,
		func(p *forwarder.BARPlan) uint8 { return p.BARID },
	)
	return err
}

func newProspectiveRuleState(sess *Sess) *prospectiveRuleState {
	state := &prospectiveRuleState{
		PDRs: make(map[uint16]*pdrReferenceState, len(sess.PDRIDs)),
		FARs: currentFARSet(sess),
		QERs: currentQERSet(sess),
		URRs: currentURRSet(sess),
		BARs: currentBARSet(sess),
	}

	for id, info := range sess.PDRIDs {
		state.PDRs[id] = &pdrReferenceState{
			FARID:        info.FARID,
			FARIDPresent: info.HasFARID,
			URRIDs:       cloneUint32Set(info.RelatedURRIDs),
			QERIDs:       cloneUint32Set(info.RelatedQERIDs),
		}
	}

	return state
}

func newPDRReferenceState(plan *forwarder.PDRPlan) *pdrReferenceState {
	return &pdrReferenceState{
		FARID:        plan.FARID,
		FARIDPresent: plan.FARIDPresent,
		URRIDs:       uint32Set(plan.URRIDs),
		QERIDs:       uint32Set(plan.QERIDs),
	}
}

func (state *prospectiveRuleState) apply(plan *forwarder.ModificationPlan) {
	for _, p := range plan.CreateFARs {
		state.FARs[p.FARID] = struct{}{}
	}
	for _, p := range plan.CreateQERs {
		state.QERs[p.QERID] = struct{}{}
	}
	for _, p := range plan.CreateURRs {
		state.URRs[p.URRID] = struct{}{}
	}
	for _, p := range plan.CreateBARs {
		state.BARs[p.BARID] = struct{}{}
	}
	for _, p := range plan.CreatePDRs {
		state.PDRs[p.PDRID] = newPDRReferenceState(p)
	}

	for _, p := range plan.UpdatePDRs {
		references := state.PDRs[p.PDRID]
		if p.FARIDPresent {
			references.FARID = p.FARID
			references.FARIDPresent = true
		}
		if p.URRIDsPresent {
			references.URRIDs = uint32Set(p.URRIDs)
		}
		if p.QERIDsPresent {
			references.QERIDs = uint32Set(p.QERIDs)
		}
	}

	for _, p := range plan.RemovePDRs {
		delete(state.PDRs, p.PDRID)
	}
	for _, p := range plan.RemoveBARs {
		delete(state.BARs, p.BARID)
	}
	for _, p := range plan.RemoveURRs {
		delete(state.URRs, p.URRID)
	}
	for _, p := range plan.RemoveQERs {
		delete(state.QERs, p.QERID)
	}
	for _, p := range plan.RemoveFARs {
		delete(state.FARs, p.FARID)
	}
}

func (state *prospectiveRuleState) validateReferences() error {
	for pdrid, references := range state.PDRs {
		if references.FARIDPresent {
			if _, exists := state.FARs[references.FARID]; !exists {
				return errors.Wrapf(
					ErrRuleCreationModificationFailed,
					"PDR %d references missing FAR %d",
					pdrid,
					references.FARID,
				)
			}
		}

		for qerid := range references.QERIDs {
			if _, exists := state.QERs[qerid]; !exists {
				return errors.Wrapf(
					ErrRuleCreationModificationFailed,
					"PDR %d references missing QER %d",
					pdrid,
					qerid,
				)
			}
		}

		for urrid := range references.URRIDs {
			if _, exists := state.URRs[urrid]; !exists {
				return errors.Wrapf(
					ErrRuleCreationModificationFailed,
					"PDR %d references missing URR %d",
					pdrid,
					urrid,
				)
			}
		}
	}

	return nil
}

// validateProspectiveState validates the rule graph that would exist after the
// complete PFCP request. It is intentionally run only after every individual IE
// has been parsed into ModificationPlan, so reference validation is independent
// of the request's IE order.
func (s *Sess) validateProspectiveState(plan *forwarder.ModificationPlan) error {
	if err := s.validateOperationTargets(plan); err != nil {
		return err
	}

	state := newProspectiveRuleState(s)
	state.apply(plan)
	return state.validateReferences()
}
