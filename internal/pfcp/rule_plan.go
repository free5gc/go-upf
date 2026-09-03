package pfcp

import (
	"github.com/pkg/errors"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"

	"github.com/free5gc/go-upf/internal/forwarder"
)

func appendRulePlans[P any](
	destination *[]P,
	operation string,
	ruleIEs []*ie.IE,
	localSEID uint64,
	build func(uint64, *ie.IE) (P, error),
	failure error,
) error {
	for _, ruleIE := range ruleIEs {
		rulePlan, err := build(localSEID, ruleIE)
		if err != nil {
			if errors.Is(err, forwarder.ErrMissingMandatoryRuleIE) {
				failure = ErrMissingMandatoryIE
			}
			return errors.Wrapf(failure, "%s: %v", operation, err)
		}
		*destination = append(*destination, rulePlan)
	}
	return nil
}

// BuildEstablishmentPlan parses every rule operation in one PFCP Session
// Establishment Request without mutating Session or executing netlink commands.
func (s *Session) BuildEstablishmentPlan(
	req *message.SessionEstablishmentRequest,
) (*forwarder.ModificationPlan, error) {
	if req == nil {
		return nil, errors.Wrap(ErrMissingMandatoryIE, "nil SessionEstablishmentRequest")
	}

	plan := forwarder.NewModificationPlan(s.LocalID)

	if err := appendRulePlans(
		&plan.CreateFARs,
		"CreateFAR",
		req.CreateFAR,
		s.LocalID,
		s.driver.BuildCreateFARPlan,
		ErrMissingMandatoryIE,
	); err != nil {
		return nil, err
	}
	if err := appendRulePlans(
		&plan.CreateQERs,
		"CreateQER",
		req.CreateQER,
		s.LocalID,
		s.driver.BuildCreateQERPlan,
		ErrMissingMandatoryIE,
	); err != nil {
		return nil, err
	}
	if err := appendRulePlans(
		&plan.CreateURRs,
		"CreateURR",
		req.CreateURR,
		s.LocalID,
		s.driver.BuildCreateURRPlan,
		ErrMissingMandatoryIE,
	); err != nil {
		return nil, err
	}
	if req.CreateBAR != nil {
		if err := appendRulePlans(
			&plan.CreateBARs,
			"CreateBAR",
			[]*ie.IE{req.CreateBAR},
			s.LocalID,
			s.driver.BuildCreateBARPlan,
			ErrMissingMandatoryIE,
		); err != nil {
			return nil, err
		}
	}
	if err := appendRulePlans(
		&plan.CreatePDRs,
		"CreatePDR",
		req.CreatePDR,
		s.LocalID,
		s.driver.BuildCreatePDRPlan,
		ErrRuleCreationModificationFailed,
	); err != nil {
		return nil, err
	}

	return plan, nil
}

// BuildModificationPlan parses every rule operation in one PFCP Session
// Modification Request without mutating Session or executing netlink commands.
func (s *Session) BuildModificationPlan(
	req *message.SessionModificationRequest,
) (*forwarder.ModificationPlan, error) {
	if req == nil {
		return nil, errors.Wrap(ErrMissingMandatoryIE, "nil SessionModificationRequest")
	}

	plan := forwarder.NewModificationPlan(s.LocalID)

	if err := appendRulePlans(
		&plan.CreateFARs,
		"CreateFAR",
		req.CreateFAR,
		s.LocalID,
		s.driver.BuildCreateFARPlan,
		ErrMissingMandatoryIE,
	); err != nil {
		return nil, err
	}
	if err := appendRulePlans(
		&plan.CreateQERs,
		"CreateQER",
		req.CreateQER,
		s.LocalID,
		s.driver.BuildCreateQERPlan,
		ErrMissingMandatoryIE,
	); err != nil {
		return nil, err
	}
	if err := appendRulePlans(
		&plan.CreateURRs,
		"CreateURR",
		req.CreateURR,
		s.LocalID,
		s.driver.BuildCreateURRPlan,
		ErrMissingMandatoryIE,
	); err != nil {
		return nil, err
	}
	if req.CreateBAR != nil {
		if err := appendRulePlans(
			&plan.CreateBARs,
			"CreateBAR",
			[]*ie.IE{req.CreateBAR},
			s.LocalID,
			s.driver.BuildCreateBARPlan,
			ErrMissingMandatoryIE,
		); err != nil {
			return nil, err
		}
	}
	if err := appendRulePlans(
		&plan.CreatePDRs,
		"CreatePDR",
		req.CreatePDR,
		s.LocalID,
		s.driver.BuildCreatePDRPlan,
		ErrRuleCreationModificationFailed,
	); err != nil {
		return nil, err
	}

	if err := appendRulePlans(
		&plan.UpdateFARs,
		"UpdateFAR",
		req.UpdateFAR,
		s.LocalID,
		s.driver.BuildUpdateFARPlan,
		ErrMissingMandatoryIE,
	); err != nil {
		return nil, err
	}
	if err := appendRulePlans(
		&plan.UpdateQERs,
		"UpdateQER",
		req.UpdateQER,
		s.LocalID,
		s.driver.BuildUpdateQERPlan,
		ErrMissingMandatoryIE,
	); err != nil {
		return nil, err
	}
	if err := appendRulePlans(
		&plan.UpdateURRs,
		"UpdateURR",
		req.UpdateURR,
		s.LocalID,
		s.driver.BuildUpdateURRPlan,
		ErrMissingMandatoryIE,
	); err != nil {
		return nil, err
	}
	if req.UpdateBAR != nil {
		if err := appendRulePlans(
			&plan.UpdateBARs,
			"UpdateBAR",
			[]*ie.IE{req.UpdateBAR},
			s.LocalID,
			s.driver.BuildUpdateBARPlan,
			ErrMissingMandatoryIE,
		); err != nil {
			return nil, err
		}
	}
	if err := appendRulePlans(
		&plan.UpdatePDRs,
		"UpdatePDR",
		req.UpdatePDR,
		s.LocalID,
		s.driver.BuildUpdatePDRPlan,
		ErrMissingMandatoryIE,
	); err != nil {
		return nil, err
	}

	if err := appendRulePlans(
		&plan.QueryURRs,
		"QueryURR",
		req.QueryURR,
		s.LocalID,
		s.driver.BuildQueryURRPlan,
		ErrMissingMandatoryIE,
	); err != nil {
		return nil, err
	}

	if err := appendRulePlans(
		&plan.RemoveFARs,
		"RemoveFAR",
		req.RemoveFAR,
		s.LocalID,
		s.driver.BuildRemoveFARPlan,
		ErrMissingMandatoryIE,
	); err != nil {
		return nil, err
	}
	if err := appendRulePlans(
		&plan.RemoveQERs,
		"RemoveQER",
		req.RemoveQER,
		s.LocalID,
		s.driver.BuildRemoveQERPlan,
		ErrMissingMandatoryIE,
	); err != nil {
		return nil, err
	}
	if err := appendRulePlans(
		&plan.RemoveURRs,
		"RemoveURR",
		req.RemoveURR,
		s.LocalID,
		s.driver.BuildRemoveURRPlan,
		ErrMissingMandatoryIE,
	); err != nil {
		return nil, err
	}
	if req.RemoveBAR != nil {
		if err := appendRulePlans(
			&plan.RemoveBARs,
			"RemoveBAR",
			[]*ie.IE{req.RemoveBAR},
			s.LocalID,
			s.driver.BuildRemoveBARPlan,
			ErrMissingMandatoryIE,
		); err != nil {
			return nil, err
		}
	}
	if err := appendRulePlans(
		&plan.RemovePDRs,
		"RemovePDR",
		req.RemovePDR,
		s.LocalID,
		s.driver.BuildRemovePDRPlan,
		ErrMissingMandatoryIE,
	); err != nil {
		return nil, err
	}

	return plan, nil
}
