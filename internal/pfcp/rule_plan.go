package pfcp

import (
	"github.com/free5gc/go-upf/internal/rules"
	"github.com/pkg/errors"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

func appendRuleChanges[P any](destination *[]P, operation string, ies []*ie.IE,
	parse func(*ie.IE) (P, error), failure error) error {
	for _, i := range ies {
		p, err := parse(i)
		if err != nil {
			if errors.Is(err, ErrMissingMandatoryIE) {
				failure = ErrMissingMandatoryIE
			}
			return errors.Wrapf(failure, "%s: %v", operation, err)
		}
		*destination = append(*destination, p)
	}
	return nil
}

func parseRuleID[T any](i *ie.IE, kind uint16, get func(*ie.IE) (T, error)) (T, error) {
	var zero T
	if i == nil {
		return zero, errors.Wrap(ErrMissingMandatoryIE, "nil rule IE")
	}
	if i.Type != kind {
		return zero, errors.Errorf("unexpected rule IE %d", i.Type)
	}
	return get(i)
}

// BuildEstablishmentPlan decodes all supported rule operations without a driver,
// netlink encoding, or mutation of Session. The result owns its decoded values.
func (s *Session) BuildEstablishmentPlan(req *message.SessionEstablishmentRequest) (*rules.RuleChangeSet, error) {
	if req == nil {
		return nil, errors.Wrap(ErrMissingMandatoryIE, "nil SessionEstablishmentRequest")
	}
	changes := &rules.RuleChangeSet{SEID: s.LocalID}
	if err := appendRuleChanges(
		&changes.CreateFARs,
		"CreateFAR",
		req.CreateFAR,
		parseCreateFAR,
		ErrMissingMandatoryIE,
	); err != nil {
		return nil, err
	}
	if err := appendRuleChanges(
		&changes.CreateQERs,
		"CreateQER",
		req.CreateQER,
		parseCreateQER,
		ErrMissingMandatoryIE,
	); err != nil {
		return nil, err
	}
	if err := appendRuleChanges(
		&changes.CreateURRs,
		"CreateURR",
		req.CreateURR,
		parseCreateURR,
		ErrMissingMandatoryIE,
	); err != nil {
		return nil, err
	}
	if req.CreateBAR != nil {
		if err := appendRuleChanges(
			&changes.CreateBARs,
			"CreateBAR",
			[]*ie.IE{req.CreateBAR},
			parseCreateBAR,
			ErrMissingMandatoryIE,
		); err != nil {
			return nil, err
		}
	}
	if err := appendRuleChanges(
		&changes.CreatePDRs,
		"CreatePDR",
		req.CreatePDR,
		parseCreatePDR,
		ErrRuleCreationModificationFailed,
	); err != nil {
		return nil, err
	}
	return changes, nil
}

// BuildModificationPlan decodes all supported rule operations without a driver,
// netlink encoding, or mutation of Session. The result owns its decoded values.
func (s *Session) BuildModificationPlan(req *message.SessionModificationRequest) (*rules.RuleChangeSet, error) {
	if req == nil {
		return nil, errors.Wrap(ErrMissingMandatoryIE, "nil SessionModificationRequest")
	}
	changes := &rules.RuleChangeSet{SEID: s.LocalID}
	if err := appendRuleChanges(
		&changes.CreateFARs,
		"CreateFAR",
		req.CreateFAR,
		parseCreateFAR,
		ErrMissingMandatoryIE,
	); err != nil {
		return nil, err
	}
	if err := appendRuleChanges(
		&changes.CreateQERs,
		"CreateQER",
		req.CreateQER,
		parseCreateQER,
		ErrMissingMandatoryIE,
	); err != nil {
		return nil, err
	}
	if err := appendRuleChanges(
		&changes.CreateURRs,
		"CreateURR",
		req.CreateURR,
		parseCreateURR,
		ErrMissingMandatoryIE,
	); err != nil {
		return nil, err
	}
	if req.CreateBAR != nil {
		if err := appendRuleChanges(
			&changes.CreateBARs,
			"CreateBAR",
			[]*ie.IE{req.CreateBAR},
			parseCreateBAR,
			ErrMissingMandatoryIE,
		); err != nil {
			return nil, err
		}
	}
	if err := appendRuleChanges(
		&changes.CreatePDRs,
		"CreatePDR",
		req.CreatePDR,
		parseCreatePDR,
		ErrRuleCreationModificationFailed,
	); err != nil {
		return nil, err
	}
	if err := appendRuleChanges(
		&changes.UpdateFARs,
		"UpdateFAR",
		req.UpdateFAR,
		parseUpdateFAR,
		ErrMissingMandatoryIE,
	); err != nil {
		return nil, err
	}
	if err := appendRuleChanges(
		&changes.UpdateQERs,
		"UpdateQER",
		req.UpdateQER,
		parseUpdateQER,
		ErrMissingMandatoryIE,
	); err != nil {
		return nil, err
	}
	if err := appendRuleChanges(
		&changes.UpdateURRs,
		"UpdateURR",
		req.UpdateURR,
		parseUpdateURR,
		ErrMissingMandatoryIE,
	); err != nil {
		return nil, err
	}
	if req.UpdateBAR != nil {
		if err := appendRuleChanges(
			&changes.UpdateBARs,
			"UpdateBAR",
			[]*ie.IE{req.UpdateBAR},
			parseUpdateBAR,
			ErrMissingMandatoryIE,
		); err != nil {
			return nil, err
		}
	}
	if err := appendRuleChanges(
		&changes.UpdatePDRs,
		"UpdatePDR",
		req.UpdatePDR,
		parseUpdatePDR,
		ErrMissingMandatoryIE,
	); err != nil {
		return nil, err
	}
	if err := appendRuleChanges(
		&changes.QueryURRs,
		"QueryURR",
		req.QueryURR,
		func(i *ie.IE) (uint32, error) { return parseRuleID(i, ie.QueryURR, (*ie.IE).URRID) },
		ErrMissingMandatoryIE,
	); err != nil {
		return nil, err
	}
	if err := appendRuleChanges(
		&changes.RemoveFARs,
		"RemoveFAR",
		req.RemoveFAR,
		func(i *ie.IE) (uint32, error) { return parseRuleID(i, ie.RemoveFAR, (*ie.IE).FARID) },
		ErrMissingMandatoryIE,
	); err != nil {
		return nil, err
	}
	if err := appendRuleChanges(
		&changes.RemoveQERs,
		"RemoveQER",
		req.RemoveQER,
		func(i *ie.IE) (uint32, error) { return parseRuleID(i, ie.RemoveQER, (*ie.IE).QERID) },
		ErrMissingMandatoryIE,
	); err != nil {
		return nil, err
	}
	if err := appendRuleChanges(
		&changes.RemoveURRs,
		"RemoveURR",
		req.RemoveURR,
		func(i *ie.IE) (uint32, error) { return parseRuleID(i, ie.RemoveURR, (*ie.IE).URRID) },
		ErrMissingMandatoryIE,
	); err != nil {
		return nil, err
	}
	if req.RemoveBAR != nil {
		if err := appendRuleChanges(
			&changes.RemoveBARs,
			"RemoveBAR",
			[]*ie.IE{req.RemoveBAR},
			func(i *ie.IE) (uint8, error) { return parseRuleID(i, ie.RemoveBAR, (*ie.IE).BARID) },
			ErrMissingMandatoryIE,
		); err != nil {
			return nil, err
		}
	}
	if err := appendRuleChanges(
		&changes.RemovePDRs,
		"RemovePDR",
		req.RemovePDR,
		func(i *ie.IE) (uint16, error) { return parseRuleID(i, ie.RemovePDR, (*ie.IE).PDRID) },
		ErrMissingMandatoryIE,
	); err != nil {
		return nil, err
	}
	return changes, nil
}
