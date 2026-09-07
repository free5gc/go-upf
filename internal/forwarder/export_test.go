package forwarder

import (
	"github.com/wmnsk/go-pfcp/message"
)

// Test-only access keeps parity coverage without exposing plans in production.
var CompileRuleChangesForTest = compileRuleChanges

func LegacyRuleChangesForTest(seid uint64, req *message.SessionModificationRequest) (*modificationPlan, error) {
	g := new(Gtp5g)
	plan := newModificationPlan(seid)
	for _, i := range req.CreatePDR {
		p, err := g.buildCreatePDRPlan(seid, i)
		if err != nil {
			return nil, err
		}
		plan.CreatePDRs = append(plan.CreatePDRs, p)
	}
	for _, i := range req.CreateFAR {
		p, err := g.buildCreateFARPlan(seid, i)
		if err != nil {
			return nil, err
		}
		plan.CreateFARs = append(plan.CreateFARs, p)
	}
	for _, i := range req.CreateQER {
		p, err := g.buildCreateQERPlan(seid, i)
		if err != nil {
			return nil, err
		}
		plan.CreateQERs = append(plan.CreateQERs, p)
	}
	for _, i := range req.CreateURR {
		p, err := g.buildCreateURRPlan(seid, i)
		if err != nil {
			return nil, err
		}
		plan.CreateURRs = append(plan.CreateURRs, p)
	}
	if req.CreateBAR != nil {
		p, err := g.buildCreateBARPlan(seid, req.CreateBAR)
		if err != nil {
			return nil, err
		}
		plan.CreateBARs = append(plan.CreateBARs, p)
	}
	for _, i := range req.UpdatePDR {
		p, err := g.buildUpdatePDRPlan(seid, i)
		if err != nil {
			return nil, err
		}
		plan.UpdatePDRs = append(plan.UpdatePDRs, p)
	}
	for _, i := range req.UpdateFAR {
		p, err := g.buildUpdateFARPlan(seid, i)
		if err != nil {
			return nil, err
		}
		plan.UpdateFARs = append(plan.UpdateFARs, p)
	}
	for _, i := range req.UpdateQER {
		p, err := g.buildUpdateQERPlan(seid, i)
		if err != nil {
			return nil, err
		}
		plan.UpdateQERs = append(plan.UpdateQERs, p)
	}
	for _, i := range req.UpdateURR {
		p, err := g.buildUpdateURRPlan(seid, i)
		if err != nil {
			return nil, err
		}
		plan.UpdateURRs = append(plan.UpdateURRs, p)
	}
	if req.UpdateBAR != nil {
		p, err := g.buildUpdateBARPlan(seid, req.UpdateBAR)
		if err != nil {
			return nil, err
		}
		plan.UpdateBARs = append(plan.UpdateBARs, p)
	}
	for _, i := range req.RemovePDR {
		p, err := g.buildRemovePDRPlan(seid, i)
		if err != nil {
			return nil, err
		}
		plan.RemovePDRs = append(plan.RemovePDRs, p)
	}
	for _, i := range req.RemoveFAR {
		p, err := g.buildRemoveFARPlan(seid, i)
		if err != nil {
			return nil, err
		}
		plan.RemoveFARs = append(plan.RemoveFARs, p)
	}
	for _, i := range req.RemoveQER {
		p, err := g.buildRemoveQERPlan(seid, i)
		if err != nil {
			return nil, err
		}
		plan.RemoveQERs = append(plan.RemoveQERs, p)
	}
	for _, i := range req.RemoveURR {
		p, err := g.buildRemoveURRPlan(seid, i)
		if err != nil {
			return nil, err
		}
		plan.RemoveURRs = append(plan.RemoveURRs, p)
	}
	if req.RemoveBAR != nil {
		p, err := g.buildRemoveBARPlan(seid, req.RemoveBAR)
		if err != nil {
			return nil, err
		}
		plan.RemoveBARs = append(plan.RemoveBARs, p)
	}
	for _, i := range req.QueryURR {
		p, err := g.buildQueryURRPlan(seid, i)
		if err != nil {
			return nil, err
		}
		plan.QueryURRs = append(plan.QueryURRs, p)
	}
	return plan, nil
}
