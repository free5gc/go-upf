package pfcp

import (
	"github.com/wmnsk/go-pfcp/ie"

	"github.com/free5gc/go-upf/internal/forwarder"
	"github.com/free5gc/go-upf/internal/report"
)

// Close removes every session rule from the datapath on a best-effort basis,
// updates the local rule state, and closes the session packet queues.
func (s *Session) Close() []report.USAReport {
	plan := forwarder.NewModificationPlan(s.LocalID)

	// Build Remove plans for all rules
	for id := range s.FARIDs {
		req := ie.NewRemoveFAR(ie.NewFARID(id))
		p, err := s.driver.BuildRemoveFARPlan(s.LocalID, req)
		if err != nil {
			s.log.Errorf("Close BuildRemoveFARPlan[%#x] err: %v", id, err)
			continue
		}
		plan.RemoveFARs = append(plan.RemoveFARs, p)
	}
	for id := range s.QERIDs {
		req := ie.NewRemoveQER(ie.NewQERID(id))
		p, err := s.driver.BuildRemoveQERPlan(s.LocalID, req)
		if err != nil {
			s.log.Errorf("Close BuildRemoveQERPlan[%#x] err: %v", id, err)
			continue
		}
		plan.RemoveQERs = append(plan.RemoveQERs, p)
	}
	for id := range s.URRIDs {
		req := ie.NewRemoveURR(ie.NewURRID(id))
		p, err := s.driver.BuildRemoveURRPlan(s.LocalID, req)
		if err != nil {
			s.log.Errorf("Close BuildRemoveURRPlan[%#x] err: %v", id, err)
			continue
		}
		plan.RemoveURRs = append(plan.RemoveURRs, p)
	}
	for id := range s.BARIDs {
		req := ie.NewRemoveBAR(ie.NewBARID(id))
		p, err := s.driver.BuildRemoveBARPlan(s.LocalID, req)
		if err != nil {
			s.log.Errorf("Close BuildRemoveBARPlan[%#x] err: %v", id, err)
			continue
		}
		plan.RemoveBARs = append(plan.RemoveBARs, p)
	}
	for id := range s.PDRIDs {
		req := ie.NewRemovePDR(ie.NewPDRID(id))
		p, err := s.driver.BuildRemovePDRPlan(s.LocalID, req)
		if err != nil {
			s.log.Errorf("Close BuildRemovePDRPlan[%#x] err: %v", id, err)
			continue
		}
		plan.RemovePDRs = append(plan.RemovePDRs, p)
	}

	// Execute all Remove operations (best-effort)
	execResult, err := s.driver.ExecuteModificationPlan(plan)
	if err != nil {
		s.log.Errorf("Execute Deletion Plan err: %v", err)
	}

	// Apply state changes and collect USAReports
	var usars []report.USAReport

	for _, p := range plan.RemovePDRs {
		rs := s.ApplyRemovePDR(p)
		if len(rs) > 0 {
			usars = append(usars, rs...)
		}
	}
	for _, p := range plan.RemoveBARs {
		s.ApplyRemoveBAR(p)
	}
	for _, p := range plan.RemoveURRs {
		s.ApplyRemoveURR(p)
	}
	for _, p := range plan.RemoveQERs {
		s.ApplyRemoveQER(p)
	}
	for _, p := range plan.RemoveFARs {
		s.ApplyRemoveFAR(p)
	}

	// Collect USAReports from execution result (RemoveURR)
	if execResult != nil && len(execResult.USAReports) > 0 {
		for i := range execResult.USAReports {
			execResult.USAReports[i].USARTrigger.Flags |= report.USAR_TRIG_TERMR
		}
		usars = append(usars, execResult.USAReports...)
	}

	for _, q := range s.q {
		close(q)
	}
	return usars
}
