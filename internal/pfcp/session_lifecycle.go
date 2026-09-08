package pfcp

import (
	"github.com/free5gc/go-upf/internal/report"
	"github.com/free5gc/go-upf/internal/rules"
)

// Close removes every session rule from the datapath on a best-effort basis,
// updates the local rule state, and closes the session packet queues.
func (s *Session) Close() []report.USAReport {
	changes := &rules.RuleChangeSet{SEID: s.LocalID}
	for id := range s.PDRIDs {
		changes.RemovePDRs = append(changes.RemovePDRs, id)
	}
	for id := range s.FARIDs {
		changes.RemoveFARs = append(changes.RemoveFARs, id)
	}
	for id := range s.QERIDs {
		changes.RemoveQERs = append(changes.RemoveQERs, id)
	}
	for id := range s.URRIDs {
		changes.RemoveURRs = append(changes.RemoveURRs, id)
	}
	for id := range s.BARIDs {
		changes.RemoveBARs = append(changes.RemoveBARs, id)
	}
	// Execute all Remove operations (best-effort)
	execResult, err := s.datapath.Cleanup(changes)
	if err != nil {
		s.log.Errorf("Execute Deletion Plan err: %v", err)
	}

	// Apply state changes and collect USAReports
	var usars []report.USAReport

	for _, p := range changes.RemovePDRs {
		s.ApplyRemovePDR(p)
	}
	for _, p := range changes.RemoveBARs {
		s.ApplyRemoveBAR(p)
	}
	for _, p := range changes.RemoveURRs {
		s.ApplyRemoveURR(p)
	}
	for _, p := range changes.RemoveQERs {
		s.ApplyRemoveQER(p)
	}
	for _, p := range changes.RemoveFARs {
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
