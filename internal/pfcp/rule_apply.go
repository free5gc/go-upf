package pfcp

import (
	"fmt"

	"github.com/free5gc/go-upf/internal/forwarder"
	"github.com/free5gc/go-upf/internal/report"
	"github.com/free5gc/go-upf/internal/rules"
)

// applyRuleChanges coordinates one complete rule transaction. The PFCP event
// loop owns Session: request validation, execution, publication and response
// assembly run synchronously before the next request/report/timeout is handled.
// Do not invoke this method concurrently with Session reads or writes.
func (s *Session) applyRuleChanges(changes *rules.RuleChangeSet, establish bool) ([]report.USAReport, error) {
	state, err := s.ValidateRuleState(changes)
	if err != nil {
		return nil, err
	}
	terminalIDs := state.terminalURRIDs()
	terminal := uint32Set(terminalIDs)
	removed := uint32Set(changes.RemoveURRs)
	explicitQueries := uint32Set(changes.QueryURRs)
	// Own the augmented query slice, leaving the parsed request unchanged.
	execution := *changes
	execution.QueryURRs = append([]uint32(nil), changes.QueryURRs...)
	for _, id := range terminalIDs {
		if _, deleting := removed[id]; deleting {
			continue
		}
		if _, queried := explicitQueries[id]; queried {
			continue
		}
		execution.QueryURRs = append(execution.QueryURRs, id)
	}
	var result *forwarder.ApplyResult
	if establish {
		result, err = s.datapath.Establish(&execution)
	} else {
		result, err = s.datapath.Modify(&execution)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: datapath execution: %w", ErrRuleCreationModificationFailed, err)
	}
	// Every required query is part of execution. A query error therefore reaches
	// the normal rollback path, before any Session state is published.
	state.Commit()
	if result == nil {
		return nil, nil
	}
	reports := append([]report.USAReport(nil), result.USAReports...)
	for i := range reports {
		id := reports[i].URRID
		_, lastReference := terminal[id]
		_, deleted := removed[id]
		if lastReference || deleted {
			reports[i].USARTrigger.Flags |= report.USAR_TRIG_TERMR
		}
		if _, requested := explicitQueries[id]; requested {
			reports[i].USARTrigger.Flags |= report.USAR_TRIG_IMMER
		}
	}
	return reports, nil
}

// Commit publishes the validated candidate after successful execution. It only
// changes memory: no parsing, patch merging, datapath calls or report generation.
func (state *RuleState) Commit() {
	s := state.sess
	for id, c := range state.farOverrides {
		n := c.Clone()
		s.FARIDs[id] = &n
	}
	for id, c := range state.qerOverrides {
		n := c.Clone()
		s.QERIDs[id] = &n
	}
	for id, c := range state.barOverrides {
		n := c.Clone()
		s.BARIDs[id] = &n
	}
	for id, c := range state.urrOverrides {
		info := s.URRIDs[id]
		if info == nil {
			info = &URRInfo{}
			s.URRIDs[id] = info
		}
		info.Config = c.Clone()
	}
	for id, delta := range state.urrRefDeltas {
		if info := s.URRIDs[id]; info != nil {
			info.refPdrNum = uint16(int(info.refPdrNum) + delta)
		}
	}
	for id, c := range state.pdrOverrides {
		n := c.Clone()
		s.PDRIDs[id] = &n
	}
	for id := range state.removedPDRs {
		delete(s.PDRIDs, id)
	}
	for id := range state.removedFARs {
		s.ApplyRemoveFAR(id)
	}
	for id := range state.removedQERs {
		s.ApplyRemoveQER(id)
	}
	for id := range state.removedURRs {
		s.ApplyRemoveURR(id)
	}
	for id := range state.removedBARs {
		s.ApplyRemoveBAR(id)
	}
}

// ApplyRemovePDR updates only local relationships during session cleanup.
// Final usage reports come from the datapath's RemoveURR operations.
func (s *Session) ApplyRemovePDR(id uint16) {
	if c := s.PDRIDs[id]; c != nil {
		for uid := range uint32Set(c.URRIDs) {
			if info := s.URRIDs[uid]; info != nil && info.refPdrNum > 0 {
				info.refPdrNum--
			}
		}
	}
	delete(s.PDRIDs, id)
}

func (s *Session) ApplyRemoveFAR(id uint32) { delete(s.FARIDs, id) }
func (s *Session) ApplyRemoveQER(id uint32) { delete(s.QERIDs, id) }

// Retain removed URR configuration/runtime until response reports are assembled.
func (s *Session) ApplyRemoveURR(id uint32) {
	if info := s.URRIDs[id]; info != nil {
		info.removed = true
	}
}
func (s *Session) ApplyRemoveBAR(id uint8) { delete(s.BARIDs, id) }
func (s *Session) CleanupRemovedURRs() {
	for id, info := range s.URRIDs {
		if info.removed {
			delete(s.URRIDs, id)
		}
	}
}
