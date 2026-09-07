package forwarder

import (
	"github.com/pkg/errors"

	"github.com/free5gc/go-upf/internal/report"
	"github.com/free5gc/go-upf/internal/rules"
)

// SessionDatapath is a datapath handle owned by one PFCP session. It shares the driver's
// clients and services; creating or cleaning up a SessionDatapath never closes the driver.
// Applied attributes and rollback snapshots remain private to the handle.
type SessionDatapath interface {
	Establish(*rules.RuleChangeSet) (*ApplyResult, error)
	Modify(*rules.RuleChangeSet) (*ApplyResult, error)
	Cleanup(*rules.RuleChangeSet) (*ApplyResult, error)
	QueryURR(uint32) ([]report.USAReport, error)
}

// ApplyResult contains protocol-neutral output. Failed transactions return no
// result, since their operations were subject to rollback. Cleanup may return
// both a result and an error; Removed then lists only confirmed deletions.
type ApplyResult struct {
	USAReports []report.USAReport
	Removed    RemovedRules
}
type RemovedRules struct {
	PDRs []uint16
	FARs []uint32
	QERs []uint32
	URRs []uint32
	BARs []uint8
}

// sessionBackend deliberately excludes driver shutdown and plan construction.
type sessionBackend interface {
	QueryURR(uint64, uint32) ([]report.USAReport, error)
	executeEstablishmentPlan(*modificationPlan) (*executionResult, error)
	executeModificationPlan(*modificationPlan) (*executionResult, error)
}

type sessionDatapath struct {
	localSEID uint64
	backend   sessionBackend
	applied   appliedRules
}

// NewSessionDatapath binds a handle to an already allocated Local SEID. It performs no
// datapath I/O and allocates no sockets or background services. The owner remains
// responsible for submitting cleanup changes before releasing the handle.
func NewSessionDatapath(driver Driver, localSEID uint64) SessionDatapath {
	return &sessionDatapath{localSEID: localSEID, backend: driver, applied: newAppliedRules()}
}

func (s *sessionDatapath) QueryURR(urrID uint32) ([]report.USAReport, error) {
	return s.backend.QueryURR(s.localSEID, urrID)
}

func (s *sessionDatapath) validatePlan(plan *modificationPlan) error {
	if plan == nil {
		return errors.New("datapath session: nil plan")
	}
	if plan.SEID != s.localSEID {
		return errors.Errorf("datapath session: plan SEID %#x does not match owner %#x", plan.SEID, s.localSEID)
	}
	return nil
}

func (s *sessionDatapath) executeEstablishmentPlan(plan *modificationPlan) (*executionResult, error) {
	if err := s.validatePlan(plan); err != nil {
		return nil, err
	}
	// Ignore caller-supplied rollback metadata; only this handle owns snapshots.
	execution := *plan
	execution.Rollback = newRollbackPlan()
	result, err := s.backend.executeEstablishmentPlan(&execution)
	if err == nil {
		s.publish(result)
	}
	return result, err
}

func (s *sessionDatapath) executeModificationPlan(plan *modificationPlan) (*executionResult, error) {
	if err := s.validatePlan(plan); err != nil {
		return nil, err
	}
	before, err := s.buildRollbackPlan(plan)
	if err != nil {
		return nil, err
	}
	execution := *plan
	execution.Rollback = before
	result, err := s.backend.executeModificationPlan(&execution)
	// The existing executor compensates failures before returning. Accounting
	// restoration and rollback-failure reconciliation remain documented limitations.
	if err == nil {
		s.publish(result)
	}
	return result, err
}

// executeDeletionPlan does not close shared driver resources. Only successful
// removals are forgotten, so failed removals retain their applied snapshots.
func (s *sessionDatapath) executeDeletionPlan(plan *modificationPlan) (*executionResult, error) {
	if err := s.validatePlan(plan); err != nil {
		return nil, err
	}
	if len(plan.CreatePDRs)+len(plan.CreateFARs)+len(plan.CreateQERs)+len(plan.CreateURRs)+len(plan.CreateBARs)+
		len(plan.UpdatePDRs)+len(plan.UpdateFARs)+len(plan.UpdateQERs)+len(plan.UpdateURRs)+len(plan.UpdateBARs)+len(plan.QueryURRs) != 0 {
		return nil, errors.New("datapath cleanup: expected a removal-only plan")
	}
	execution := *plan
	execution.Rollback = nil
	result, err := s.backend.executeModificationPlan(&execution)
	s.publish(result)
	return result, err
}

func (s *sessionDatapath) Establish(changes *rules.RuleChangeSet) (*ApplyResult, error) {
	plan, err := s.compileChanges(changes)
	if err != nil {
		return nil, err
	}
	if len(plan.UpdatePDRs)+len(plan.UpdateFARs)+len(plan.UpdateQERs)+len(plan.UpdateURRs)+len(plan.UpdateBARs)+
		len(plan.RemovePDRs)+len(plan.RemoveFARs)+len(plan.RemoveQERs)+len(plan.RemoveURRs)+len(plan.RemoveBARs)+len(plan.QueryURRs) != 0 {
		return nil, errors.New("datapath establishment: expected create-only changes")
	}
	result, err := s.executeEstablishmentPlan(plan)
	if err != nil {
		return nil, err
	}
	return publicResult(result), nil
}
func (s *sessionDatapath) Modify(changes *rules.RuleChangeSet) (*ApplyResult, error) {
	plan, err := s.compileChanges(changes)
	if err != nil {
		return nil, err
	}
	result, err := s.executeModificationPlan(plan)
	if err != nil {
		return nil, err
	}
	return publicResult(result), nil
}
func (s *sessionDatapath) Cleanup(changes *rules.RuleChangeSet) (*ApplyResult, error) {
	plan, err := s.compileChanges(changes)
	if err != nil {
		return nil, err
	}
	result, err := s.executeDeletionPlan(plan)
	return publicResult(result), err
}
func publicResult(result *executionResult) *ApplyResult {
	if result == nil {
		return nil
	}
	out := &ApplyResult{USAReports: append([]report.USAReport(nil), result.USAReports...)}
	if result.AppliedPlan == nil {
		return out
	}
	for _, p := range result.AppliedPlan.RemovePDRs {
		out.Removed.PDRs = append(out.Removed.PDRs, p.PDRID)
	}
	for _, p := range result.AppliedPlan.RemoveFARs {
		out.Removed.FARs = append(out.Removed.FARs, p.FARID)
	}
	for _, p := range result.AppliedPlan.RemoveQERs {
		out.Removed.QERs = append(out.Removed.QERs, p.QERID)
	}
	for _, p := range result.AppliedPlan.RemoveURRs {
		out.Removed.URRs = append(out.Removed.URRs, p.URRID)
	}
	for _, p := range result.AppliedPlan.RemoveBARs {
		out.Removed.BARs = append(out.Removed.BARs, p.BARID)
	}
	return out
}
