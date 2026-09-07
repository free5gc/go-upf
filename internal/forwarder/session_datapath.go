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
	CompileChanges(*rules.RuleChangeSet) (*ModificationPlan, error)
	QueryURR(urrID uint32) ([]report.USAReport, error)
	ExecuteEstablishmentPlan(*ModificationPlan) (*ExecutionResult, error)
	// ExecuteModificationPlan always prepares rollback from owned snapshots.
	ExecuteModificationPlan(*ModificationPlan) (*ExecutionResult, error)
	// ExecuteDeletionPlan keeps best-effort cleanup separate from transactions.
	ExecuteDeletionPlan(*ModificationPlan) (*ExecutionResult, error)
}

// sessionBackend deliberately excludes driver shutdown and plan construction.
type sessionBackend interface {
	QueryURR(uint64, uint32) ([]report.USAReport, error)
	ExecuteEstablishmentPlan(*ModificationPlan) (*ExecutionResult, error)
	ExecuteModificationPlan(*ModificationPlan) (*ExecutionResult, error)
}

type sessionDatapath struct {
	localSEID uint64
	backend   sessionBackend
	applied   appliedRules
}

// NewSessionDatapath binds a handle to an already allocated Local SEID. It performs no
// datapath I/O and allocates no sockets or background services. The owner remains
// responsible for submitting its cleanup plan before releasing the handle.
func NewSessionDatapath(driver Driver, localSEID uint64) SessionDatapath {
	return &sessionDatapath{localSEID: localSEID, backend: driver, applied: newAppliedRules()}
}

func (s *sessionDatapath) QueryURR(urrID uint32) ([]report.USAReport, error) {
	return s.backend.QueryURR(s.localSEID, urrID)
}

func (s *sessionDatapath) validatePlan(plan *ModificationPlan) error {
	if plan == nil {
		return errors.New("datapath session: nil plan")
	}
	if plan.SEID != s.localSEID {
		return errors.Errorf("datapath session: plan SEID %#x does not match owner %#x", plan.SEID, s.localSEID)
	}
	return nil
}

func (s *sessionDatapath) ExecuteEstablishmentPlan(plan *ModificationPlan) (*ExecutionResult, error) {
	if err := s.validatePlan(plan); err != nil {
		return nil, err
	}
	// Ignore caller-supplied rollback metadata; only this handle owns snapshots.
	execution := *plan
	execution.Rollback = NewRollbackPlan()
	result, err := s.backend.ExecuteEstablishmentPlan(&execution)
	if err == nil {
		s.publish(result)
	}
	return result, err
}

func (s *sessionDatapath) ExecuteModificationPlan(plan *ModificationPlan) (*ExecutionResult, error) {
	if err := s.validatePlan(plan); err != nil {
		return nil, err
	}
	before, err := s.buildRollbackPlan(plan)
	if err != nil {
		return nil, err
	}
	execution := *plan
	execution.Rollback = before
	result, err := s.backend.ExecuteModificationPlan(&execution)
	// The existing executor compensates failures before returning. Accounting
	// restoration and rollback-failure reconciliation remain documented limitations.
	if err == nil {
		s.publish(result)
	}
	return result, err
}

// ExecuteDeletionPlan does not close shared driver resources. Only successful
// removals are forgotten, so failed removals retain their applied snapshots.
func (s *sessionDatapath) ExecuteDeletionPlan(plan *ModificationPlan) (*ExecutionResult, error) {
	if err := s.validatePlan(plan); err != nil {
		return nil, err
	}
	if len(plan.CreatePDRs)+len(plan.CreateFARs)+len(plan.CreateQERs)+len(plan.CreateURRs)+len(plan.CreateBARs)+
		len(plan.UpdatePDRs)+len(plan.UpdateFARs)+len(plan.UpdateQERs)+len(plan.UpdateURRs)+len(plan.UpdateBARs)+len(plan.QueryURRs) != 0 {
		return nil, errors.New("datapath cleanup: expected a removal-only plan")
	}
	execution := *plan
	execution.Rollback = nil
	result, err := s.backend.ExecuteModificationPlan(&execution)
	s.publish(result)
	return result, err
}
