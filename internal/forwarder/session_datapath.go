package forwarder

import (
	"github.com/pkg/errors"

	"github.com/free5gc/go-upf/internal/report"
)

// SessionDatapath is a datapath handle owned by one PFCP session. It shares the driver's
// clients and services; creating or cleaning up a SessionDatapath never closes the driver.
// Plans and rollback metadata retain their existing representation for now.
type SessionDatapath interface {
	QueryURR(urrID uint32) ([]report.USAReport, error)
	ExecuteEstablishmentPlan(*ModificationPlan) (*ExecutionResult, error)
	// ExecuteModificationPlan also executes the owner's removal plan during
	// cleanup. A nil Rollback retains the existing best-effort cleanup behavior.
	ExecuteModificationPlan(*ModificationPlan) (*ExecutionResult, error)
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
}

// NewSessionDatapath binds a handle to an already allocated Local SEID. It performs no
// datapath I/O and allocates no sockets or background services. The owner remains
// responsible for submitting its cleanup plan before releasing the handle.
func NewSessionDatapath(driver Driver, localSEID uint64) SessionDatapath {
	return &sessionDatapath{localSEID: localSEID, backend: driver}
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
	return s.backend.ExecuteEstablishmentPlan(plan)
}

func (s *sessionDatapath) ExecuteModificationPlan(plan *ModificationPlan) (*ExecutionResult, error) {
	if err := s.validatePlan(plan); err != nil {
		return nil, err
	}
	return s.backend.ExecuteModificationPlan(plan)
}
