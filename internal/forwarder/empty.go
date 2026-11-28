package forwarder

import (
	"github.com/free5gc/go-upf/internal/report"
)

type Empty struct{}

func (Empty) Close() {
}

func (Empty) QueryURR(uint64, uint32) ([]report.USAReport, error) {
	return nil, nil
}

func (Empty) HandleReport(report.Handler) {
}

// Plan-based methods for two-phase commit

func (Empty) executeModificationPlan(plan *modificationPlan) (*executionResult, error) {
	return newSuccessfulExecutionResult(plan), nil
}

func (Empty) executeEstablishmentPlan(plan *modificationPlan) (*executionResult, error) {
	return newSuccessfulExecutionResult(plan), nil
}
