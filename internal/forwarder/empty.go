package forwarder

import (
	"github.com/wmnsk/go-pfcp/ie"

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

func (Empty) buildCreatePDRPlan(lSeid uint64, req *ie.IE) (*pdrPlan, error) {
	return &pdrPlan{}, nil
}

func (Empty) buildUpdatePDRPlan(lSeid uint64, req *ie.IE) (*pdrPlan, error) {
	return &pdrPlan{}, nil
}

func (Empty) buildRemovePDRPlan(lSeid uint64, req *ie.IE) (*pdrPlan, error) {
	return &pdrPlan{}, nil
}

func (Empty) buildCreateFARPlan(lSeid uint64, req *ie.IE) (*farPlan, error) {
	return &farPlan{}, nil
}

func (Empty) buildUpdateFARPlan(lSeid uint64, req *ie.IE) (*farPlan, error) {
	return &farPlan{}, nil
}

func (Empty) buildRemoveFARPlan(lSeid uint64, req *ie.IE) (*farPlan, error) {
	return &farPlan{}, nil
}

func (Empty) buildCreateQERPlan(lSeid uint64, req *ie.IE) (*qerPlan, error) {
	return &qerPlan{}, nil
}

func (Empty) buildUpdateQERPlan(lSeid uint64, req *ie.IE) (*qerPlan, error) {
	return &qerPlan{}, nil
}

func (Empty) buildRemoveQERPlan(lSeid uint64, req *ie.IE) (*qerPlan, error) {
	return &qerPlan{}, nil
}

func (Empty) buildCreateURRPlan(lSeid uint64, req *ie.IE) (*urrPlan, error) {
	return &urrPlan{}, nil
}

func (Empty) buildUpdateURRPlan(lSeid uint64, req *ie.IE) (*urrPlan, error) {
	return &urrPlan{}, nil
}

func (Empty) buildRemoveURRPlan(lSeid uint64, req *ie.IE) (*urrPlan, error) {
	return &urrPlan{}, nil
}

func (Empty) buildQueryURRPlan(lSeid uint64, req *ie.IE) (*urrPlan, error) {
	return &urrPlan{}, nil
}

func (Empty) buildCreateBARPlan(lSeid uint64, req *ie.IE) (*barPlan, error) {
	return &barPlan{}, nil
}

func (Empty) buildUpdateBARPlan(lSeid uint64, req *ie.IE) (*barPlan, error) {
	return &barPlan{}, nil
}

func (Empty) buildRemoveBARPlan(lSeid uint64, req *ie.IE) (*barPlan, error) {
	return &barPlan{}, nil
}

func (Empty) executeModificationPlan(plan *modificationPlan) (*executionResult, error) {
	return newSuccessfulExecutionResult(plan), nil
}

func (Empty) executeEstablishmentPlan(plan *modificationPlan) (*executionResult, error) {
	return newSuccessfulExecutionResult(plan), nil
}
