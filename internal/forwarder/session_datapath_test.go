package forwarder

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/free5gc/go-upf/internal/report"
)

type sessionDatapathTestDriver struct {
	Empty
	calls        int
	closed       bool
	lastPlan     *ModificationPlan
	queriedSEID  uint64
	queriedURRID uint32
	result       *ExecutionResult
	reports      []report.USAReport
	err          error
}

func (d *sessionDatapathTestDriver) Close() { d.closed = true }
func (d *sessionDatapathTestDriver) QueryURR(seid uint64, id uint32) ([]report.USAReport, error) {
	d.calls++
	d.queriedSEID, d.queriedURRID = seid, id
	return d.reports, d.err
}
func (d *sessionDatapathTestDriver) ExecuteEstablishmentPlan(plan *ModificationPlan) (*ExecutionResult, error) {
	d.calls++
	d.lastPlan = plan
	return d.result, d.err
}
func (d *sessionDatapathTestDriver) ExecuteModificationPlan(plan *ModificationPlan) (*ExecutionResult, error) {
	d.calls++
	d.lastPlan = plan
	return d.result, d.err
}

func TestSessionDatapathRejectsInvalidPlansBeforeExecution(t *testing.T) {
	d := &sessionDatapathTestDriver{}
	s := NewSessionDatapath(d, 42)
	for name, execute := range map[string]func(*ModificationPlan) (*ExecutionResult, error){
		"establishment": s.ExecuteEstablishmentPlan,
		"modification":  s.ExecuteModificationPlan,
	} {
		t.Run(name, func(t *testing.T) {
			for _, plan := range []*ModificationPlan{nil, NewModificationPlan(43)} {
				result, err := execute(plan)
				require.Error(t, err)
				require.Nil(t, result)
			}
		})
	}
	require.Zero(t, d.calls)
}

func TestSessionDatapathPreservesExecutionResultsAndErrors(t *testing.T) {
	d := &sessionDatapathTestDriver{result: NewExecutionResult(42), err: errors.New("execution failed")}
	s := NewSessionDatapath(d, 42)
	plan := NewModificationPlan(42)
	plan.Rollback = NewRollbackPlan()
	for name, execute := range map[string]func(*ModificationPlan) (*ExecutionResult, error){
		"establishment": s.ExecuteEstablishmentPlan,
		"modification":  s.ExecuteModificationPlan,
	} {
		t.Run(name, func(t *testing.T) {
			result, err := execute(plan)
			require.Same(t, plan, d.lastPlan)
			require.Same(t, d.result, result)
			require.ErrorIs(t, err, d.err)
			require.NotNil(t, plan.Rollback)
		})
	}
}

func TestSessionDatapathCleanupKeepsSharedDriverAvailable(t *testing.T) {
	d := &sessionDatapathTestDriver{reports: []report.USAReport{{URRID: 7}}}
	first, second := NewSessionDatapath(d, 41), NewSessionDatapath(d, 42)
	require.Zero(t, d.calls, "creating handles must not perform datapath I/O")

	reports, err := first.QueryURR(7)
	require.NoError(t, err)
	require.Equal(t, d.reports, reports)
	require.Equal(t, uint64(41), d.queriedSEID)
	require.Equal(t, uint32(7), d.queriedURRID)

	cleanup := NewModificationPlan(41)
	cleanup.RemoveURRs = []*URRPlan{{URRID: 7}}
	_, err = first.ExecuteModificationPlan(cleanup)
	require.NoError(t, err)
	require.Same(t, cleanup, d.lastPlan)
	require.Nil(t, d.lastPlan.Rollback, "cleanup must keep its existing best-effort semantics")
	require.False(t, d.closed)

	d.err = errors.New("query failed")
	reports, err = second.QueryURR(8)
	require.ErrorIs(t, err, d.err)
	require.Equal(t, d.reports, reports)
	require.Equal(t, uint64(42), d.queriedSEID)
	require.Equal(t, uint32(8), d.queriedURRID)
	require.False(t, d.closed)
}

func TestEmptySessionDatapath(t *testing.T) {
	s := NewSessionDatapath(Empty{}, 42)
	plan := NewModificationPlan(42)
	result, err := s.ExecuteEstablishmentPlan(plan)
	require.NoError(t, err)
	require.Same(t, plan, result.AppliedPlan)
	result, err = s.ExecuteModificationPlan(plan)
	require.NoError(t, err)
	require.Same(t, plan, result.AppliedPlan)
	_, err = s.QueryURR(7)
	require.NoError(t, err)
}
