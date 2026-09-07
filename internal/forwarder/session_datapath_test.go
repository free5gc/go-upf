package forwarder

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/free5gc/go-upf/internal/report"
	"github.com/free5gc/go-upf/internal/rules"
)

type sessionDatapathTestDriver struct {
	Empty
	calls        int
	closed       bool
	lastPlan     *modificationPlan
	queriedSEID  uint64
	queriedURRID uint32
	result       *executionResult
	reports      []report.USAReport
	err          error
}

func (d *sessionDatapathTestDriver) Close() { d.closed = true }
func (d *sessionDatapathTestDriver) QueryURR(seid uint64, id uint32) ([]report.USAReport, error) {
	d.calls++
	d.queriedSEID, d.queriedURRID = seid, id
	return d.reports, d.err
}
func (d *sessionDatapathTestDriver) executeEstablishmentPlan(plan *modificationPlan) (*executionResult, error) {
	d.calls++
	d.lastPlan = plan
	return d.result, d.err
}
func (d *sessionDatapathTestDriver) executeModificationPlan(plan *modificationPlan) (*executionResult, error) {
	d.calls++
	d.lastPlan = plan
	return d.result, d.err
}

func TestSessionDatapathRejectsInvalidPlansBeforeExecution(t *testing.T) {
	d := &sessionDatapathTestDriver{}
	s := NewSessionDatapath(d, 42).(*sessionDatapath)
	for name, execute := range map[string]func(*modificationPlan) (*executionResult, error){
		"establishment": s.executeEstablishmentPlan,
		"modification":  s.executeModificationPlan,
	} {
		t.Run(name, func(t *testing.T) {
			for _, plan := range []*modificationPlan{nil, newModificationPlan(43)} {
				result, err := execute(plan)
				require.Error(t, err)
				require.Nil(t, result)
			}
		})
	}
	require.Zero(t, d.calls)
}

func TestSessionDatapathPreservesExecutionResultsAndErrors(t *testing.T) {
	d := &sessionDatapathTestDriver{result: newExecutionResult(42), err: errors.New("execution failed")}
	s := NewSessionDatapath(d, 42).(*sessionDatapath)
	plan := newModificationPlan(42)
	plan.Rollback = newRollbackPlan()
	for name, execute := range map[string]func(*modificationPlan) (*executionResult, error){
		"establishment": s.executeEstablishmentPlan,
		"modification":  s.executeModificationPlan,
	} {
		t.Run(name, func(t *testing.T) {
			result, err := execute(plan)
			require.Equal(t, plan.SEID, d.lastPlan.SEID)
			require.NotSame(t, plan, d.lastPlan)
			require.Same(t, d.result, result)
			require.ErrorIs(t, err, d.err)
			require.NotNil(t, plan.Rollback)
		})
	}
}

func TestSessionDatapathCleanupKeepsSharedDriverAvailable(t *testing.T) {
	d := &sessionDatapathTestDriver{reports: []report.USAReport{{URRID: 7}}}
	first, second := NewSessionDatapath(d, 41).(*sessionDatapath), NewSessionDatapath(d, 42).(*sessionDatapath)
	require.Zero(t, d.calls, "creating handles must not perform datapath I/O")

	reports, err := first.QueryURR(7)
	require.NoError(t, err)
	require.Equal(t, d.reports, reports)
	require.Equal(t, uint64(41), d.queriedSEID)
	require.Equal(t, uint32(7), d.queriedURRID)

	cleanup := newModificationPlan(41)
	cleanup.RemoveURRs = []*urrPlan{{URRID: 7}}
	_, err = first.executeDeletionPlan(cleanup)
	require.NoError(t, err)
	require.Equal(t, cleanup, d.lastPlan)
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
	s := NewSessionDatapath(Empty{}, 42).(*sessionDatapath)
	plan := newModificationPlan(42)
	result, err := s.executeEstablishmentPlan(plan)
	require.NoError(t, err)
	require.Equal(t, plan.SEID, result.AppliedPlan.SEID)
	require.NotNil(t, result.AppliedPlan.Rollback)
	require.Nil(t, plan.Rollback)
	result, err = s.executeModificationPlan(plan)
	require.NoError(t, err)
	require.Equal(t, plan.SEID, result.AppliedPlan.SEID)
	require.NotNil(t, result.AppliedPlan.Rollback)
	require.Nil(t, plan.Rollback)
	_, err = s.QueryURR(7)
	require.NoError(t, err)
}

type semanticExecutionDriver struct {
	Empty
	plans   []*modificationPlan
	fail    bool
	cleanup bool
}

func (d *semanticExecutionDriver) executeEstablishmentPlan(p *modificationPlan) (*executionResult, error) {
	return d.executeModificationPlan(p)
}
func (d *semanticExecutionDriver) executeModificationPlan(p *modificationPlan) (*executionResult, error) {
	d.plans = append(d.plans, p)
	result := newSuccessfulExecutionResult(p)
	result.USAReports = []report.USAReport{{URRID: 7}}
	if d.fail {
		if d.cleanup {
			result.AppliedPlan = newModificationPlan(p.SEID)
			result.AppliedPlan.RemoveQERs = p.RemoveQERs[:1]
		}
		return result, errors.New("injected failure")
	}
	return result, nil
}

func TestSemanticDatapathCompilesAndOwnsRollback(t *testing.T) {
	d := &semanticExecutionDriver{}
	s := NewSessionDatapath(d, 42)
	qfi := uint8(9)
	changes := &rules.RuleChangeSet{SEID: 42, CreateQERs: []rules.QERConfig{{QERID: 7, QFI: &qfi}}}
	result, err := s.Establish(changes)
	require.NoError(t, err)
	require.Equal(t, uint32(7), result.USAReports[0].URRID)
	require.NotNil(t, d.plans[0].Rollback)
	original := ruleConfig{OID: d.plans[0].CreateQERs[0].OID, Attrs: d.plans[0].CreateQERs[0].Attrs}
	qfi = 63
	_, err = s.Modify(&rules.RuleChangeSet{SEID: 42, UpdateQERs: []rules.QERPatch{{QERID: 7, QFI: &qfi}}})
	require.NoError(t, err)
	require.Equal(t, original.Attrs, d.plans[1].Rollback.QERs[7].Attrs)
	// A failed transaction must expose no misleading successful removals and must
	// keep the last successful applied snapshot for the next request.
	d.fail = true
	result, err = s.Modify(&rules.RuleChangeSet{SEID: 42, RemoveQERs: []uint32{7}})
	require.Error(t, err)
	require.Nil(t, result)
	d.fail = false
	_, err = s.Modify(&rules.RuleChangeSet{SEID: 42, RemoveQERs: []uint32{7}})
	require.NoError(t, err)
	require.Equal(t, d.plans[1].UpdateQERs[0].Attrs, d.plans[3].Rollback.QERs[7].Attrs)
}

func TestSemanticDatapathRejectsInvalidRequestsBeforeIO(t *testing.T) {
	d := &semanticExecutionDriver{}
	s := NewSessionDatapath(d, 42)
	for _, apply := range []func(*rules.RuleChangeSet) (*ApplyResult, error){s.Establish, s.Modify, s.Cleanup} {
		for _, c := range []*rules.RuleChangeSet{nil, {SEID: 99}} {
			_, err := apply(c)
			require.Error(t, err)
		}
	}
	_, err := s.Establish(&rules.RuleChangeSet{SEID: 42, RemoveQERs: []uint32{7}})
	require.Error(t, err)
	_, err = s.Cleanup(&rules.RuleChangeSet{SEID: 42, CreateQERs: []rules.QERConfig{{QERID: 7}}})
	require.Error(t, err)
	require.Empty(t, d.plans)
}

func TestSemanticCleanupReturnsOnlyConfirmedIDs(t *testing.T) {
	d := &semanticExecutionDriver{}
	s := NewSessionDatapath(d, 42)
	_, err := s.Establish(&rules.RuleChangeSet{SEID: 42, CreateQERs: []rules.QERConfig{{QERID: 7}, {QERID: 8}}})
	require.NoError(t, err)
	d.fail, d.cleanup = true, true
	result, err := s.Cleanup(&rules.RuleChangeSet{SEID: 42, RemoveQERs: []uint32{7, 8}})
	require.Error(t, err)
	require.Equal(t, []uint32{7}, result.Removed.QERs)
	require.Nil(t, d.plans[1].Rollback)
	require.Contains(t, s.(*sessionDatapath).applied.qers, uint32(8))
	require.NotContains(t, s.(*sessionDatapath).applied.qers, uint32(7))
	result.Removed.QERs[0] = 99
	require.Equal(t, uint32(7), d.plans[1].RemoveQERs[0].QERID)
}

func TestSemanticCompilationDoesNotMutateFlowDescription(t *testing.T) {
	flow, err := rules.ParseFlowDesc("permit out ip from 10.0.0.1 123 to 20.0.0.1 456")
	require.NoError(t, err)
	changes := &rules.RuleChangeSet{SEID: 42, CreatePDRs: []rules.PDRConfig{{PDRID: 1, PDI: &rules.PDI{
		SDFFilters: []rules.SDFFilter{{FlowDescription: flow}},
	}}}}
	original := changes.CreatePDRs[0].Clone()
	first, err := compileRuleChanges(changes)
	require.NoError(t, err)
	second, err := compileRuleChanges(changes)
	require.NoError(t, err)
	require.Equal(t, first, second)
	require.Equal(t, original, changes.CreatePDRs[0])
}
