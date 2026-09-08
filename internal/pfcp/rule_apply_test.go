package pfcp

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/wmnsk/go-pfcp/ie"

	"github.com/free5gc/go-upf/internal/forwarder"
	"github.com/free5gc/go-upf/internal/report"
	"github.com/free5gc/go-upf/internal/rules"
)

type transactionDatapath struct {
	forwarder.SessionDatapath
	calls int
	apply func(*rules.RuleChangeSet) (*forwarder.ApplyResult, error)
}

func (d *transactionDatapath) Establish(c *rules.RuleChangeSet) (*forwarder.ApplyResult, error) {
	d.calls++
	return d.apply(c)
}

func (d *transactionDatapath) Modify(c *rules.RuleChangeSet) (*forwarder.ApplyResult, error) {
	d.calls++
	return d.apply(c)
}

func (d *transactionDatapath) QueryURR(uint32) ([]report.USAReport, error) {
	panic("query outside transaction")
}

func TestRuleTransactionPublishesOnlyAfterCompleteSuccess(t *testing.T) {
	s := newRuleStateTestSession()
	original := s.QERIDs[7]
	failed := errors.New("execution failed")
	d := &transactionDatapath{apply: func(c *rules.RuleChangeSet) (*forwarder.ApplyResult, error) {
		require.Same(t, original, s.QERIDs[7])
		require.Nil(t, s.QERIDs[7].MBR)
		return &forwarder.ApplyResult{}, failed
	}}
	s.datapath = d
	changes := &rules.RuleChangeSet{
		UpdateQERs: []rules.QERPatch{{QERID: 7, MBR: &rules.DirectionalBitRate{UplinkBps: 1000}}},
	}
	reports, err := s.applyRuleChanges(changes, false)
	require.ErrorIs(t, err, failed)
	require.Nil(t, reports)
	require.Equal(t, ie.CauseRuleCreationModificationFailure, pfcpCauseFromError(err))
	require.Same(t, original, s.QERIDs[7])
	d.apply = func(c *rules.RuleChangeSet) (*forwarder.ApplyResult, error) {
		require.Same(t, original, s.QERIDs[7])
		return &forwarder.ApplyResult{}, nil
	}
	_, err = s.applyRuleChanges(changes, false)
	require.NoError(t, err)
	require.Equal(t, uint64(1000), s.QERIDs[7].MBR.UplinkBps)
	_, err = s.applyRuleChanges(&rules.RuleChangeSet{RemoveQERs: []uint32{7}}, false)
	require.Error(t, err)
	require.Equal(t, 2, d.calls, "invalid references must fail before execution")
}

func TestRuleTransactionTerminalReporting(t *testing.T) {
	for _, tc := range []struct {
		name                string
		explicit, removeURR bool
	}{
		{name: "implicit query"}, {name: "explicit query", explicit: true}, {name: "remove report", removeURR: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newRuleStateTestSession()
			changes := &rules.RuleChangeSet{RemovePDRs: []uint16{11}}
			if tc.explicit {
				changes.QueryURRs = []uint32{3}
			}
			if tc.removeURR {
				changes.RemoveURRs = []uint32{3}
			}
			returned := &forwarder.ApplyResult{USAReports: []report.USAReport{{URRID: 3}}}
			s.datapath = &transactionDatapath{apply: func(c *rules.RuleChangeSet) (*forwarder.ApplyResult, error) {
				require.Contains(t, s.PDRIDs, uint16(11))
				require.Equal(t, uint16(1), s.URRIDs[3].refPdrNum)
				if tc.removeURR {
					require.Empty(t, c.QueryURRs)
				} else {
					require.Equal(t, []uint32{3}, c.QueryURRs)
				}
				return returned, nil
			}}
			reports, err := s.applyRuleChanges(changes, false)
			require.NoError(t, err)
			require.NotContains(t, s.PDRIDs, uint16(11))
			require.Zero(t, s.URRIDs[3].refPdrNum)
			require.Len(t, reports, 1)
			require.NotZero(t, reports[0].USARTrigger.Flags&report.USAR_TRIG_TERMR)
			require.Equal(t, tc.explicit, reports[0].USARTrigger.Flags&report.USAR_TRIG_IMMER != 0)
			require.Zero(t, returned.USAReports[0].USARTrigger.Flags, "do not mutate backend output")
			if !tc.explicit {
				require.Empty(t, changes.QueryURRs, "do not mutate parsed request")
			}
		})
	}
}

func TestTerminalQueryFailureDoesNotPublish(t *testing.T) {
	s := newRuleStateTestSession()
	failure := errors.New("terminal query failed; transaction compensated")
	s.datapath = &transactionDatapath{apply: func(c *rules.RuleChangeSet) (*forwarder.ApplyResult, error) {
		require.Equal(t, []uint32{3}, c.QueryURRs)
		return nil, failure
	}}
	_, err := s.applyRuleChanges(&rules.RuleChangeSet{RemovePDRs: []uint16{11}}, false)
	require.ErrorIs(t, err, failure)
	require.Contains(t, s.PDRIDs, uint16(11))
	require.Equal(t, uint16(1), s.URRIDs[3].refPdrNum)
}

func TestRuleTransactionTransferDoesNotTerminateURR(t *testing.T) {
	s := newRuleStateTestSession()
	s.datapath = &transactionDatapath{apply: func(c *rules.RuleChangeSet) (*forwarder.ApplyResult, error) {
		require.Empty(t, c.QueryURRs)
		return &forwarder.ApplyResult{}, nil
	}}
	_, err := s.applyRuleChanges(&rules.RuleChangeSet{
		RemovePDRs: []uint16{11}, CreatePDRs: []rules.PDRConfig{{PDRID: 12, URRIDs: []uint32{3, 3}}},
	}, false)
	require.NoError(t, err)
	require.Equal(t, uint16(1), s.URRIDs[3].refPdrNum)
}
