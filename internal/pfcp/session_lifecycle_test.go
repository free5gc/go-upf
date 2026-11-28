package pfcp

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"

	"github.com/free5gc/go-upf/internal/forwarder"
	"github.com/free5gc/go-upf/internal/logger"
	"github.com/free5gc/go-upf/internal/report"
	"github.com/free5gc/go-upf/internal/rules"
)

type cleanupDatapath struct {
	forwarder.SessionDatapath
	calls int
	run   func(*rules.RuleChangeSet) (*forwarder.ApplyResult, error)
}

func (d *cleanupDatapath) Cleanup(c *rules.RuleChangeSet) (*forwarder.ApplyResult, error) {
	d.calls++
	return d.run(c)
}

func cleanupSession(t *testing.T) (*LocalNode, *Session, *cleanupDatapath) {
	t.Helper()
	node := NewLocalNode("upf.example.com", time.Time{}, forwarder.Empty{}, logger.PfcpLog.WithField("test", t.Name()))
	a := node.EstablishAssociation("127.0.0.1", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8805})
	s := node.CreateSession(a, 100)
	s.PDRIDs[11] = &rules.PDRConfig{PDRID: 11, URRIDs: []uint32{3}}
	s.QERIDs[7] = &rules.QERConfig{QERID: 7}
	method := uint8(2)
	s.URRIDs[3] = &URRInfo{Config: rules.URRConfig{URRID: 3, MeasureMethod: &method}, refPdrNum: 1}
	d := &cleanupDatapath{}
	s.datapath = d
	return node, s, d
}

func TestCleanupRetainsOnlyPendingRulesAndSEID(t *testing.T) {
	node, s, backend := cleanupSession(t)
	originalHandle := s.datapath
	s.Push(11, []byte{1})
	queue := s.q[11]
	failure := errors.New("QER removal failed")
	backend.run = func(c *rules.RuleChangeSet) (*forwarder.ApplyResult, error) {
		require.Equal(t, []uint16{11}, c.RemovePDRs)
		return &forwarder.ApplyResult{
			Removed:    forwarder.RemovedRules{PDRs: []uint16{11}, URRs: []uint32{3}},
			USAReports: []report.USAReport{{URRID: 3, VolumMeasure: report.VolumeMeasure{TotalVolume: 42}}},
		}, failure
	}
	reports, err := node.deleteSession(s.LocalID)
	require.ErrorIs(t, err, failure)
	require.Empty(t, reports)
	require.True(t, s.closing)
	require.Same(t, originalHandle, s.datapath)
	require.Empty(t, s.PDRIDs)
	require.Contains(t, s.QERIDs, uint32(7))
	require.True(t, s.URRIDs[3].removed)
	require.Zero(t, s.URRIDs[3].refPdrNum)
	require.Contains(t, s.association.sessionIDs, s.LocalID)
	require.Empty(t, node.sessions.freeSEIDs)
	_, ok := <-queue
	require.True(t, ok)
	_, ok = <-queue
	require.False(t, ok)
	require.NotPanics(t, func() { s.Push(11, []byte{2}) })
	_, err = s.applyRuleChanges(&rules.RuleChangeSet{SEID: s.LocalID}, false, nil)
	require.Error(t, err, "closing sessions cannot resume modification")
	other := node.CreateSession(s.association, 101)
	require.NotEqual(t, s.LocalID, other.LocalID)
	backend.run = func(c *rules.RuleChangeSet) (*forwarder.ApplyResult, error) {
		require.Empty(t, c.RemovePDRs)
		require.Empty(t, c.RemoveURRs)
		require.Equal(t, []uint32{7}, c.RemoveQERs)
		return &forwarder.ApplyResult{Removed: forwarder.RemovedRules{QERs: []uint32{7}}}, nil
	}
	reports, err = node.deleteSession(s.LocalID)
	require.NoError(t, err)
	require.Len(t, reports, 1)
	require.Equal(t, uint64(42), reports[0].VolumMeasure.TotalVolume)
	require.NotZero(t, reports[0].USARTrigger.Flags&report.USAR_TRIG_TERMR)
	_, err = node.Session(s.LocalID)
	require.Error(t, err)
	require.NotContains(t, s.association.sessionIDs, s.LocalID)
	replacement := node.CreateSession(s.association, 102)
	require.Equal(t, s.LocalID, replacement.LocalID)
	require.NotSame(t, originalHandle, replacement.datapath)
}

func TestCleanupRejectsUnconfirmedSuccessAndBacksOff(t *testing.T) {
	node, s, backend := cleanupSession(t)
	backend.run = func(*rules.RuleChangeSet) (*forwarder.ApplyResult, error) { return nil, nil }
	transport := &messageTransportMock{}
	d := newDispatcher(node, transport, node.log)
	_, err := node.deleteSession(s.LocalID)
	require.Error(t, err)
	due := s.cleanupRetryAt
	d.retrySessionCleanup(due.Add(-time.Nanosecond))
	require.Equal(t, 1, backend.calls)
	secondAttempt := time.Now()
	d.retrySessionCleanup(due)
	require.Equal(t, 2, backend.calls)
	require.WithinDuration(t, secondAttempt.Add(2*time.Second), s.cleanupRetryAt, time.Second)
	d.retrySessionCleanup(s.cleanupRetryAt)
	require.Equal(t, 3, backend.calls)
	require.True(t, s.cleanupRetryAt.IsZero())
	d.retrySessionCleanup(time.Now().Add(time.Hour))
	require.Equal(t, 3, backend.calls)
	require.Empty(t, node.sessions.freeSEIDs)
}

func TestCleanupAfterAssociationReplacementKeepsNewMembership(t *testing.T) {
	node, s, backend := cleanupSession(t)
	old := s.association
	backend.run = func(*rules.RuleChangeSet) (*forwarder.ApplyResult, error) { return nil, errors.New("unavailable") }
	next := node.EstablishAssociation(old.PeerNodeID, old.peerAddr)
	require.NotSame(t, old, next)
	current := node.CreateSession(next, 200)
	require.NotEqual(t, s.LocalID, current.LocalID)
	backend.run = func(c *rules.RuleChangeSet) (*forwarder.ApplyResult, error) {
		return &forwarder.ApplyResult{
			Removed:    forwarder.RemovedRules{PDRs: c.RemovePDRs, QERs: c.RemoveQERs, URRs: c.RemoveURRs},
			USAReports: []report.USAReport{{URRID: 3}},
		}, nil
	}
	transport := &messageTransportMock{}
	d := newDispatcher(node, transport, node.log)
	d.retrySessionCleanup(s.cleanupRetryAt)
	require.Contains(t, next.sessionIDs, current.LocalID)
	require.Empty(t, old.sessionIDs)
	require.Nil(t, transport.req, "do not send old reports to a replacement association")
	_, err := node.Session(s.LocalID)
	require.Error(t, err)
}

func TestDeletionFailureAndRetryFinalReport(t *testing.T) {
	node, s, backend := cleanupSession(t)
	backend.run = func(*rules.RuleChangeSet) (*forwarder.ApplyResult, error) {
		return &forwarder.ApplyResult{
			Removed:    forwarder.RemovedRules{PDRs: []uint16{11}, URRs: []uint32{3}},
			USAReports: []report.USAReport{{URRID: 3}},
		}, errors.New("QER failed")
	}
	transport := &messageTransportMock{}
	d := newDispatcher(node, transport, node.log)
	deleteRequest := func(seq uint32, addr net.Addr, want uint8) *message.SessionDeletionResponse {
		t.Helper()
		d.handleSessionDeletionRequest(message.NewSessionDeletionRequest(0, 0, s.LocalID, seq, 0), addr)
		rsp := transport.rsp.(*message.SessionDeletionResponse)
		cause, err := rsp.Cause.Cause()
		require.NoError(t, err)
		require.Equal(t, want, cause)
		return rsp
	}
	peer := s.association.peerAddr
	failed := deleteRequest(1, peer, ie.CauseSystemFailure)
	require.Empty(t, failed.UsageReport)
	d.retrySessionCleanup(time.Now().Add(time.Hour))
	require.Equal(t, 1, backend.calls, "SMF owns the retries")

	backend.run = func(c *rules.RuleChangeSet) (*forwarder.ApplyResult, error) {
		require.Empty(t, c.RemovePDRs)
		require.Empty(t, c.RemoveURRs)
		require.Equal(t, []uint32{7}, c.RemoveQERs)
		return &forwarder.ApplyResult{Removed: forwarder.RemovedRules{QERs: c.RemoveQERs}}, nil
	}
	accepted := deleteRequest(2, peer, ie.CauseRequestAccepted)
	require.Equal(t, s.RemoteID, accepted.SEID())
	require.Len(t, accepted.UsageReport, 1)
	require.True(t, accepted.UsageReport[0].HasTERMR())
	require.Nil(t, transport.req, "usage is delivered in the response")
	_, err := node.Session(s.LocalID)
	require.Error(t, err)
	otherPeer := &net.UDPAddr{IP: net.ParseIP("127.0.0.99"), Port: 8805}
	otherAssoc := node.EstablishAssociation("127.0.0.99", otherPeer)
	other := node.CreateSession(otherAssoc, 999)
	require.NotEqual(t, s.LocalID, other.LocalID)
	require.Empty(t, deleteRequest(3, otherPeer, ie.CauseRequestRejected).UsageReport)
	replayed := deleteRequest(4, peer, ie.CauseRequestAccepted)
	require.Equal(t, uint32(4), replayed.Sequence())
	require.Equal(t, accepted.UsageReport, replayed.UsageReport)
	require.Equal(t, 2, backend.calls, "replaying success must not touch the datapath")

	d.retrySessionCleanup(d.completedDeletions[s.LocalID].expiresAt)
	deleteRequest(5, peer, ie.CauseSessionContextNotFound)
	reused := node.CreateSession(s.association, 120)
	require.Equal(t, s.LocalID, reused.LocalID)
}

func TestDeletionRequestsStopAfterThreeCleanupAttempts(t *testing.T) {
	node, s, backend := cleanupSession(t)
	backend.run = func(*rules.RuleChangeSet) (*forwarder.ApplyResult, error) {
		return nil, errors.New("kernel cleanup failed")
	}
	transport := &messageTransportMock{}
	d := newDispatcher(node, transport, node.log)
	for seq := uint32(1); seq <= 4; seq++ {
		req := message.NewSessionDeletionRequest(0, 0, s.LocalID, seq, 0)
		d.handleSessionDeletionRequest(req, s.association.peerAddr)
		cause, err := transport.rsp.(*message.SessionDeletionResponse).Cause.Cause()
		require.NoError(t, err)
		require.Equal(t, ie.CauseSystemFailure, cause)
	}
	d.retrySessionCleanup(time.Now().Add(time.Hour))
	require.Equal(t, 3, backend.calls)
	retained, err := node.Session(s.LocalID)
	require.NoError(t, err)
	require.Same(t, s, retained)
	require.Empty(t, node.sessions.freeSEIDs)
}

func TestCleanupLateReportResponseDoesNotDeleteReplacement(t *testing.T) {
	node, s, backend := cleanupSession(t)
	backend.run = func(c *rules.RuleChangeSet) (*forwarder.ApplyResult, error) {
		return &forwarder.ApplyResult{Removed: forwarder.RemovedRules{
			PDRs: c.RemovePDRs, QERs: c.RemoveQERs, URRs: c.RemoveURRs,
		}}, nil
	}
	transport := &messageTransportMock{}
	d := newDispatcher(node, transport, node.log)
	require.NoError(t, d.sendUSAReport(s.association.peerAddr, s, []report.USAReport{{URRID: 3}}))
	setReqSeq(transport.req, 42)
	require.Equal(t, uint32(42), transport.req.Sequence())
	_, err := node.deleteSession(s.LocalID)
	require.NoError(t, err)
	replacement := node.CreateSession(s.association, s.RemoteID)
	require.Equal(t, s.LocalID, replacement.LocalID)
	rsp := message.NewSessionReportResponse(0, 0, 0, 42, 0, ie.NewCause(ie.CauseSessionContextNotFound))
	d.handleSessionReportResponse(rsp, s.association.peerAddr, transport.req)
	got, err := node.Session(replacement.LocalID)
	require.NoError(t, err)
	require.Same(t, replacement, got)
	require.NoError(t, d.HandleRequestTimeout(transport.req, s.association.peerAddr))
}

func TestCleanupStillDeliversUsageReports(t *testing.T) {
	node, s, backend := cleanupSession(t)
	backend.run = func(*rules.RuleChangeSet) (*forwarder.ApplyResult, error) {
		return nil, errors.New("unavailable")
	}
	_, err := node.deleteSession(s.LocalID)
	require.Error(t, err)
	transport := &messageTransportMock{}
	d := newDispatcher(node, transport, node.log)
	d.ServeReport(&report.SessReport{SEID: s.LocalID, Reports: []report.Report{
		report.DLDReport{PDRID: 11, Action: report.APPLY_ACT_BUFF, BufPkt: []byte{1}},
		report.USAReport{URRID: 3},
	}})
	req := transport.req.(*sessionReportRequest)
	require.Len(t, req.UsageReport, 1)
	require.Nil(t, req.DownlinkDataReport)
	require.Zero(t, s.Len(11))
}
