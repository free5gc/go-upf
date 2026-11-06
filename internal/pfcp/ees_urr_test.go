package pfcp

import (
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/wmnsk/go-pfcp/ie"

	"github.com/free5gc/go-upf/internal/ees"
	"github.com/free5gc/go-upf/internal/forwarder"
	"github.com/free5gc/go-upf/internal/logger"
	"github.com/free5gc/go-upf/internal/report"
)

func upfSourceSubscription(target ees.TargetScope) *ees.Subscription {
	return &ees.Subscription{
		NotifURI: "http://consumer.invalid/notify", NfID: "nf", NotifyCorrelationID: "corr",
		Event: ees.EventUserDataUsageMeasures, Granularity: ees.GranularityPerSession,
		Mode: ees.ModePeriodic, PeriodSec: 1, Source: ees.SourceUPFURR, Target: target,
		MeasurementTypes: []ees.MeasurementType{ees.MeasureVolume},
	}
}

func sortedPlanURRIDs(ids []uint32) []uint32 {
	out := append([]uint32(nil), ids...)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// eesURRState reads, under the session lock, which PDRs the UPF-owned URR
// is linked to and which URR IDs the forwarder has for each PDR.
func eesURRState(t *testing.T, s *PfcpServer, seid uint64) (uint32, map[uint16][]uint32, []string) {
	t.Helper()
	sess, err := s.lnode.Sess(seid)
	if err != nil {
		return 0, nil, nil
	}
	sess.mu.RLock()
	defer sess.mu.RUnlock()
	if sess.eesURR == nil {
		return 0, nil, nil
	}
	linked := map[uint16][]uint32{}
	for id, info := range sess.PDRIDs {
		if _, ok := info.RelatedURRIDs[sess.eesURR.id]; ok {
			linked[id] = sortedPlanURRIDs(sortedURRIDs(info.fwdURRIDs))
		}
	}
	return sess.eesURR.id, linked, sortedOwners(sess.eesURR.owners)
}

// With the opt-in UPF-owned source, the UPF adds its own URR to every PDR of
// the matched sessions without disturbing the SMF URRs in the forwarder, and
// the SMF-facing PFCP stays byte-identical to the upstream golden trace:
// UPF-owned usage reaches EES only.
func TestUPFOwnedURRKeepsSMFFacingPFCPUnchanged(t *testing.T) {
	var (
		server   *PfcpServer
		store    *ees.SubscriptionStore
		subID    string
		mu       sync.Mutex
		eesUsage = map[uint64][]report.USAReport{} // per local SEID
		plans    []*forwarder.PDRPlan              // SMF-driven PDR plans after setup
		setupOK  bool
		badID    bool
	)
	driver := newParityDriver()
	driver.planHook = func(kind string, p *forwarder.ModificationPlan) {
		mu.Lock()
		defer mu.Unlock()
		if setupOK && kind == "Modification" && !p.Strict {
			plans = append(plans, append(append([]*forwarder.PDRPlan(nil), p.CreatePDRs...), p.UpdatePDRs...)...)
		}
	}
	trace := runPFCPParityScenarioWith(t, driver, func(s *PfcpServer) {
		server = s
		store = ees.NewSubscriptionStore("")
		s.EnableUPFOwnedURRs(store, 2*time.Second)
		s.RegisterEESReportHandler(func(sr report.SessReport, identity ees.SessionContext) {
			mu.Lock()
			defer mu.Unlock()
			for _, r := range sr.Reports {
				if u, ok := r.(report.USAReport); ok && u.URRID >= eesURRIDBase {
					badID = badID || u.URRID != identity.UPFURRID
					eesUsage[sr.SEID] = append(eesUsage[sr.SEID], u)
				}
			}
		})
	}, func() {
		var err error
		subID, err = store.CreateSubscription(upfSourceSubscription(ees.TargetScope{AnyUE: true, DNN: "Internet"}))
		require.NoError(t, err)
		// Both sessions: one owned URR on PDRs 1-4, SMF URRs kept per PDR.
		want := map[uint16][]uint32{
			1: {1, 2, eesURRIDBase}, 2: {3, eesURRIDBase}, 3: {1, 2, eesURRIDBase}, 4: {3, 4, eesURRIDBase},
		}
		for _, seid := range []uint64{1, 2} {
			require.Eventually(t, func() bool {
				id, linked, owners := eesURRState(t, server, seid)
				return id == eesURRIDBase && len(linked) == 4 && len(owners) == 1 && owners[0] == subID &&
					assertSameLinks(linked, want)
			}, 5*time.Second, 20*time.Millisecond, "SEID %d", seid)
		}
		mu.Lock()
		setupOK = true
		mu.Unlock()
		driver.kernelReport(1, eesURRIDBase) // goes to EES, not to the SMF
	})

	want, err := os.ReadFile(pfcpParityGolden)
	require.NoError(t, err)
	cut := func(lines []string) string {
		for i, l := range lines {
			if l == "== forwarder calls" {
				return strings.Join(lines[:i], "\n")
			}
		}
		return strings.Join(lines, "\n")
	}
	require.Equal(t, cut(strings.Split(string(want), "\n")), cut(trace), "SMF-facing PFCP changed")

	mu.Lock()
	defer mu.Unlock()
	require.False(t, badID, "EES identity must carry the owned URR ID")
	// SMF Update PDR with a URR ID list keeps the owned URR; without a list it
	// is not touched; a PDR created later is measured too.
	byPDR := map[uint16][]uint32{}
	for _, p := range plans {
		if p.PDRID == 1 || p.PDRID == 3 || p.PDRID == 5 {
			byPDR[p.PDRID] = sortedPlanURRIDs(p.URRIDs)
		}
	}
	require.Equal(t, []uint32{1, eesURRIDBase}, byPDR[1])
	require.Empty(t, byPDR[3])
	require.Equal(t, []uint32{4, eesURRIDBase}, byPDR[5])
	// The kernel report and the final reports of both deleted sessions
	// reached EES (final reports with the TERMR trigger).
	require.GreaterOrEqual(t, len(eesUsage[1]), 2)
	require.NotEmpty(t, eesUsage[2])
	final := eesUsage[2][len(eesUsage[2])-1]
	require.NotZero(t, final.USARTrigger.Flags&report.USAR_TRIG_TERMR)
}

func assertSameLinks(got, want map[uint16][]uint32) bool {
	if len(got) != len(want) {
		return false
	}
	for id, w := range want {
		g := got[id]
		if len(g) != len(w) {
			return false
		}
		for i := range w {
			if g[i] != w[i] {
				return false
			}
		}
	}
	return true
}

// Owners follow the subscriptions; when the last owner goes away the URR is
// unlinked (SMF URRs restored on every PDR) and removed, and its final report
// goes to EES. A subscription on another DNN or UE never creates one.
func TestUPFOwnedURRLifecycleFollowsOwners(t *testing.T) {
	var (
		server   *PfcpServer
		store    *ees.SubscriptionStore
		mu       sync.Mutex
		eesFinal []report.USAReport
		strict   []*forwarder.ModificationPlan
	)
	driver := newParityDriver()
	driver.planHook = func(kind string, p *forwarder.ModificationPlan) {
		if p.Strict {
			mu.Lock()
			strict = append(strict, p)
			mu.Unlock()
		}
	}
	runPFCPParityScenarioWith(t, driver, func(s *PfcpServer) {
		server = s
		store = ees.NewSubscriptionStore("")
		s.EnableUPFOwnedURRs(store, time.Second)
		s.RegisterEESReportHandler(func(sr report.SessReport, identity ees.SessionContext) {
			mu.Lock()
			defer mu.Unlock()
			for _, r := range sr.Reports {
				if u, ok := r.(report.USAReport); ok && u.URRID >= eesURRIDBase {
					eesFinal = append(eesFinal, u)
				}
			}
		})
	}, func() {
		other, err := store.CreateSubscription(upfSourceSubscription(ees.TargetScope{AnyUE: true, DNN: "ims"}))
		require.NoError(t, err)
		smfSource := upfSourceSubscription(ees.TargetScope{AnyUE: true})
		smfSource.Source = ees.SourceSMFURR
		_, err = store.CreateSubscription(smfSource)
		require.NoError(t, err)
		first, err := store.CreateSubscription(upfSourceSubscription(ees.TargetScope{UeIPAddress: "10.60.0.1"}))
		require.NoError(t, err)
		second, err := store.CreateSubscription(upfSourceSubscription(ees.TargetScope{AnyUE: true}))
		require.NoError(t, err)

		require.Eventually(t, func() bool {
			_, _, owners := eesURRState(t, server, 1)
			return len(owners) == 2
		}, 5*time.Second, 20*time.Millisecond, "SEID 1 owned by the UE and the anyUe subscriptions")
		_, _, owners := eesURRState(t, server, 2)
		require.Equal(t, []string{second}, owners, "SEID 2 only by anyUe; never by the ims or SMF-source one")

		require.NoError(t, store.DeleteSubscription(second))
		require.Eventually(t, func() bool {
			id, _, _ := eesURRState(t, server, 2)
			_, _, owners := eesURRState(t, server, 1)
			return id == 0 && len(owners) == 1 && owners[0] == first
		}, 5*time.Second, 20*time.Millisecond, "SEID 2 released, SEID 1 kept by its UE subscription")
		require.NoError(t, store.DeleteSubscription(first))
		require.NoError(t, store.DeleteSubscription(other))
		require.Eventually(t, func() bool {
			id, _, _ := eesURRState(t, server, 1)
			return id == 0
		}, 5*time.Second, 20*time.Millisecond)

		sess, err := server.lnode.Sess(1)
		require.NoError(t, err)
		sess.mu.RLock()
		_, present := sess.URRIDs[eesURRIDBase]
		for id, info := range sess.PDRIDs {
			_, linked := info.RelatedURRIDs[eesURRIDBase]
			_, inFwd := info.fwdURRIDs[eesURRIDBase]
			require.False(t, linked || inFwd, "PDR %d still references the owned URR", id)
		}
		sess.mu.RUnlock()
		require.False(t, present)
	})

	mu.Lock()
	defer mu.Unlock()
	require.NotEmpty(t, eesFinal, "final usage of a removed owned URR goes to EES")
	var removed int
	for _, p := range strict {
		for _, u := range p.UpdatePDRs {
			require.NotEmpty(t, u.URRIDs, "an Update PDR never sends an empty URR list")
		}
		removed += len(p.RemoveURRs)
	}
	require.Equal(t, 2, removed, "one Remove URR per session")
}

// The SMF may not create or touch IDs in the UPF-owned range while the
// source is enabled; without it nothing changes.
func TestSMFCannotUseUPFOwnedURRIDs(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		node := &LocalNode{eesURRs: enabled}
		remote := NewRemoteNode("smf", nil, node, newParityDriver(), logger.PfcpLog)
		sess := remote.NewSess(1)
		plan := forwarder.NewModificationPlan(sess.LocalID)

		_, err := sess.ValidateCreateURR(ie.NewCreateURR(ie.NewURRID(eesURRIDBase+5),
			ie.NewMeasurementMethod(0, 1, 0), ie.NewReportingTriggers(0x01, 0x00),
			ie.NewMeasurementPeriod(time.Second)))
		if enabled {
			require.ErrorIs(t, err, ErrRuleCreationModificationFailed)
		} else {
			require.NoError(t, err)
		}
		_, err = sess.ValidateCreateURR(ie.NewCreateURR(ie.NewURRID(2),
			ie.NewMeasurementMethod(0, 1, 0), ie.NewReportingTriggers(0x01, 0x00),
			ie.NewMeasurementPeriod(time.Second)))
		require.NoError(t, err, "normal SMF URR IDs stay allowed")

		sess.URRIDs[eesURRIDBase] = &URRInfo{}
		sess.eesURR = &eesOwnedURR{id: eesURRIDBase}
		for name, validate := range map[string]func() error{
			"update": func() error {
				_, e := sess.ValidateUpdateURR(ie.NewUpdateURR(ie.NewURRID(eesURRIDBase)), plan)
				return e
			},
			"remove": func() error {
				_, e := sess.ValidateRemoveURR(ie.NewRemoveURR(ie.NewURRID(eesURRIDBase)), plan)
				return e
			},
			"query": func() error {
				_, e := sess.ValidateQueryURR(ie.NewQueryURR(ie.NewURRID(eesURRIDBase)), plan)
				return e
			},
		} {
			require.ErrorIs(t, validate(), ErrRuleCreationModificationFailed, name)
		}
	}
}

// The session DNN comes from the PDI Network Instance, in plain or FQDN
// (name syntax) encoding.
func TestSessionDNNFromNetworkInstance(t *testing.T) {
	for name, instance := range map[string]*ie.IE{
		"plain": ie.NewNetworkInstance("internet"),
		"fqdn":  ie.NewNetworkInstanceFQDN("internet"),
	} {
		t.Run(name, func(t *testing.T) {
			node := &LocalNode{}
			remote := NewRemoteNode("smf", nil, node, newParityDriver(), logger.PfcpLog)
			sess := remote.NewSess(1)
			plan := forwarder.NewModificationPlan(sess.LocalID)
			pdr, err := sess.ValidateCreatePDR(ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(255),
				ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess), instance,
					ie.NewUEIPAddress(2, "10.60.0.1", "", 0, 0)),
				ie.NewFARID(1)), plan)
			require.NoError(t, err)
			sess.ApplyCreatePDR(pdr)
			identity := sess.identitySnapshot()
			require.Equal(t, "internet", identity.DNN)
			require.Equal(t, "10.60.0.1", identity.UeIPv4Addr)
		})
	}
}
