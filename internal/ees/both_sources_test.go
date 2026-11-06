package ees

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/free5gc/go-upf/internal/report"
)

func smfStream(id string) stream { return stream{id, SourceSMFURR} }

func bothSourcesAggregator(t *testing.T, mode Mode) (*Aggregator, *Subscription, *consumer) {
	t.Helper()
	c := newConsumer(t)
	store := NewSubscriptionStore("")
	sub := testSub()
	sub.NotifURI, sub.Mode, sub.PeriodSec, sub.Source = c.srv.URL, mode, 1, SourceBothURRs
	_, err := store.CreateSubscription(sub)
	require.NoError(t, err)
	return NewAggregator(store, NewNotifier(testLogger()), testLogger()), sub, c
}

// bothIdentity is a session with URR 2 and a UPF-owned URR, both reporting
// every second, so a one-second subscription is due on each report.
func bothIdentity() SessionContext {
	return SessionContext{
		RemoteSEID: 9, Generation: 1, UeIPv4Addr: "10.60.0.1", MeasurePeriod: time.Second,
		UPFURRID: testUPFURRID, UPFURRPeriod: time.Second,
	}
}

func ulVolumeBySource(t *testing.T, c *consumer) map[string][]string {
	t.Helper()
	got := make(map[string][]string)
	for _, n := range c.notifications() {
		require.Len(t, n.body.NotificationItems, 1)
		source := n.header.Get("X-EES-Source")
		got[source] = append(got[source],
			n.body.NotificationItems[0].UserDataUsageMeasurements[0].VolumeMeasurement.UlVolume)
	}
	return got
}

// With both URRs on, one kernel report produces one notification per URR,
// each labeled with its source and carrying only that URR's usage.
func TestBothSourcesReportSeparatelyWithoutSumming(t *testing.T) {
	a, sub, c := bothSourcesAggregator(t, ModePeriodic)
	require.True(t, sub.UsesUPFURR())

	a.PushReportWithContext(report.SessReport{SEID: 1, Reports: []report.Report{
		usage(SingleUPFMAQEURRID, 1000), usage(testUPFURRID, 7), usage(1, 5555),
	}}, bothIdentity())
	n, err := a.TickOnce(context.Background())
	require.NoError(t, err)
	require.Equal(t, 2, n)
	require.Equal(t, map[string][]string{
		string(SourceSMFURR): {"1000 B"},
		string(SourceUPFURR): {"7 B"},
	}, ulVolumeBySource(t, c))
}

// A silent URR 2 does not hold back the UPF-owned URR, and a failed send on
// one stream is retried without resending the other.
func TestBothSourcesAreScheduledIndependently(t *testing.T) {
	a, sub, c := bothSourcesAggregator(t, ModePeriodic)

	a.PushReportWithContext(report.SessReport{SEID: 1, Reports: []report.Report{usage(testUPFURRID, 7)}}, bothIdentity())
	n, err := a.TickOnce(context.Background())
	require.NoError(t, err)
	require.Equal(t, 1, n, "the UPF stream reports while URR 2 is silent")

	c.mu.Lock()
	c.status = []int{500}
	c.mu.Unlock()
	a.PushReportWithContext(report.SessReport{
		SEID: 1, Reports: []report.Report{usage(SingleUPFMAQEURRID, 1000)},
	}, bothIdentity())
	n, err = a.TickOnce(context.Background())
	require.NoError(t, err)
	require.Zero(t, n)
	a.mu.Lock()
	require.Len(t, a.reportBuffer[smfStream(sub.ID)], 1, "the failed URR 2 batch is retained")
	require.Empty(t, a.reportBuffer[stream{sub.ID, SourceUPFURR}])
	a.retryAt[smfStream(sub.ID)] = time.Time{}
	a.mu.Unlock()

	n, err = a.TickOnce(context.Background())
	require.NoError(t, err)
	require.Equal(t, 1, n)
	require.Equal(t, map[string][]string{
		string(SourceSMFURR): {"1000 B"},
		string(SourceUPFURR): {"7 B"},
	}, ulVolumeBySource(t, c))
}

// ONE_TIME with both URRs: each stream delivers once, then the subscription
// is removed.
func TestOneTimeBothSourcesDeliverOnceThenRemove(t *testing.T) {
	a, sub, c := bothSourcesAggregator(t, ModeOnDemand)

	a.PushReportWithContext(report.SessReport{SEID: 1, Reports: []report.Report{
		usage(SingleUPFMAQEURRID, 1000), usage(testUPFURRID, 7),
	}}, bothIdentity())
	n, err := a.TickOnce(context.Background())
	require.NoError(t, err)
	require.Equal(t, 2, n)
	_, exists := a.subscriptionStore.GetSubscription(sub.ID)
	require.False(t, exists)
	require.Len(t, c.notifications(), 2)

	_, err = a.TickOnce(context.Background())
	require.NoError(t, err)
	require.Empty(t, a.oneTimeSent)
	require.Empty(t, a.lastSent)
}

// ONE_TIME with both URRs and a silent URR 2 ends after a bounded wait, and
// the delivered stream does not report a second time meanwhile.
func TestOneTimeBothSourcesDoesNotWaitForeverForSilentSource(t *testing.T) {
	a, sub, c := bothSourcesAggregator(t, ModeOnDemand)
	a.oneTimeWait = 50 * time.Millisecond
	upfReport := report.SessReport{SEID: 1, Reports: []report.Report{usage(testUPFURRID, 7)}}

	a.PushReportWithContext(upfReport, bothIdentity())
	n, err := a.TickOnce(context.Background())
	require.NoError(t, err)
	require.Equal(t, 1, n)
	_, exists := a.subscriptionStore.GetSubscription(sub.ID)
	require.True(t, exists, "URR 2 may still report")

	a.PushReportWithContext(upfReport, bothIdentity())
	n, err = a.TickOnce(context.Background())
	require.NoError(t, err)
	require.Zero(t, n, "a ONE_TIME stream reports once")

	require.Eventually(t, func() bool {
		_, tickErr := a.TickOnce(context.Background())
		require.NoError(t, tickErr)
		_, present := a.subscriptionStore.GetSubscription(sub.ID)
		return !present
	}, 2*time.Second, 10*time.Millisecond)
	require.Len(t, c.notifications(), 1)
}
