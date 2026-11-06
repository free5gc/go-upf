package ees

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/free5gc/go-upf/internal/report"
)

const testUPFURRID uint32 = 0xF0000001

// captureNotifications records every notification the aggregator sends.
type captureNotifications struct {
	mu    sync.Mutex
	posts []NotificationData
}

func (c *captureNotifications) transport() roundTripFunc {
	return func(r *http.Request) (*http.Response, error) {
		var n NotificationData
		if err := json.NewDecoder(r.Body).Decode(&n); err != nil {
			return nil, err
		}
		c.mu.Lock()
		c.posts = append(c.posts, n)
		c.mu.Unlock()
		return response(http.StatusNoContent), nil
	}
}

func (c *captureNotifications) byCorrelation() map[string][]NotificationItem {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[string][]NotificationItem)
	for _, n := range c.posts {
		out[n.CorrelationId] = append(out[n.CorrelationId], n.NotificationItems...)
	}
	return out
}

func usage(urrID uint32, ul uint64) report.USAReport {
	return report.USAReport{
		URRID: urrID, StartTime: time.Now().Add(-time.Second), EndTime: time.Now(),
		VolumMeasure: report.VolumeMeasure{UplinkVolume: ul},
	}
}

// One kernel report carries both URR 2 and the UPF-owned URR. Each
// subscription must read only its own source, never the sum.
func TestMeasurementSourceIsPerSubscriptionWithoutDoubleCounting(t *testing.T) {
	store := NewSubscriptionStore("")
	smfSub, upfSub := testSub(), testSub()
	smfSub.NotifyCorrelationID, upfSub.NotifyCorrelationID = "smf", "upf"
	upfSub.Source = SourceUPFURR
	for _, sub := range []*Subscription{smfSub, upfSub} {
		_, err := store.CreateSubscription(sub)
		require.NoError(t, err)
	}
	a := NewAggregator(store, NewNotifier(testLogger()), testLogger())
	capture := &captureNotifications{}
	a.notifier.httpClient.Transport = capture.transport()

	identity := SessionContext{RemoteSEID: 9, Generation: 1, UeIPv4Addr: "10.60.0.1", UPFURRID: testUPFURRID}
	a.PushReportWithContext(report.SessReport{SEID: 1, Reports: []report.Report{
		usage(SingleUPFMAQEURRID, 1000), usage(testUPFURRID, 7), usage(1, 5555),
	}}, identity)
	n, err := a.TickOnce(context.Background())
	require.NoError(t, err)
	require.Equal(t, 2, n)

	got := capture.byCorrelation()
	require.Len(t, got["smf"], 1)
	require.Equal(t, "1000 B", got["smf"][0].UserDataUsageMeasurements[0].VolumeMeasurement.UlVolume)
	require.Len(t, got["upf"], 1)
	require.Equal(t, "7 B", got["upf"][0].UserDataUsageMeasurements[0].VolumeMeasurement.UlVolume)
}

// A UPF-source subscription ignores URR 2 entirely, and a session without a
// UPF-owned URR gives it nothing (no fabricated data).
func TestUPFSourceIgnoresSMFURRAndMissingOwnedURR(t *testing.T) {
	store := NewSubscriptionStore("")
	sub := testSub()
	sub.Source = SourceUPFURR
	_, err := store.CreateSubscription(sub)
	require.NoError(t, err)
	a := NewAggregator(store, NewNotifier(testLogger()), testLogger())

	a.PushReportWithContext(report.SessReport{SEID: 1, Reports: []report.Report{usage(SingleUPFMAQEURRID, 1000)}},
		SessionContext{UeIPv4Addr: "10.60.0.1", UPFURRID: testUPFURRID})
	a.PushReportWithContext(report.SessReport{SEID: 2, Reports: []report.Report{usage(testUPFURRID, 5)}},
		SessionContext{UeIPv4Addr: "10.60.0.2"}) // URR no longer owned by this session
	require.Empty(t, a.reportBuffer)
}

// anyUe over the UPF-owned source: one notification, one item per PDU
// session, each with that session's own UE address (TS 29.564 5.2.2.3.1).
func TestAnyUEUPFSourceReportsEachSessionUEAddress(t *testing.T) {
	store := NewSubscriptionStore("")
	sub := testSub()
	sub.Source = SourceUPFURR
	_, err := store.CreateSubscription(sub)
	require.NoError(t, err)
	a := NewAggregator(store, NewNotifier(testLogger()), testLogger())
	capture := &captureNotifications{}
	a.notifier.httpClient.Transport = capture.transport()

	for seid, ip := range map[uint64]string{1: "10.60.0.1", 2: "10.60.0.2"} {
		a.PushReportWithContext(report.SessReport{SEID: seid, Reports: []report.Report{usage(testUPFURRID, seid*10)}},
			SessionContext{RemoteSEID: seid, Generation: seid, UeIPv4Addr: ip, UPFURRID: testUPFURRID})
	}
	_, err = a.TickOnce(context.Background())
	require.NoError(t, err)

	capture.mu.Lock()
	defer capture.mu.Unlock()
	require.Len(t, capture.posts, 1)
	items := map[string]string{}
	for _, it := range capture.posts[0].NotificationItems {
		items[it.UeIpv4Addr] = it.UserDataUsageMeasurements[0].VolumeMeasurement.UlVolume
	}
	require.Equal(t, map[string]string{"10.60.0.1": "10 B", "10.60.0.2": "20 B"}, items)
}

func TestMatchesTargetWithDNN(t *testing.T) {
	session := SessionContext{UeIPv4Addr: "10.60.0.1", DNN: "internet"}
	for name, tc := range map[string]struct {
		target  TargetScope
		session SessionContext
		want    bool
	}{
		"anyUe":                   {TargetScope{AnyUE: true}, session, true},
		"ue ip":                   {TargetScope{UeIPAddress: "10.60.0.1"}, session, true},
		"other ue ip":             {TargetScope{UeIPAddress: "10.60.0.2"}, session, false},
		"dnn equal ignoring case": {TargetScope{AnyUE: true, DNN: "Internet"}, session, true},
		"dnn differs":             {TargetScope{AnyUE: true, DNN: "ims"}, session, false},
		"dnn wanted, session unknown": {
			TargetScope{AnyUE: true, DNN: "internet"}, SessionContext{UeIPv4Addr: "10.60.0.1"}, true,
		},
		"ip and dnn":         {TargetScope{UeIPAddress: "10.60.0.1", DNN: "internet"}, session, true},
		"no session address": {TargetScope{AnyUE: true}, SessionContext{DNN: "internet"}, false},
	} {
		t.Run(name, func(t *testing.T) {
			sub := testSub()
			sub.Target = tc.target
			require.Equal(t, tc.want, MatchesTarget(sub, tc.session))
		})
	}
}

// The #79 contract is kept for both sources: absolute Location equal to the
// body subscriptionId, and the subscription records its source and DNN.
func TestAPIRecordsSourceAndKeepsResourceURIContract(t *testing.T) {
	for _, source := range []MeasurementSource{"", SourceUPFURR, SourceBothURRs} {
		t.Run(string(source), func(t *testing.T) {
			store := NewSubscriptionStore("")
			server := NewServer(store, testLogger())
			if source != "" {
				server.UseMeasurementSource(source)
			}
			api := httptest.NewServer(server.Handler())
			defer api.Close()

			rsp, body := do(t, http.MethodPost, api.URL+eeCollection, edit(func(sub, _, _ map[string]any) {
				sub["dnn"] = "internet"
			}))
			require.Equal(t, http.StatusCreated, rsp.StatusCode, string(body))
			var created createSubscriptionResponse
			require.NoError(t, json.Unmarshal(body, &created))
			location := rsp.Header.Get("Location")
			require.Equal(t, location, created.SubscriptionID)
			resource, err := url.Parse(location)
			require.NoError(t, err)
			require.True(t, resource.IsAbs())
			require.Equal(t, "internet", created.Subscription.Dnn)

			subs := store.AllSubscriptions()
			require.Len(t, subs, 1)
			want := source
			if want == "" {
				want = SourceSMFURR
			}
			require.Equal(t, want, subs[0].Source)
			require.Equal(t, "internet", subs[0].Target.DNN)
			require.Equal(t, eeCollection+"/"+subs[0].ID, resource.Path)

			rsp, _ = do(t, http.MethodDelete, location, nil)
			require.Equal(t, http.StatusNoContent, rsp.StatusCode)
			require.Empty(t, store.AllSubscriptions())
		})
	}
}

// A subscriber that never answers must not hold a notification forever.
func TestNotifierHasPerRequestTimeout(t *testing.T) {
	release := make(chan struct{})
	hanging := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer hanging.Close()
	defer close(release)

	notifier := NewNotifier(testLogger())
	require.Positive(t, notifier.requestTimeout, "notifications need an HTTP timeout")
	notifier.requestTimeout = 200 * time.Millisecond
	sub := testSub()
	sub.NotifURI = hanging.URL
	started := time.Now()
	err := notifier.NotifyContext(context.Background(), sub, []UsageMeasures{{UeIpv4Addr: "10.60.0.1"}})
	require.Error(t, err)
	require.Less(t, time.Since(started), 3*time.Second)
}
