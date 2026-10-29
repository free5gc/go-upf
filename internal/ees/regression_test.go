package ees

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	"github.com/free5gc/go-upf/internal/report"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func response(code int) *http.Response {
	return &http.Response{StatusCode: code, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(""))}
}

func testLogger() *logrus.Entry {
	l := logrus.New()
	l.SetOutput(io.Discard)
	return logrus.NewEntry(l)
}

func testSub() *Subscription {
	return &Subscription{
		NotifURI: "http://subscriber.invalid/notify", NfID: "nf", NotifyCorrelationID: "corr",
		Event: EventUserDataUsageMeasures, Granularity: GranularityPerSession, Mode: ModeOnDemand,
		Target: TargetScope{AnyUE: true}, MeasurementTypes: []MeasurementType{MeasureVolume},
	}
}

func usageReport(id uint32, bytes uint64) report.SessReport {
	return report.SessReport{SEID: 1, Reports: []report.Report{report.USAReport{
		URRID: id, StartTime: time.Now().Add(-time.Second), EndTime: time.Now(),
		VolumMeasure: report.VolumeMeasure{UplinkVolume: bytes},
	}}}
}

func testAggregator(t *testing.T) (*Aggregator, *Subscription) {
	t.Helper()
	store := NewSubscriptionStore("")
	sub := testSub()
	_, err := store.CreateSubscription(sub)
	require.NoError(t, err)
	return NewAggregator(store, 10*time.Second, NewNotifier(testLogger()), testLogger(), nil, nil), sub
}

func TestTrafficVolumeWireFormatIncludesZero(t *testing.T) {
	n := NewNotifier(testLogger())
	n.httpClient.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		var body NotificationData
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		volume := body.NotificationItems[0].UserDataUsageMeasurements[0].VolumeMeasurement
		require.Equal(t, "123 B", volume.TotalVolume)
		require.Equal(t, "0 B", volume.DlVolume)
		return response(204), nil
	})
	require.NoError(t, n.Notify(testSub(), []UsageMeasures{{UeIpv4Addr: "10.0.0.1", ULBytesDelta: 123}}))
}

func TestSessionGenerationAndMAQESelection(t *testing.T) {
	a, sub := testAggregator(t)
	old := SessionContext{RemoteSEID: 10, Generation: 1, UeIPv4Addr: "10.0.0.1"}
	current := SessionContext{RemoteSEID: 10, Generation: 2, UeIPv4Addr: "10.0.0.1"}
	a.PushReportWithContext(usageReport(1, 999), old)
	a.PushReportWithContext(usageReport(7, 999), old)
	require.Empty(t, a.reportBuffer)
	a.PushReportWithContext(usageReport(2, 100), old)
	a.PushReportWithContext(usageReport(2, 200), current)
	require.Len(t, a.reportBuffer[sub.ID], 2, "even the same IP and both SEIDs must not merge across session lifetimes")
	for key, m := range a.reportBuffer[sub.ID] {
		require.Equal(t, uint64(100)*key.Generation, m.ULBytesDelta)
	}
	otherSession := usageReport(2, 500)
	otherSession.SEID = 2
	a.PushReportWithContext(otherSession, old)
	require.Len(t, a.reportBuffer[sub.ID], 3, "URR 2 in another live session is a separate rule")
}

func TestOneTimeWaitsWithoutSessionAndRetriesRealZero(t *testing.T) {
	a, sub := testAggregator(t)
	calls := 0
	a.notifier.httpClient.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			return response(500), nil
		}
		b, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.Contains(t, string(b), `"totalVolume":"0 B"`)
		return response(204), nil
	})
	n, err := a.TickOnce(context.Background())
	require.NoError(t, err)
	require.Zero(t, n)
	_, exists := a.subscriptionStore.GetSubscription(sub.ID)
	require.True(t, exists)
	a.PushReportWithContext(usageReport(2, 0), SessionContext{Generation: 1, UeIPv4Addr: "10.0.0.1"})
	n, err = a.TickOnce(context.Background())
	require.NoError(t, err)
	require.Zero(t, n)
	require.Len(t, a.reportBuffer[sub.ID], 1)
	a.mu.Lock()
	a.retryAt[sub.ID] = time.Time{}
	a.mu.Unlock()
	n, err = a.TickOnce(context.Background())
	require.NoError(t, err)
	require.Equal(t, 1, n)
	_, exists = a.subscriptionStore.GetSubscription(sub.ID)
	require.False(t, exists)
}

func TestIndependentSubscribersAndCancellation(t *testing.T) {
	a, slow := testAggregator(t)
	slow.NotifURI = "http://slow.invalid/notify"
	fast := testSub()
	_, err := a.subscriptionStore.CreateSubscription(fast)
	require.NoError(t, err)
	slowStarted, fastDone, cancelled := make(chan struct{}), make(chan struct{}), make(chan struct{})
	a.notifier.httpClient.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Hostname() == "slow.invalid" {
			close(slowStarted)
			<-r.Context().Done()
			close(cancelled)
			return nil, r.Context().Err()
		}
		close(fastDone)
		return response(204), nil
	})
	a.PushReportWithContext(usageReport(2, 1), SessionContext{UeIPv4Addr: "10.0.0.1"})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { a.Run(ctx); close(done) }()
	for _, ch := range []chan struct{}{slowStarted, fastDone} {
		select {
		case <-ch:
		case <-time.After(time.Second):
			t.Fatal("one subscriber blocked another")
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run did not cancel notification and join worker")
	}
	select {
	case <-cancelled:
	default:
		t.Fatal("HTTP request was not cancelled")
	}
}

func TestSubscriptionDeadlineNotGlobalTicker(t *testing.T) {
	a, sub := testAggregator(t)
	sub.Mode, sub.PeriodSec = ModePeriodic, 1
	// There is deliberately no dependency on the constructor's 10s period.
	sent := make(chan time.Time, 1)
	a.notifier.httpClient.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		sent <- time.Now()
		return response(204), nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { a.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()
	a.PushReportWithContext(usageReport(2, 1), SessionContext{UeIPv4Addr: "10.0.0.1"})
	select {
	case when := <-sent:
		require.GreaterOrEqual(t, when.Sub(sub.CreatedAt), time.Second)
		require.Less(t, when.Sub(sub.CreatedAt), 2*time.Second)
	case <-time.After(2 * time.Second):
		t.Fatal("accepted 1s subscription was not scheduled")
	}
}

const validRequest = `{"subscription":{"nfId":"nf",` +
	`"eventList":[{"type":"USER_DATA_USAGE_MEASURES","granularityOfMeasurement":"PER_SESSION",` +
	`"measurementTypes":["VOLUME_MEASUREMENT"]}],` +
	`"eventNotifyUri":"http://subscriber.invalid/notify","notifyCorrelationId":"corr",` +
	`"eventReportingMode":{"trigger":"PERIODIC","repPeriod":1},"ueIpAddress":{"ipv4Addr":"10.0.0.1"}}}`

func TestAPIRejectsUnfulfillableRequestsAndWrongDeletePath(t *testing.T) {
	srv := NewServer(NewSubscriptionStore(""), nil, testLogger())
	mux := http.NewServeMux()
	srv.Routes(mux)
	for name, body := range map[string]string{
		"empty measurements":       strings.Replace(validRequest, `["VOLUME_MEASUREMENT"]`, `[]`, 1),
		"unsupported measurements": strings.Replace(validRequest, "VOLUME_MEASUREMENT", "APPLICATION_RELATED_INFO", 1),
		"app filters":              strings.Replace(validRequest, `"type":`, `"appIds":["x"],"type":`, 1),
		"flow filters":             strings.Replace(validRequest, `"type":`, `"trafficFilters":[{}],"type":`, 1),
		"multiple events": strings.Replace(validRequest,
			`}],"eventNotifyUri"`, `},{"type":"QOS_MONITORING"}],"eventNotifyUri"`, 1),
		"old period": strings.Replace(validRequest, "repPeriod", "reportPeriod", 1),
		"string IP":  strings.Replace(validRequest, `{"ipv4Addr":"10.0.0.1"}`, `"10.0.0.1"`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, httptest.NewRequestWithContext(t.Context(), http.MethodPost,
				"http://upf/nupf-ee/v1/ee-subscriptions", strings.NewReader(body)))
			require.Equal(t, 400, rr.Code, rr.Body.String())
		})
	}
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequestWithContext(t.Context(), http.MethodPost,
		"https://upf/nupf-ee/v1/ee-subscriptions", strings.NewReader(validRequest)))
	require.Equal(t, 201, rr.Code, rr.Body.String())
	var created createSubscriptionResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &created))
	require.Equal(t, rr.Header().Get("Location"), created.SubscriptionID)
	require.True(t, strings.HasPrefix(created.SubscriptionID, "https://upf/"))
	id := path.Base(created.SubscriptionID)
	for _, suffix := range []string{"wrong/" + id, id + "/"} {
		rr = httptest.NewRecorder()
		mux.ServeHTTP(rr, httptest.NewRequestWithContext(t.Context(), http.MethodDelete,
			"/nupf-ee/v1/ee-subscriptions/"+suffix, nil))
		require.Equal(t, 404, rr.Code)
		_, exists := srv.subscriptionStore.GetSubscription(id)
		require.True(t, exists)
	}
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequestWithContext(t.Context(), http.MethodDelete, created.SubscriptionID, nil))
	require.Equal(t, 204, rr.Code)
}

func TestDeleteDuringFailedNotificationDoesNotRestoreBuffer(t *testing.T) {
	a, sub := testAggregator(t)
	var calls atomic.Int32
	a.notifier.httpClient.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		require.NoError(t, a.subscriptionStore.DeleteSubscription(sub.ID))
		return response(500), nil
	})
	a.PushReportWithContext(usageReport(2, 10), SessionContext{UeIPv4Addr: "10.0.0.1"})
	_, err := a.TickOnce(context.Background())
	require.NoError(t, err)
	require.Empty(t, a.reportBuffer)
	require.Equal(t, int32(1), calls.Load())
}

func TestFailedBatchMergesWithReportsArrivingDuringRequest(t *testing.T) {
	a, sub := testAggregator(t)
	identity := SessionContext{Generation: 1, UeIPv4Addr: "10.0.0.1"}
	a.notifier.httpClient.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		a.PushReportWithContext(usageReport(2, 200), identity)
		return response(500), nil
	})
	a.PushReportWithContext(usageReport(2, 100), identity)
	_, err := a.TickOnce(context.Background())
	require.NoError(t, err)
	a.mu.Lock()
	defer a.mu.Unlock()
	require.Len(t, a.reportBuffer[sub.ID], 1)
	for _, measure := range a.reportBuffer[sub.ID] {
		require.Equal(t, uint64(300), measure.ULBytesDelta)
	}
}

func TestNotificationPeriodRoundsUpToURRPeriod(t *testing.T) {
	for _, c := range []struct{ requested, base, want time.Duration }{
		{5 * time.Second, 10 * time.Second, 10 * time.Second}, // never faster than the URR reports
		{25 * time.Second, 10 * time.Second, 30 * time.Second},
		{30 * time.Second, 10 * time.Second, 30 * time.Second},
		{3 * time.Second, 2 * time.Second, 4 * time.Second},
		{7 * time.Second, 0, 7 * time.Second}, // no periodic URR: as requested
	} {
		require.Equal(t, c.want, notificationPeriod(c.requested, c.base), "%v over %v", c.requested, c.base)
	}
}

func windowReport(start, end time.Time) report.SessReport {
	return report.SessReport{SEID: 1, Reports: []report.Report{report.USAReport{
		URRID: SingleUPFMAQEURRID, StartTime: start, EndTime: end,
		VolumMeasure: report.VolumeMeasure{UplinkVolume: 10},
	}}}
}

func TestPeriodicSendsOnceWholeURRPeriodsAreCollected(t *testing.T) {
	a, sub := testAggregator(t)
	sub.Mode, sub.PeriodSec = ModePeriodic, 3 // rounded up to 4s over a 2s URR period
	sub.MeasurementTypes = []MeasurementType{MeasureVolume, MeasureThroughput}
	var bodies []string
	a.notifier.httpClient.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		b, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		bodies = append(bodies, string(b))
		return response(204), nil
	})
	identity := SessionContext{Generation: 1, UeIPv4Addr: "10.0.0.1", MeasurePeriod: 2 * time.Second}
	now := time.Now()

	a.PushReportWithContext(windowReport(now.Add(-4*time.Second), now.Add(-2*time.Second)), identity)
	n, err := a.TickOnce(context.Background())
	require.NoError(t, err)
	require.Zero(t, n, "one 2s URR period does not fill a 4s notification period")

	a.PushReportWithContext(windowReport(now.Add(-2*time.Second), now), identity)
	n, err = a.TickOnce(context.Background())
	require.NoError(t, err)
	require.Equal(t, 1, n, "sent as soon as two URR periods are collected, not on a wall-clock deadline")
	require.Len(t, bodies, 1)
	require.Contains(t, bodies[0], `"ulVolume":"20 B"`)
	require.Contains(t, bodies[0], `"ulThroughput":"40 bps"`) // 20 B over the 4s span
}

func TestPeriodicSendsPartialBatchWhenReportsStop(t *testing.T) {
	a, sub := testAggregator(t)
	sub.Mode, sub.PeriodSec = ModePeriodic, 1
	a.notifier.httpClient.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return response(204), nil
	})
	now := time.Now()
	// e.g. the session was released shortly after its last full period.
	a.PushReportWithContext(windowReport(now.Add(-200*time.Millisecond), now),
		SessionContext{Generation: 1, UeIPv4Addr: "10.0.0.1", MeasurePeriod: time.Second})
	n, err := a.TickOnce(context.Background())
	require.NoError(t, err)
	require.Zero(t, n)
	require.Eventually(t, func() bool {
		n, err := a.TickOnce(context.Background())
		return err == nil && n == 1
	}, 3*time.Second, 50*time.Millisecond)
	require.GreaterOrEqual(t, time.Since(sub.CreatedAt), 1400*time.Millisecond,
		"partial batch waits for the deadline plus half a URR period")
}
