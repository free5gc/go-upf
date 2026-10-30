package ees

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/free5gc/go-upf/internal/report"
)

const eeCollection = "/nupf-ee/v1/ee-subscriptions"

func baseCreateRequest() map[string]any {
	return map[string]any{"subscription": map[string]any{
		"nfId": "smf-1", "eventNotifyUri": "http://consumer.invalid/notify", "notifyCorrelationId": "corr-1",
		"eventList": []any{map[string]any{
			"type": "USER_DATA_USAGE_MEASURES", "granularityOfMeasurement": "PER_SESSION",
			"measurementTypes": []any{"VOLUME_MEASUREMENT"},
		}},
		"eventReportingMode": map[string]any{"trigger": "PERIODIC", "repPeriod": 5},
		"ueIpAddress":        map[string]any{"ipv4Addr": "10.60.0.1"},
	}}
}

func edit(fn func(sub, event, mode map[string]any)) []byte {
	req := baseCreateRequest()
	sub := req["subscription"].(map[string]any)
	fn(sub, sub["eventList"].([]any)[0].(map[string]any), sub["eventReportingMode"].(map[string]any))
	b, err := json.Marshal(req)
	if err != nil {
		panic(err)
	}
	return b
}

// apiResult keeps only what the tests inspect; the body is always closed.
type apiResult struct {
	StatusCode int
	Header     http.Header
}

func do(t *testing.T, method, url string, body []byte) (apiResult, []byte) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, url, bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	rsp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { require.NoError(t, rsp.Body.Close()) }()
	b, err := io.ReadAll(rsp.Body)
	require.NoError(t, err)
	return apiResult{StatusCode: rsp.StatusCode, Header: rsp.Header}, b
}

// every accepted and rejected subscription form, over real HTTP.
func TestValidationAPICreateMatrix(t *testing.T) {
	store := NewSubscriptionStore("")
	api := httptest.NewServer(NewServer(store, testLogger()).Handler())
	defer api.Close()

	accepted := []struct {
		name  string
		body  []byte
		check func(*testing.T, *Subscription)
	}{
		{"periodic ue ip volume", edit(func(_, _, _ map[string]any) {}), func(t *testing.T, s *Subscription) {
			require.Equal(t, ModePeriodic, s.Mode)
			require.Equal(t, 5, s.PeriodSec)
			require.Equal(t, TargetScope{UeIPAddress: "10.60.0.1"}, s.Target)
			require.Equal(t, []MeasurementType{MeasureVolume}, s.MeasurementTypes)
			require.Equal(t, "smf-1", s.NfID)
			require.Equal(t, "corr-1", s.NotifyCorrelationID)
		}},
		{"one time ignores missing repPeriod", edit(func(_, _, m map[string]any) {
			m["trigger"] = "ONE_TIME"
			delete(m, "repPeriod")
		}), func(t *testing.T, s *Subscription) { require.Equal(t, ModeOnDemand, s.Mode) }},
		{"any ue, lowercase throughput", edit(func(s, e, _ map[string]any) {
			delete(s, "ueIpAddress")
			s["anyUe"] = true
			e["measurementTypes"] = []any{"throughput_measurement"}
		}), func(t *testing.T, s *Subscription) {
			require.Equal(t, TargetScope{AnyUE: true}, s.Target)
			require.Equal(t, []MeasurementType{MeasureThroughput}, s.MeasurementTypes)
		}},
		{"volume and throughput", edit(func(_, e, _ map[string]any) {
			e["measurementTypes"] = []any{"VOLUME_MEASUREMENT", "THROUGHPUT_MEASUREMENT"}
		}), func(t *testing.T, s *Subscription) { require.Len(t, s.MeasurementTypes, 2) }},
		{"unknown fields such as supi are tolerated", edit(func(s, _, _ map[string]any) {
			s["supi"] = "imsi-208930000000001"
		}), func(t *testing.T, s *Subscription) { require.Equal(t, "10.60.0.1", s.Target.UeIPAddress) }},
		{
			"long repPeriod", edit(func(_, _, m map[string]any) { m["repPeriod"] = 86400 }),
			func(t *testing.T, s *Subscription) { require.Equal(t, 86400, s.PeriodSec) },
		},
	}
	for _, tc := range accepted {
		t.Run("accept/"+tc.name, func(t *testing.T) {
			rsp, body := do(t, http.MethodPost, api.URL+eeCollection, tc.body)
			require.Equal(t, http.StatusCreated, rsp.StatusCode, string(body))
			require.Equal(t, "application/json", rsp.Header.Get("Content-Type"))
			var created struct {
				Subscription   json.RawMessage `json:"subscription"`
				SubscriptionID string          `json:"subscriptionId"`
			}
			require.NoError(t, json.Unmarshal(body, &created))
			loc := rsp.Header.Get("Location")
			require.True(t, strings.HasPrefix(loc, api.URL+eeCollection+"/"), loc)
			require.Equal(t, loc, created.SubscriptionID)
			sub, ok := store.GetSubscription(strings.TrimPrefix(loc, api.URL+eeCollection+"/"))
			require.True(t, ok)
			require.Equal(t, EventUserDataUsageMeasures, sub.Event)
			require.Equal(t, GranularityPerSession, sub.Granularity)
			require.Equal(t, "http://consumer.invalid/notify", sub.NotifURI)
			tc.check(t, sub)
		})
	}

	rejected := []struct {
		name string
		body []byte
	}{
		{"empty body", nil},
		{"malformed json", []byte(`{"subscription":`)},
		{"two json objects", append(edit(func(_, _, _ map[string]any) {}), []byte(`{}`)...)},
		{"oversized body", append([]byte(`{"subscription":{"nfId":"`),
			append(bytes.Repeat([]byte("a"), 1<<20), `"}}`...)...)},
		{"empty eventList", edit(func(s, _, _ map[string]any) { s["eventList"] = []any{} })},
		{"two events", edit(func(s, e, _ map[string]any) { s["eventList"] = []any{e, e} })},
		{"trends event", edit(func(_, e, _ map[string]any) { e["type"] = "USER_DATA_USAGE_TRENDS" })},
		{"per application", edit(func(_, e, _ map[string]any) { e["granularityOfMeasurement"] = "PER_APPLICATION" })},
		{"missing granularity", edit(func(_, e, _ map[string]any) { delete(e, "granularityOfMeasurement") })},
		{"per session with appIds", edit(func(_, e, _ map[string]any) { e["appIds"] = []any{"app"} })},
		{"per session with filters", edit(func(_, e, _ map[string]any) {
			e["trafficFilters"] = []any{map[string]any{"flowDescription": "permit out ip from any to any"}}
		})},
		{"no measurementTypes", edit(func(_, e, _ map[string]any) { delete(e, "measurementTypes") })},
		{"app info measurement", edit(func(_, e, _ map[string]any) {
			e["measurementTypes"] = []any{"APPLICATION_RELATED_INFO"}
		})},
		{"relative notify uri", edit(func(s, _, _ map[string]any) { s["eventNotifyUri"] = "/notify" })},
		{"ftp notify uri", edit(func(s, _, _ map[string]any) { s["eventNotifyUri"] = "ftp://consumer/notify" })},
		{"missing notify uri", edit(func(s, _, _ map[string]any) { delete(s, "eventNotifyUri") })},
		{"on event trigger", edit(func(_, _, m map[string]any) { m["trigger"] = "ON_EVENT_DETECTION" })},
		{"missing trigger", edit(func(_, _, m map[string]any) { delete(m, "trigger") })},
		{"periodic without repPeriod", edit(func(_, _, m map[string]any) { delete(m, "repPeriod") })},
		{"periodic zero repPeriod", edit(func(_, _, m map[string]any) { m["repPeriod"] = 0 })},
		{"periodic negative repPeriod", edit(func(_, _, m map[string]any) { m["repPeriod"] = -5 })},
		{"periodic repPeriod over int32", edit(func(_, _, m map[string]any) { m["repPeriod"] = int64(1) << 31 })},
		{"anyUe and ueIp", edit(func(s, _, _ map[string]any) { s["anyUe"] = true })},
		{"neither anyUe nor ueIp", edit(func(s, _, _ map[string]any) { delete(s, "ueIpAddress") })},
		{"ipv6 only", edit(func(s, _, _ map[string]any) { s["ueIpAddress"] = map[string]any{"ipv6Addr": "2001:db8::1"} })},
		{"ipv4 plus ipv6 prefix", edit(func(s, _, _ map[string]any) {
			s["ueIpAddress"] = map[string]any{"ipv4Addr": "10.60.0.1", "ipv6Prefix": "2001:db8::/64"}
		})},
		{"invalid ipv4", edit(func(s, _, _ map[string]any) { s["ueIpAddress"] = map[string]any{"ipv4Addr": "10.60.0.300"} })},
		{"ipv6 in ipv4 field", edit(func(s, _, _ map[string]any) {
			s["ueIpAddress"] = map[string]any{"ipv4Addr": "2001:db8::1"}
		})},
		{"missing nfId", edit(func(s, _, _ map[string]any) { delete(s, "nfId") })},
		{"missing correlation id", edit(func(s, _, _ map[string]any) { delete(s, "notifyCorrelationId") })},
	}
	before := len(store.AllSubscriptions())
	for _, tc := range rejected {
		t.Run("reject/"+tc.name, func(t *testing.T) {
			rsp, body := do(t, http.MethodPost, api.URL+eeCollection, tc.body)
			require.Equal(t, http.StatusBadRequest, rsp.StatusCode, string(body))
			require.Empty(t, rsp.Header.Get("Location"))
		})
	}
	require.Len(t, store.AllSubscriptions(), before, "a rejected request must not create a subscription")

	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		rsp, _ := do(t, method, api.URL+eeCollection, nil)
		require.Equal(t, http.StatusMethodNotAllowed, rsp.StatusCode, method)
	}
}

// DELETE semantics and that the scheduler drops a deleted subscription.
func TestValidationAPIDeleteMatrix(t *testing.T) {
	store := NewSubscriptionStore("")
	agg := NewAggregator(store, NewNotifier(testLogger()), testLogger())
	api := httptest.NewServer(NewServer(store, testLogger()).Handler())
	defer api.Close()

	rsp, _ := do(t, http.MethodPost, api.URL+eeCollection, edit(func(_, _, _ map[string]any) {}))
	require.Equal(t, http.StatusCreated, rsp.StatusCode)
	loc := rsp.Header.Get("Location")
	id := strings.TrimPrefix(loc, api.URL+eeCollection+"/")

	for _, path := range []string{"", "/", "/unknown", "/" + id + "/extra", "/" + id + "/"} {
		r, _ := do(t, http.MethodDelete, api.URL+eeCollection+path, nil)
		require.Contains(t, []int{http.StatusNotFound, http.StatusMethodNotAllowed}, r.StatusCode, path)
	}
	for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodPut} {
		r, _ := do(t, method, loc, nil)
		require.Equal(t, http.StatusMethodNotAllowed, r.StatusCode, method)
	}
	_, ok := store.GetSubscription(id)
	require.True(t, ok, "wrong paths and methods must not delete")

	agg.PushReportWithContext(usageReport(SingleUPFMAQEURRID, 10), SessionContext{UeIPv4Addr: "10.60.0.1"})
	agg.mu.Lock()
	require.Len(t, agg.reportBuffer[id], 1)
	agg.mu.Unlock()

	rsp, _ = do(t, http.MethodDelete, loc, nil)
	require.Equal(t, http.StatusNoContent, rsp.StatusCode)
	rsp, _ = do(t, http.MethodDelete, loc, nil)
	require.Equal(t, http.StatusNotFound, rsp.StatusCode)

	sent, err := agg.TickOnce(context.Background())
	require.NoError(t, err)
	require.Zero(t, sent)
	agg.mu.Lock()
	require.NotContains(t, agg.reportBuffer, id, "buffer of a deleted subscription is dropped")
	agg.mu.Unlock()
}

type capturedNotify struct {
	subID  string
	header http.Header
	body   NotificationData
	raw    map[string]any
}

type consumer struct {
	mu     sync.Mutex
	got    []capturedNotify
	status []int // per-request status; 204 once exhausted
	srv    *httptest.Server
}

func newConsumer(t *testing.T, status ...int) *consumer {
	t.Helper()
	c := &consumer{status: status}
	c.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		var n capturedNotify
		require.NoError(t, json.Unmarshal(b, &n.body))
		require.NoError(t, json.Unmarshal(b, &n.raw))
		n.subID, n.header = r.Header.Get("X-EES-SubscriptionId"), r.Header.Clone()
		c.mu.Lock()
		code := http.StatusNoContent
		if len(c.status) > 0 {
			code, c.status = c.status[0], c.status[1:]
		}
		if code/100 == 2 {
			c.got = append(c.got, n)
		}
		c.mu.Unlock()
		w.WriteHeader(code)
	}))
	t.Cleanup(c.srv.Close)
	return c
}

func (c *consumer) notifications() []capturedNotify {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]capturedNotify(nil), c.got...)
}

var t0 = time.Date(2026, 10, 28, 1, 0, 0, 0, time.UTC)

func usar(urr uint32, from, to time.Duration, ul, dl, ulp, dlp uint64) report.USAReport {
	return report.USAReport{
		URRID: urr, StartTime: t0.Add(from), EndTime: t0.Add(to),
		VolumMeasure: report.VolumeMeasure{UplinkVolume: ul, DownlinkVolume: dl, UplinkPktNum: ulp, DownlinkPktNum: dlp},
	}
}

func sessReport(seid uint64, rs ...report.USAReport) report.SessReport {
	sr := report.SessReport{SEID: seid}
	for _, r := range rs {
		sr.Reports = append(sr.Reports, r)
	}
	return sr
}

// pushScenario feeds the same reports to every test: UE A has two URR 2
// periods plus URR 1 and an empty interval (both ignored); UE B has a
// zero-volume period; UE A also appears in a recycled SEID (new generation).
func pushScenario(agg *Aggregator) {
	a := SessionContext{RemoteSEID: 2, Generation: 1, UeIPv4Addr: "10.60.0.1", MeasurePeriod: 5 * time.Second}
	b := SessionContext{RemoteSEID: 1, Generation: 2, UeIPv4Addr: "10.60.0.2", MeasurePeriod: 5 * time.Second}
	agg.PushReportWithContext(sessReport(1,
		usar(2, 0, 5*time.Second, 1000, 3000, 10, 20),
		usar(1, 0, 5*time.Second, 99999, 99999, 99, 99),
		usar(2, 5*time.Second, 5*time.Second, 7777, 7777, 7, 7)), a)
	agg.PushReportWithContext(sessReport(1, usar(2, 5*time.Second, 10*time.Second, 500, 0, 5, 0)), a)
	agg.PushReportWithContext(sessReport(2, usar(2, 0, 10*time.Second, 0, 0, 0, 0)), b)
	// No UE identity: dropped, never attributed to anyone.
	agg.PushReportWithContext(sessReport(3, usar(2, 0, 10*time.Second, 1, 1, 1, 1)), SessionContext{RemoteSEID: 9})
}

// the exact notification body for each measurement type and target.
func TestValidationNotificationContentMatrix(t *testing.T) {
	volA := map[string]any{
		"totalVolume": "4500 B", "ulVolume": "1500 B", "dlVolume": "3000 B",
		"totalNbOfPackets": float64(35), "ulNbOfPackets": float64(15), "dlNbOfPackets": float64(20),
	}
	thrA := map[string]any{ // 10s window: 1500 B*8/10, 3000 B*8/10, 15/10, 20/10
		"ulThroughput": "1200 bps", "dlThroughput": "2400 bps",
		"ulPacketThroughput": "1.50 pps", "dlPacketThroughput": "2.00 pps",
	}
	volB := map[string]any{
		"totalVolume": "0 B", "ulVolume": "0 B", "dlVolume": "0 B",
		"totalNbOfPackets": float64(0), "ulNbOfPackets": float64(0), "dlNbOfPackets": float64(0),
	}
	cases := []struct {
		name   string
		mode   Mode
		target TargetScope
		types  []MeasurementType
		want   map[string][]string // ueIp -> measurement keys
	}{
		{
			"periodic ue A volume", ModePeriodic,
			TargetScope{UeIPAddress: "10.60.0.1"},
			[]MeasurementType{MeasureVolume},
			map[string][]string{"10.60.0.1": {"volumeMeasurement"}},
		},
		{
			"periodic ue A throughput", ModePeriodic,
			TargetScope{UeIPAddress: "10.60.0.1"},
			[]MeasurementType{MeasureThroughput},
			map[string][]string{"10.60.0.1": {"throughputMeasurement"}},
		},
		{
			"one time any ue both", ModeOnDemand,
			TargetScope{AnyUE: true},
			[]MeasurementType{MeasureVolume, MeasureThroughput},
			map[string][]string{
				"10.60.0.1": {"throughputMeasurement", "volumeMeasurement"},
				"10.60.0.2": {"throughputMeasurement", "volumeMeasurement"},
			},
		},
		{
			"one time ue B zero volume", ModeOnDemand,
			TargetScope{UeIPAddress: "10.60.0.2"},
			[]MeasurementType{MeasureVolume},
			map[string][]string{"10.60.0.2": {"volumeMeasurement"}},
		},
		{
			"other ue gets nothing", ModePeriodic,
			TargetScope{UeIPAddress: "10.60.0.9"},
			[]MeasurementType{MeasureVolume},
			nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newConsumer(t)
			store := NewSubscriptionStore("")
			sub := &Subscription{
				NotifURI: c.srv.URL + "/notify", NfID: "nf", NotifyCorrelationID: "corr-" + tc.name,
				Event: EventUserDataUsageMeasures, Granularity: GranularityPerSession, Mode: tc.mode, PeriodSec: 5,
				Target: tc.target, MeasurementTypes: tc.types,
			}
			id, err := store.CreateSubscription(sub)
			require.NoError(t, err)
			agg := NewAggregator(store, NewNotifier(testLogger()), testLogger())
			pushScenario(agg)
			sent, err := agg.TickOnce(context.Background())
			require.NoError(t, err)

			got := c.notifications()
			if tc.want == nil {
				require.Zero(t, sent)
				require.Empty(t, got)
				return
			}
			require.Equal(t, 1, sent)
			require.Len(t, got, 1)
			n := got[0]
			require.Equal(t, id, n.subID)
			require.Equal(t, "application/json", n.header.Get("Content-Type"))
			require.Equal(t, sub.NotifyCorrelationID, n.raw["correlationId"])
			items := n.raw["notificationItems"].([]any)
			require.Len(t, items, len(tc.want))
			for _, it := range items {
				item := it.(map[string]any)
				ip := item["ueIpv4Addr"].(string)
				require.Contains(t, tc.want, ip)
				require.Equal(t, "USER_DATA_USAGE_MEASURES", item["eventType"])
				require.Equal(t, t0.Format(time.RFC3339), item["startTime"], "earliest URR 2 start")
				require.NotEmpty(t, item["timeStamp"])
				ms := item["userDataUsageMeasurements"].([]any)
				require.Len(t, ms, 1)
				m := ms[0].(map[string]any)
				var keys []string
				for k := range m {
					keys = append(keys, k)
				}
				require.ElementsMatch(t, tc.want[ip], keys)
				if v, ok := m["volumeMeasurement"]; ok {
					require.Equal(t, map[string]any{"10.60.0.1": volA, "10.60.0.2": volB}[ip], v)
				}
				if v, ok := m["throughputMeasurement"]; ok && ip == "10.60.0.1" {
					require.Equal(t, thrA, v)
				}
			}
			_, exists := store.GetSubscription(id)
			require.Equal(t, tc.mode == ModePeriodic, exists, "ONE_TIME is removed after one delivery")
		})
	}
}

// a recycled local SEID with a new generation is a separate session item.
func TestValidationRecycledSEIDKeepsSessionsApart(t *testing.T) {
	c := newConsumer(t)
	store := NewSubscriptionStore("")
	sub := testSub()
	sub.NotifURI = c.srv.URL
	_, err := store.CreateSubscription(sub)
	require.NoError(t, err)
	agg := NewAggregator(store, NewNotifier(testLogger()), testLogger())
	for gen, ul := range map[uint64]uint64{1: 100, 2: 200} {
		agg.PushReportWithContext(sessReport(1, usar(2, 0, time.Second, ul, 0, 1, 0)),
			SessionContext{RemoteSEID: 2, Generation: gen, UeIPv4Addr: "10.60.0.1"})
	}
	_, err = agg.TickOnce(context.Background())
	require.NoError(t, err)
	got := c.notifications()
	require.Len(t, got, 1)
	var uls []string
	for _, item := range got[0].body.NotificationItems {
		uls = append(uls, item.UserDataUsageMeasurements[0].VolumeMeasurement.UlVolume)
	}
	require.ElementsMatch(t, []string{"100 B", "200 B"}, uls)
}

// when a PERIODIC batch is due for every relation of requested period,
// URR base period and collected span.
func TestValidationPeriodicDueTable(t *testing.T) {
	last := t0
	now := t0.Add(3 * time.Second)
	batch := func(base, span time.Duration) map[SessionKey]*UsageMeasures {
		return map[SessionKey]*UsageMeasures{{LocalSEID: 1}: {StartTime: t0, EndTime: t0.Add(span), MeasurePeriod: base}}
	}
	s := time.Second
	cases := []struct {
		name                  string
		requested, base, span time.Duration
		want                  time.Time
	}{
		{"no periodic URR uses repPeriod", 7 * s, 0, 30 * s, last.Add(7 * s)},
		{"equal periods, one report collected", 5 * s, 5 * s, 5 * s, now},
		{"7 over base 5 waits for 10s of data", 7 * s, 5 * s, 5 * s, last.Add(10*s + 2500*time.Millisecond)},
		{"7 over base 5 sends at 10s span", 7 * s, 5 * s, 10 * s, now},
		{"requested below base rounds to base", 3 * s, 5 * s, 5 * s, now},
		{"11 over base 5 needs 15s", 11 * s, 5 * s, 10 * s, last.Add(15*s + 2500*time.Millisecond)},
		{"11 over base 5 sends at 15s span", 11 * s, 5 * s, 15 * s, now},
		{"half a base of jitter is tolerated", 10 * s, 5 * s, 7500 * time.Millisecond, now},
		{"60 over base 10 at threshold", 60 * s, 10 * s, 55 * s, now},
		{"60 over base 10 below threshold", 60 * s, 10 * s, 50 * s, last.Add(65 * s)},
	}
	for _, tc := range cases {
		require.Equal(t, tc.want, periodicDue(last, tc.requested, batch(tc.base, tc.span), now), tc.name)
	}
}

// the whole subscription lifecycle against one consumer, over the API:
// create -> notify -> failed delivery keeps data -> retry merges -> delete ->
// nothing more is sent.
func TestValidationPeriodicLifecycleWithRetryAndDelete(t *testing.T) {
	c := newConsumer(t, http.StatusNoContent, http.StatusInternalServerError, http.StatusOK)
	store := NewSubscriptionStore("")
	agg := NewAggregator(store, NewNotifier(testLogger()), testLogger())
	api := httptest.NewServer(NewServer(store, testLogger()).Handler())
	defer api.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { agg.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()

	rsp, body := do(t, http.MethodPost, api.URL+eeCollection, edit(func(s, _, m map[string]any) {
		s["eventNotifyUri"] = c.srv.URL + "/notify"
		m["repPeriod"] = 1
	}))
	require.Equal(t, http.StatusCreated, rsp.StatusCode, string(body))
	loc := rsp.Header.Get("Location")
	ue := SessionContext{RemoteSEID: 2, Generation: 1, UeIPv4Addr: "10.60.0.1", MeasurePeriod: time.Second}
	push := func(ul uint64) {
		end := time.Now()
		agg.PushReportWithContext(report.SessReport{SEID: 1, Reports: []report.Report{report.USAReport{
			URRID: 2, StartTime: end.Add(-time.Second), EndTime: end, VolumMeasure: report.VolumeMeasure{UplinkVolume: ul},
		}}}, ue)
	}
	waitFor := func(n int) []capturedNotify {
		require.Eventually(t, func() bool { return len(c.notifications()) >= n }, 5*time.Second, 20*time.Millisecond)
		return c.notifications()
	}

	push(100)
	got := waitFor(1)
	require.Equal(t, "100 B", got[0].body.NotificationItems[0].UserDataUsageMeasurements[0].VolumeMeasurement.UlVolume)

	push(200) // consumer answers 500: kept and retried after >= 1s
	time.Sleep(200 * time.Millisecond)
	push(300) // arrives while the retry is pending: merged into it
	start := time.Now()
	got = waitFor(2)
	require.GreaterOrEqual(t, time.Since(start), 700*time.Millisecond, "retry is delayed, not a busy loop")
	require.Len(t, got, 2)
	require.Equal(t, "500 B", got[1].body.NotificationItems[0].UserDataUsageMeasurements[0].VolumeMeasurement.UlVolume)

	rsp, _ = do(t, http.MethodDelete, loc, nil)
	require.Equal(t, http.StatusNoContent, rsp.StatusCode)
	push(400)
	time.Sleep(1500 * time.Millisecond)
	require.Len(t, c.notifications(), 2, "no notification after DELETE")
}
