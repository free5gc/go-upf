package pfcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	"github.com/free5gc/go-upf/internal/ees"
	"github.com/free5gc/go-upf/internal/report"
)

type e2eConsumer struct {
	mu    sync.Mutex
	items []ees.NotificationItem
	posts int
	srv   *httptest.Server
}

// newE2EConsumer answers with status; status 0 blocks until the request is
// cancelled, like a subscriber that never responds.
func newE2EConsumer(t *testing.T, status int) *e2eConsumer {
	t.Helper()
	c := &e2eConsumer{}
	c.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var n ees.NotificationData
		if err := json.NewDecoder(r.Body).Decode(&n); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		c.mu.Lock()
		c.posts++
		if status/100 == 2 {
			c.items = append(c.items, n.NotificationItems...)
		}
		c.mu.Unlock()
		if status == 0 {
			<-r.Context().Done()
			return
		}
		w.WriteHeader(status)
	}))
	t.Cleanup(c.srv.Close)
	return c
}

func (c *e2eConsumer) snapshot() (posts int, items []ees.NotificationItem) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.posts, append([]ees.NotificationItem(nil), c.items...)
}

type volume struct{ ul, dl uint64 }

func parseBytes(t *testing.T, s string) uint64 {
	t.Helper()
	var v uint64
	_, err := fmt.Sscanf(s, "%d B", &v)
	require.NoError(t, err, s)
	return v
}

func subscribe(t *testing.T, api, notify string, mutate func(sub, mode map[string]any)) string {
	t.Helper()
	loc, err := trySubscribe(api, notify, mutate)
	require.NoError(t, err)
	return loc
}

// trySubscribe does not use require, so it is safe off the test goroutine.
func trySubscribe(api, notify string, mutate func(sub, mode map[string]any)) (string, error) {
	sub := map[string]any{
		"nfId": "smf-e2e", "eventNotifyUri": notify, "notifyCorrelationId": "corr",
		"eventList": []any{map[string]any{
			"type": "USER_DATA_USAGE_MEASURES", "granularityOfMeasurement": "PER_SESSION",
			"measurementTypes": []any{"VOLUME_MEASUREMENT", "THROUGHPUT_MEASUREMENT"},
		}},
		"anyUe": true,
	}
	mode := map[string]any{"trigger": "PERIODIC", "repPeriod": 1}
	sub["eventReportingMode"] = mode
	if mutate != nil {
		mutate(sub, mode)
	}
	body, err := json.Marshal(map[string]any{"subscription": sub})
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		api+"/nupf-ee/v1/ee-subscriptions", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	rsp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	b, err := io.ReadAll(rsp.Body)
	if closeErr := rsp.Body.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return "", err
	}
	if rsp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("create: %d %s", rsp.StatusCode, b)
	}
	return rsp.Header.Get("Location"), nil
}

func unsubscribe(loc string) (int, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodDelete, loc, nil)
	if err != nil {
		return 0, err
	}
	rsp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	return rsp.StatusCode, rsp.Body.Close()
}

// V4: the real PFCP server and the real EES stack (API, store, aggregator,
// notifier) run together. With healthy, failing, hanging and unrelated
// subscribers plus concurrent subscribe/delete churn, the SMF must still see
// exactly the upstream golden, and EES must deliver every URR 2 byte it was
// handed, per UE, to the healthy subscriber.
func TestValidationEndToEndSMFUnaffectedByLiveEES(t *testing.T) {
	healthy := newE2EConsumer(t, http.StatusNoContent)
	oneTime := newE2EConsumer(t, http.StatusOK)
	failing := newE2EConsumer(t, http.StatusInternalServerError)
	hanging := newE2EConsumer(t, 0)
	unrelated := newE2EConsumer(t, http.StatusNoContent)

	var mu sync.Mutex
	handed := map[string]volume{} // URR 2 usage EES received, per UE
	var store *ees.SubscriptionStore
	var oneTimeLoc, failingLoc string
	var churned atomic.Int64

	trace := runPFCPParityScenario(t, func(s *PfcpServer) {
		log := logrus.New()
		log.SetOutput(io.Discard)
		entry := logrus.NewEntry(log)
		store = ees.NewSubscriptionStore("")
		agg := ees.NewAggregator(store, ees.NewNotifier(entry), entry)
		api := httptest.NewServer(ees.NewServer(store, entry).Handler())
		ctx, cancel := context.WithCancel(context.Background())
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); agg.Run(ctx) }()
		// Churn: subscriptions created and deleted while PFCP runs.
		go func() {
			defer wg.Done()
			for ctx.Err() == nil {
				loc, err := trySubscribe(api.URL, unrelated.srv.URL, func(sub, _ map[string]any) {
					delete(sub, "anyUe")
					sub["ueIpAddress"] = map[string]any{"ipv4Addr": "10.60.0.8"}
				})
				if err == nil {
					var code int
					if code, err = unsubscribe(loc); err == nil && code != http.StatusNoContent {
						err = fmt.Errorf("delete: %d", code)
					}
				}
				if err != nil && !errors.Is(err, context.Canceled) && ctx.Err() == nil {
					t.Errorf("churn: %v", err)
					return
				}
				churned.Add(1)
			}
		}()
		t.Cleanup(func() { cancel(); wg.Wait(); api.Close() })

		subscribe(t, api.URL, healthy.srv.URL, nil)
		oneTimeLoc = subscribe(t, api.URL, oneTime.srv.URL, func(sub, mode map[string]any) {
			delete(sub, "anyUe")
			sub["ueIpAddress"] = map[string]any{"ipv4Addr": "10.60.0.2"}
			mode["trigger"] = "ONE_TIME"
		})
		failingLoc = subscribe(t, api.URL, failing.srv.URL, nil)
		subscribe(t, api.URL, hanging.srv.URL, nil)
		subscribe(t, api.URL, unrelated.srv.URL, func(sub, _ map[string]any) {
			delete(sub, "anyUe")
			sub["ueIpAddress"] = map[string]any{"ipv4Addr": "10.60.0.9"}
		})

		s.RegisterEESReportHandler(func(sr report.SessReport, identity ees.SessionContext) {
			mu.Lock()
			for _, r := range sr.Reports {
				u := r.(report.USAReport)
				if u.URRID == ees.SingleUPFMAQEURRID && u.EndTime.After(u.StartTime) {
					v := handed[identity.UeIPv4Addr]
					v.ul += u.VolumMeasure.UplinkVolume
					v.dl += u.VolumMeasure.DownlinkVolume
					handed[identity.UeIPv4Addr] = v
				}
			}
			mu.Unlock()
			agg.PushReportWithContext(sr, identity)
		})
	})

	want, err := os.ReadFile(pfcpParityGolden)
	require.NoError(t, err)
	require.Equal(t, string(want), strings.Join(trace, "\n")+"\n", "SMF-facing PFCP changed")

	mu.Lock()
	expected := map[string]volume{}
	for k, v := range handed {
		expected[k] = v
	}
	mu.Unlock()
	require.Len(t, expected, 2, "both UEs produced URR 2 usage")

	// URR 2 has a 10s PERIO period, so repPeriod 1 rounds up to 10s and the
	// final partial batch after deletion is sent at 10s + 5s.
	sum := func(items []ees.NotificationItem) map[string]volume {
		got := map[string]volume{}
		for _, it := range items {
			v := got[it.UeIpv4Addr]
			vm := it.UserDataUsageMeasurements[0].VolumeMeasurement
			v.ul += parseBytes(t, vm.UlVolume)
			v.dl += parseBytes(t, vm.DlVolume)
			got[it.UeIpv4Addr] = v
		}
		return got
	}
	require.Eventually(t, func() bool {
		_, items := healthy.snapshot()
		return assertEqualMaps(sum(items), expected)
	}, 25*time.Second, 100*time.Millisecond, "healthy subscriber must get every URR 2 byte")
	_, items := healthy.snapshot()
	for _, it := range items {
		require.NotNil(t, it.UserDataUsageMeasurements[0].ThroughputMeasurement)
	}

	posts, items := oneTime.snapshot()
	require.Equal(t, 1, posts, "ONE_TIME notifies once")
	require.Len(t, items, 1)
	require.Equal(t, "10.60.0.2", items[0].UeIpv4Addr)
	code, err := unsubscribe(oneTimeLoc)
	require.NoError(t, err)
	require.Equal(t, http.StatusNotFound, code, "ONE_TIME removed after delivery")

	posts, _ = failing.snapshot()
	require.Positive(t, posts, "failing subscriber was attempted")
	code, err = unsubscribe(failingLoc)
	require.NoError(t, err)
	require.Equal(t, http.StatusNoContent, code, "a failing subscriber keeps its subscription")

	posts, _ = hanging.snapshot()
	require.Positive(t, posts)
	_, items = unrelated.snapshot()
	require.Empty(t, items, "no usage for a UE without a session")
	require.Positive(t, churned.Load(), "subscriptions were churned during PFCP traffic")
}

func assertEqualMaps(a, b map[string]volume) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range b {
		if a[k] != v {
			return false
		}
	}
	return true
}
