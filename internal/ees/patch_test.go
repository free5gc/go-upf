package ees

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func doPatch(t *testing.T, url, contentType, body string) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPatch, url, bytes.NewReader([]byte(body)))
	require.NoError(t, err)
	req.Header.Set("Content-Type", contentType)
	rsp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { require.NoError(t, rsp.Body.Close()) }()
	b, err := io.ReadAll(rsp.Body)
	require.NoError(t, err)
	var problem map[string]any
	if len(b) > 0 {
		require.Equal(t, "application/problem+json", rsp.Header.Get("Content-Type"))
		require.NoError(t, json.Unmarshal(b, &problem))
	}
	return rsp.StatusCode, problem
}

func createForPatch(t *testing.T, api *httptest.Server, body []byte) (string, string) {
	t.Helper()
	rsp, b := do(t, http.MethodPost, api.URL+eeCollection, body)
	require.Equal(t, http.StatusCreated, rsp.StatusCode, string(b))
	loc := rsp.Header.Get("Location")
	return loc, strings.TrimPrefix(loc, api.URL+eeCollection+"/")
}

const jsonPatch = "application/json-patch+json"

// TS 29.564 5.2.2.2.3: the events, the event report options and the NF Id can
// be modified. The ID, target and measurement source stay the same.
func TestPatchSubscriptionModifiesEventsReportingAndNfID(t *testing.T) {
	store := NewSubscriptionStore("")
	server := NewServer(store, testLogger())
	server.UseMeasurementSource(SourceUPFURR)
	api := httptest.NewServer(server.Handler())
	defer api.Close()
	loc, id := createForPatch(t, api, edit(func(_, _, _ map[string]any) {}))
	before, _ := store.GetSubscription(id)

	status, problem := doPatch(t, loc, jsonPatch, `[
		{"op":"replace","path":"/eventReportingMode/repPeriod","value":10},
		{"op":"replace","path":"/nfId","value":"nwdaf-1"},
		{"op":"add","path":"/eventList/0/measurementTypes/-","value":"THROUGHPUT_MEASUREMENT"}
	]`)
	require.Equal(t, http.StatusNoContent, status, problem)

	after, ok := store.GetSubscription(id)
	require.True(t, ok)
	require.NotSame(t, before, after, "a PATCH replaces the subscription, it does not edit it in place")
	require.Equal(t, 10, after.PeriodSec)
	require.Equal(t, "nwdaf-1", after.NfID)
	require.Equal(t, []MeasurementType{MeasureVolume, MeasureThroughput}, after.MeasurementTypes)
	require.Equal(t, before.ID, after.ID)
	require.Equal(t, before.CreatedAt, after.CreatedAt)
	require.Equal(t, before.LastNotify, after.LastNotify)
	require.Equal(t, before.Target, after.Target)
	require.Equal(t, SourceUPFURR, after.Source)
	require.Equal(t, "nwdaf-1", after.Resource.NfID)
	require.Len(t, store.AllSubscriptions(), 1)

	// The whole reporting mode can be replaced too.
	status, problem = doPatch(t, loc, jsonPatch,
		`[{"op":"replace","path":"/eventReportingMode","value":{"trigger":"ONE_TIME"}}]`)
	require.Equal(t, http.StatusNoContent, status, problem)
	after, _ = store.GetSubscription(id)
	require.Equal(t, ModeOnDemand, after.Mode)
}

// Every rejected PATCH leaves the stored subscription untouched.
func TestPatchSubscriptionRejectsWithoutChange(t *testing.T) {
	store := NewSubscriptionStore("")
	api := httptest.NewServer(NewServer(store, testLogger()).Handler())
	defer api.Close()
	loc, id := createForPatch(t, api, edit(func(sub, _, _ map[string]any) { sub["dnn"] = "internet" }))
	before, _ := store.GetSubscription(id)

	for _, tc := range []struct {
		name, contentType, body, cause string
		status                         int
	}{
		{
			"target ue", jsonPatch, `[{"op":"replace","path":"/ueIpAddress/ipv4Addr","value":"10.60.0.9"}]`,
			"MODIFICATION_NOT_ALLOWED", http.StatusForbidden,
		},
		{
			"any ue", jsonPatch, `[{"op":"add","path":"/anyUe","value":true}]`,
			"MODIFICATION_NOT_ALLOWED", http.StatusForbidden,
		},
		{
			"notify uri", jsonPatch, `[{"op":"replace","path":"/eventNotifyUri","value":"http://other.invalid/n"}]`,
			"MODIFICATION_NOT_ALLOWED", http.StatusForbidden,
		},
		{
			"correlation id", jsonPatch, `[{"op":"replace","path":"/notifyCorrelationId","value":"c2"}]`,
			"MODIFICATION_NOT_ALLOWED", http.StatusForbidden,
		},
		{
			"move out of target", jsonPatch, `[{"op":"move","from":"/dnn","path":"/nfId"}]`,
			"MODIFICATION_NOT_ALLOWED", http.StatusForbidden,
		},
		{
			"allowed item before a forbidden one", jsonPatch,
			`[{"op":"replace","path":"/nfId","value":"x"},{"op":"remove","path":"/dnn"}]`,
			"MODIFICATION_NOT_ALLOWED", http.StatusForbidden,
		},
		{
			"zero period", jsonPatch, `[{"op":"replace","path":"/eventReportingMode/repPeriod","value":0}]`,
			"INVALID_REQUEST", http.StatusBadRequest,
		},
		{
			"unknown trigger", jsonPatch, `[{"op":"replace","path":"/eventReportingMode/trigger","value":"ON_EVENT"}]`,
			"INVALID_REQUEST", http.StatusBadRequest,
		},
		{
			"unsupported event", jsonPatch, `[{"op":"replace","path":"/eventList/0/type","value":"USER_DATA_USAGE_TRENDS"}]`,
			"INVALID_REQUEST", http.StatusBadRequest,
		},
		{
			"remove nf id", jsonPatch, `[{"op":"remove","path":"/nfId"}]`,
			"INVALID_REQUEST", http.StatusBadRequest,
		},
		{
			"unknown field", jsonPatch, `[{"op":"add","path":"/eventList/0/foo","value":1}]`,
			"INVALID_REQUEST", http.StatusBadRequest,
		},
		{
			"failed test", jsonPatch,
			`[{"op":"test","path":"/nfId","value":"other"},{"op":"replace","path":"/nfId","value":"x"}]`,
			"INVALID_REQUEST", http.StatusBadRequest,
		},
		{
			"missing path", jsonPatch, `[{"op":"replace","path":"/eventList/3/type","value":"x"}]`,
			"INVALID_REQUEST", http.StatusBadRequest,
		},
		{
			"unknown op", jsonPatch, `[{"op":"merge","path":"/nfId","value":"x"}]`,
			"INVALID_MSG_FORMAT", http.StatusBadRequest,
		},
		{"empty array", jsonPatch, `[]`, "INVALID_MSG_FORMAT", http.StatusBadRequest},
		{"not an array", jsonPatch, `{"nfId":"x"}`, "INVALID_MSG_FORMAT", http.StatusBadRequest},
		{
			"merge patch body", "application/json", `[{"op":"replace","path":"/nfId","value":"x"}]`,
			"", http.StatusUnsupportedMediaType,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, problem := doPatch(t, loc, tc.contentType, tc.body)
			require.Equal(t, tc.status, status, problem)
			require.EqualValues(t, tc.status, problem["status"])
			if tc.cause != "" {
				require.Equal(t, tc.cause, problem["cause"])
			}
			after, ok := store.GetSubscription(id)
			require.True(t, ok)
			require.Same(t, before, after)
		})
	}

	status, problem := doPatch(t, api.URL+eeCollection+"/unknown", jsonPatch,
		`[{"op":"replace","path":"/nfId","value":"x"}]`)
	require.Equal(t, http.StatusNotFound, status)
	require.Equal(t, "SUBSCRIPTION_NOT_FOUND", problem["cause"])
}

// Measurements buffered before a PATCH are kept and sent under the new
// reporting mode; a one-time subscription is removed after delivery.
func TestPatchedSubscriptionKeepsPendingMeasurements(t *testing.T) {
	c := newConsumer(t)
	store := NewSubscriptionStore("")
	agg := NewAggregator(store, NewNotifier(testLogger()), testLogger())
	api := httptest.NewServer(NewServer(store, testLogger()).Handler())
	defer api.Close()
	loc, id := createForPatch(t, api, edit(func(sub, _, mode map[string]any) {
		sub["eventNotifyUri"] = c.srv.URL
		mode["repPeriod"] = 3600
	}))

	agg.PushReportWithContext(usageReport(SingleUPFMAQEURRID, 10), SessionContext{UeIPv4Addr: "10.60.0.1"})
	sent, err := agg.TickOnce(context.Background())
	require.NoError(t, err)
	require.Zero(t, sent, "the hourly period is not due yet")

	status, problem := doPatch(t, loc, jsonPatch,
		`[{"op":"replace","path":"/eventReportingMode","value":{"trigger":"ONE_TIME"}}]`)
	require.Equal(t, http.StatusNoContent, status, problem)

	sent, err = agg.TickOnce(context.Background())
	require.NoError(t, err)
	require.Equal(t, 1, sent)
	got := c.notifications()
	require.Len(t, got, 1)
	require.Equal(t, id, got[0].subID)
	_, ok := store.GetSubscription(id)
	require.False(t, ok, "a one-time subscription is removed after delivery")
}
