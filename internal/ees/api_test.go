package ees

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleCreateSubscription(t *testing.T) {
	logger := logrus.NewEntry(logrus.New())
	store := NewSubscriptionStore("")
	// Aggregator can be nil for basic API validation testing if we don't hit ModeOnDemand
	server := NewServer(store, nil, logger)

	t.Run("ValidPeriodicSubscription", func(t *testing.T) {
		reqBody := createSubscriptionRequest{
			Subscription: UpfEventSubscription{
				NfID:                "test-nf",
				EventNotifyURI:      "http://localhost:9999/notify",
				NotifyCorrelationID: "test-corr",
				EventList: []UpfEvent{
					{
						Type:                     "USER_DATA_USAGE_MEASURES",
						GranularityOfMeasurement: "PER_SESSION",
						MeasurementTypes:         []string{"VOLUME_MEASUREMENT"},
					},
				},
				EventReportingMode: UpfEventMode{
					Trigger:      "PERIODIC",
					ReportPeriod: 10,
				},
				AnyUE: true,
			},
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)
		req := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodPost,
			"/nupf-ee/v1/ee-subscriptions",
			bytes.NewReader(body),
		)
		rr := httptest.NewRecorder()

		server.handleCreateSubscription(rr, req)

		assert.Equal(t, http.StatusCreated, rr.Code)
		var resp createSubscriptionResponse
		err = json.Unmarshal(rr.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.NotEmpty(t, resp.SubscriptionID)

		// Check if it was actually added to store
		_, ok := store.GetSubscription(resp.SubscriptionID)
		assert.True(t, ok)
	})

	t.Run("UnsupportedEventType", func(t *testing.T) {
		reqBody := createSubscriptionRequest{
			Subscription: UpfEventSubscription{
				EventList: []UpfEvent{
					{
						Type: "QOS_MONITORING", // Not supported in current MVP
					},
				},
			},
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)
		req := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodPost,
			"/nupf-ee/v1/ee-subscriptions",
			bytes.NewReader(body),
		)
		rr := httptest.NewRecorder()

		server.handleCreateSubscription(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
		assert.Contains(t, rr.Body.String(), "unsupported event type")
	})

	t.Run("MissingEventList", func(t *testing.T) {
		reqBody := createSubscriptionRequest{
			Subscription: UpfEventSubscription{
				EventList: []UpfEvent{},
			},
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)
		req := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodPost,
			"/nupf-ee/v1/ee-subscriptions",
			bytes.NewReader(body),
		)
		rr := httptest.NewRecorder()

		server.handleCreateSubscription(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
		assert.Contains(t, rr.Body.String(), "eventList must not be empty")
	})

	t.Run("UnsupportedGranularity", func(t *testing.T) {
		reqBody := createSubscriptionRequest{
			Subscription: UpfEventSubscription{
				EventList: []UpfEvent{
					{
						Type:                     "USER_DATA_USAGE_MEASURES",
						GranularityOfMeasurement: "PER_APPLICATION", // Not supported in current MVP
					},
				},
			},
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)
		req := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodPost,
			"/nupf-ee/v1/ee-subscriptions",
			bytes.NewReader(body),
		)
		rr := httptest.NewRecorder()

		server.handleCreateSubscription(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
		assert.Contains(t, rr.Body.String(), "unsupported granularity")
	})

	t.Run("DeleteSubscription", func(t *testing.T) {
		sub := &Subscription{
			NotifURI:            "http://test",
			Event:               EventUserDataUsageMeasures,
			Granularity:         GranularityPerSession,
			Mode:                ModePeriodic,
			PeriodSec:           10,
			NfID:                "test",
			NotifyCorrelationID: "test",
		}
		id, err := store.CreateSubscription(sub)
		require.NoError(t, err)

		req := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodDelete,
			"/nupf-ee/v1/ee-subscriptions/"+id,
			nil,
		)
		rr := httptest.NewRecorder()

		server.handleDeleteSubscriptionByID(rr, req)

		assert.Equal(t, http.StatusNoContent, rr.Code)
		_, ok := store.GetSubscription(id)
		assert.False(t, ok)
	})
}
