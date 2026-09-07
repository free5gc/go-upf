package ees

import (
	"context"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/h2non/gock.v1"
)

func TestModeOnDemandLifecycle(t *testing.T) {
	defer gock.Off()
	logger := logrus.NewEntry(logrus.New())
	store := NewSubscriptionStore("")
	notifier := NewNotifier(logger)
	gock.InterceptClient(notifier.httpClient)

	// Mock Aggregator dependencies
	aggregator := NewAggregator(store, 10*time.Second, notifier, logger, nil, nil)

	sub := &Subscription{
		NotifURI:            "http://subscriber:8080/callback",
		NotifyCorrelationID: "corr-ondemand",
		Event:               EventUserDataUsageMeasures,
		Granularity:         GranularityPerSession,
		Mode:                ModeOnDemand,
		MeasurementTypes:    []MeasurementType{MeasureVolume},
		NfID:                "nf-ondemand",
	}
	id, err := store.CreateSubscription(sub)
	require.NoError(t, err)

	t.Run("OnDemandWithData_ShouldNotifyAndDelete", func(t *testing.T) {
		// 1. Manually inject data into aggregator buffer
		aggregator.mu.Lock()
		aggregator.reportBuffer[id] = map[SessionKey]*UsageMeasures{
			{LocalSEID: 1}: {
				Key:          SessionKey{LocalSEID: 1},
				ULBytesDelta: 100,
				DLBytesDelta: 200,
				StartTime:    time.Now().Add(-5 * time.Second),
				EndTime:      time.Now(),
				UeIpv4Addr:   "10.0.0.1",
			},
		}
		aggregator.mu.Unlock()

		// 2. Mock the callback
		gock.New("http://subscriber:8080").
			Post("/callback").
			Reply(204)

		// 3. Trigger TickOnce
		n, err := aggregator.TickOnce(context.Background())
		assert.NoError(t, err)
		assert.Equal(t, 1, n)

		// 4. Verify subscription is deleted
		_, exists := store.GetSubscription(id)
		assert.False(t, exists, "Subscription should be implicitly deleted after successful report")
		assert.True(t, gock.IsDone())
	})

	t.Run("OnDemandEmptyBuffer_ShouldSendZeroReportAndDelete", func(t *testing.T) {
		// Mock SessionProvider to return an active session
		mockProvider := &mockSessionProvider{
			sessions: map[uint64]SessionContext{
				10: {UeIPv4Addr: "10.60.0.1", RemoteSEID: 99},
			},
		}
		aggregator.sessionProvider = mockProvider

		// Create a new ONE_TIME subscription targeting the UE
		sub2 := &Subscription{
			NotifURI:            "http://subscriber:8080/callback-zero",
			NotifyCorrelationID: "corr-zero",
			Event:               EventUserDataUsageMeasures,
			Granularity:         GranularityPerSession,
			Mode:                ModeOnDemand,
			MeasurementTypes:    []MeasurementType{MeasureVolume},
			NfID:                "nf-ondemand",
			Target: TargetScope{
				UeIPAddress: "10.60.0.1",
			},
		}
		id2, err := store.CreateSubscription(sub2)
		require.NoError(t, err)
		_ = id2 // id2 is used implicitly via store lookup in TickOnce

		// Mock the callback for zero report
		gock.New("http://subscriber:8080").
			Post("/callback-zero").
			Reply(204)

		// Trigger TickOnce with empty buffer
		n, err := aggregator.TickOnce(context.Background())
		assert.NoError(t, err)
		assert.Equal(t, 1, n, "Should have sent 1 zero-value report")

		// Verify subscription is deleted
		_, exists := store.GetSubscription(id2)
		assert.False(t, exists, "Subscription should be implicitly deleted even with zero report")
		assert.True(t, gock.IsDone())
	})
}

type mockSessionProvider struct {
	sessions map[uint64]SessionContext
}

func (m *mockSessionProvider) GetSessionContexts() map[uint64]SessionContext {
	return m.sessions
}

func (m *mockSessionProvider) GetSessionContextUEIP(lSeid uint64) (string, bool) {
	ctx, ok := m.sessions[lSeid]
	return ctx.UeIPv4Addr, ok
}
