package ees

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"gopkg.in/h2non/gock.v1"
)

func TestNotifier_Notify(t *testing.T) {
	defer gock.Off()

	logger := logrus.NewEntry(logrus.New())
	notifier := NewNotifier(logger)
	gock.InterceptClient(notifier.httpClient)

	sub := &Subscription{
		ID:                  "sub-123",
		Event:               EventUserDataUsageMeasures,
		NotifURI:            "http://subscriber:8080/callback",
		NotifyCorrelationID: "corr-123",
		MeasurementTypes:    []MeasurementType{MeasureVolume},
	}

	measures := []UsageMeasures{
		{
			UeIpv4Addr:     "10.0.0.1",
			StartTime:      time.Now().Add(-10 * time.Second),
			EndTime:        time.Now(),
			ULBytesDelta:   1000,
			DLBytesDelta:   2000,
			ULPacketsDelta: 10,
			DLPacketsDelta: 20,
		},
	}

	t.Run("SuccessfulNotification", func(t *testing.T) {
		gock.New("http://subscriber:8080").
			Post("/callback").
			Reply(200).
			BodyString("OK")

		err := notifier.Notify(sub, measures)
		assert.NoError(t, err)
		assert.True(t, gock.IsDone())
	})

	t.Run("CheckPayloadStructure", func(t *testing.T) {
		gock.New("http://subscriber:8080").
			Post("/callback").
			MatchHeader("Content-Type", "application/json").
			// Check correlationId field in JSON body
			Filter(func(req *http.Request) bool {
				var data map[string]interface{}
				body, err := io.ReadAll(req.Body)
				if err != nil {
					return false
				}
				req.Body = io.NopCloser(bytes.NewBuffer(body))
				if err := json.Unmarshal(body, &data); err != nil {
					return false
				}
				return data["correlationId"] == "corr-123"
			}).
			Reply(204)

		err := notifier.Notify(sub, measures)
		assert.NoError(t, err)
		assert.True(t, gock.IsDone())
	})

	t.Run("HandleHttpError", func(t *testing.T) {
		gock.New("http://subscriber:8080").
			Post("/callback").
			Reply(500).
			BodyString("Internal Server Error")

		err := notifier.Notify(sub, measures)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "non-2xx response")
		assert.True(t, gock.IsDone())
	})
}
