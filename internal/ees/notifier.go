// Package ees - UPF Event Exposure Service (EES)
// notifier.go: deliver EES Notify payloads to subscriber endpoints.
//
// Behavior (MVP):
// - Sends USER_DATA_USAGE_MEASURES notifications to sub.NotifURI via HTTP POST.
// - Payload contains subscription ID, event ID, granularity, and a list of items,
//   each item includes LocalSEID, RemoteSEID, UL/DL bytes/packets, StartTime/EndTime,
//   and optional derived throughputs.
// - Uses a per-request timeout; no retry (keep it simple for MVP).
// - Logs both success and failure with descriptive fields.

package ees

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
)

// Notifier is responsible for delivering EES notifications to subscribers.
type Notifier struct {
	httpClient         *http.Client
	logger             *logrus.Entry
	defaultUserAgent   string
	requestTimeout     time.Duration
	maxResponseBodyLen int64
}

// NewNotifier creates a notifier with same defaults.
// - request timeout: 5s
// - connect + TLS handshake timeouts are governed by the http.Transport below.
func NewNotifier(logger *logrus.Entry) *Notifier {
	transport := &http.Transport{
		// Reasonable defaults for a control-plane style HTTP call.
		DialContext: (&net.Dialer{
			Timeout:   3 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          64,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   3 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	return &Notifier{
		httpClient: &http.Client{
			Transport: transport,
		},
		logger:             logger,
		defaultUserAgent:   "go-upf-ees/notify",
		requestTimeout:     5 * time.Second,
		maxResponseBodyLen: 4 << 10, // 4 KiB cap when logging response bodies
	}
}

// NotificationData per TS 29.564 schema.
type NotificationData struct {
	NotificationItems []NotificationItem `json:"notificationItems"`
	CorrelationId     string             `json:"correlationId,omitempty"`
}

// NotificationItem per TS 29.564 schema.
type NotificationItem struct {
	// Required fields
	EventType string    `json:"eventType"`
	TimeStamp time.Time `json:"timeStamp"`

	// Conditional: one of ueIpv4Addr, ueIpv6Prefix, or ueMacAddr must be present
	UeIpv4Addr string `json:"ueIpv4Addr,omitempty"`

	// Optional fields
	Supi      string     `json:"supi,omitempty"`
	StartTime *time.Time `json:"startTime,omitempty"`

	// Measurements array per TS 29.564
	UserDataUsageMeasurements []UserDataUsageMeasurements `json:"userDataUsageMeasurements,omitempty"`
}

// Notify converts a set of UsageMeasures into a POST request per TS 29.564.
func (notifier *Notifier) Notify(subscription *Subscription, measures []UsageMeasures) error {
	if subscription == nil {
		return fmt.Errorf("notify: subscription is nil")
	}
	if subscription.NotifURI == "" {
		return fmt.Errorf("notify: empty NotifURI for subscriptionId=%s", subscription.ID)
	}

	notificationItems := make([]NotificationItem, 0, len(measures))
	now := time.Now()

	for _, m := range measures {
		if m.UeIpv4Addr == "" {
			return fmt.Errorf("notify: missing UE IPv4 address in usage measure for subscriptionId=%s", subscription.ID)
		}
		item := NotificationItem{
			EventType:  string(subscription.Event),
			TimeStamp:  now,
			UeIpv4Addr: m.UeIpv4Addr,
			StartTime:  &m.StartTime,
		}

		switch subscription.Event {
		case EventUserDataUsageMeasures:
			// Build UserDataUsageMeasurements per TS 29.564
			measurement := UserDataUsageMeasurements{}

			// Conditionally add Volume Measurement
			if subscription.HasMeasurementType(MeasureVolume) {
				measurement.VolumeMeasurement = &VolumeMeasurement{
					TotalVolume:      m.ULBytesDelta + m.DLBytesDelta,
					UlVolume:         m.ULBytesDelta,
					DlVolume:         m.DLBytesDelta,
					TotalNbOfPackets: m.ULPacketsDelta + m.DLPacketsDelta,
					UlNbOfPackets:    m.ULPacketsDelta,
					DlNbOfPackets:    m.DLPacketsDelta,
				}
			}

			// Conditionally add Throughput Measurement
			if subscription.HasMeasurementType(MeasureThroughput) {
				measurement.ThroughputMeasurement = &ThroughputMeasurement{
					UlThroughput:       fmt.Sprintf("%.0f bps", m.ULThroughputBps),
					DlThroughput:       fmt.Sprintf("%.0f bps", m.DLThroughputBps),
					UlPacketThroughput: fmt.Sprintf("%.2f pps", m.ULPacketThroughputPps),
					DlPacketThroughput: fmt.Sprintf("%.2f pps", m.DLPacketThroughputPps),
				}
			}

			if measurement.VolumeMeasurement == nil &&
				measurement.ThroughputMeasurement == nil &&
				measurement.ThroughputStatisticsMeasurement == nil {
				return fmt.Errorf("notify: subscriptionId=%s has no supported measurementTypes", subscription.ID)
			}
			item.UserDataUsageMeasurements = append(item.UserDataUsageMeasurements, measurement)
		}

		notificationItems = append(notificationItems, item)
	}

	payload := NotificationData{
		NotificationItems: notificationItems,
		CorrelationId:     subscription.NotifyCorrelationID,
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("notify: marshal payload failed: %w", err)
	}

	// Context with timeout for the request lifecycle.
	ctx, cancel := context.WithTimeout(context.Background(), notifier.requestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, subscription.NotifURI, bytes.NewReader(bodyBytes))
	if err != nil {
		return fmt.Errorf("notify: new request failed: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", notifier.defaultUserAgent)
	req.Header.Set("X-EES-EventId", string(subscription.Event))
	req.Header.Set("X-EES-SubscriptionId", subscription.ID)

	resp, err := notifier.httpClient.Do(req)
	if err != nil {
		notifier.logger.WithFields(logrus.Fields{
			"subscriptionId": subscription.ID,
			"notifUri":       subscription.NotifURI,
			"items":          len(payload.NotificationItems),
		}).Warnf("ees notify failed: http request error: %v", err)
		return fmt.Errorf("notify: http request failed: %w", err)
	}

	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			notifier.logger.WithFields(logrus.Fields{
				"subscriptionId": subscription.ID,
			}).Debugf("ees notify: close response body failed: %v", closeErr)
		}
	}()

	// Accept any 2xx as success.
	if resp.StatusCode/100 != 2 {
		// Best-effort small response read for logging; avoid large buffers.
		var snippet string
		limit := notifier.maxResponseBodyLen
		if limit <= 0 {
			limit = 4096
		}
		bodyLimited := io.LimitReader(resp.Body, limit)
		bodyBytes, readErr := io.ReadAll(bodyLimited)
		if readErr != nil {
			snippet = fmt.Sprintf("status=%s body=(read error: %v)", resp.Status, readErr)
		} else if resp.ContentLength != -1 && resp.ContentLength > limit {
			snippet = fmt.Sprintf("status=%s body=%q (truncated)", resp.Status, string(bodyBytes))
		} else {
			snippet = fmt.Sprintf("status=%s body=%q", resp.Status, string(bodyBytes))
		}

		notifier.logger.WithFields(logrus.Fields{
			"subscriptionId": subscription.ID,
			"notifUri":       subscription.NotifURI,
			"statusCode":     resp.StatusCode,
			"items":          len(payload.NotificationItems),
		}).Warnf("ees notify failed: non-2xx response: %s", snippet)
		return fmt.Errorf("notify: non-2xx response: %s", resp.Status)
	}

	// Success log (compact, with essential identifiers).
	notifier.logger.WithFields(logrus.Fields{
		"subscriptionId": subscription.ID,
		"notifUri":       subscription.NotifURI,
		"items":          len(payload.NotificationItems),
	}).Debug("ees notify success")

	return nil
}
