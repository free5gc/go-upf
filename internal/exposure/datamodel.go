// Package exposure implements the Nupf_EventExposure service defined in 3GPP TS 29.564.
package exposure

import (
	"net"
	"time"
)

// EventType enumerates the UPF event types defined in 3GPP TS 29.564 clause 5.6.
type EventType string

const (
	EventTypeUserDataUsageMeasures EventType = "USER_DATA_USAGE_MEASURES"
	EventTypeUserDataUsageTrends   EventType = "USER_DATA_USAGE_TRENDS"
	EventTypeQosMonitoring         EventType = "QOS_MONITORING"
	EventTypeTscMngtInfo           EventType = "TSC_MNGT_INFO"
)

// UpfEventTrigger specifies when event notifications are sent.
type UpfEventTrigger string

const (
	TriggerOneTime  UpfEventTrigger = "ONE_TIME"
	TriggerPeriodic UpfEventTrigger = "PERIODIC"
)

// MeasurementType specifies what to measure for USER_DATA_USAGE_*.
type MeasurementType string

const (
	MeasurementVolume     MeasurementType = "VOLUME"
	MeasurementThroughput MeasurementType = "THROUGHPUT"
)

// GranularityOfMeasurement specifies measurement granularity.
type GranularityOfMeasurement string

const (
	GranularityPerUe     GranularityOfMeasurement = "PER_UE"
	GranularityPerFlow   GranularityOfMeasurement = "PER_FLOW"
	GranularityPerAppId  GranularityOfMeasurement = "PER_APP_ID"
	GranularityAggregate GranularityOfMeasurement = "AGGREGATE"
)

// Snssai represents a Single Network Slice Selection Assistance Information.
type Snssai struct {
	Sst int32  `json:"sst"`
	Sd  string `json:"sd,omitempty"`
}

// UpfEvent describes a single event to subscribe to (TS 29.564 clause 6.1.6.2.3).
type UpfEvent struct {
	Type            EventType         `json:"type"`
	ImmediateFlag   bool              `json:"immediateFlag,omitempty"`
	MeasurementType []MeasurementType `json:"measurementTypes,omitempty"`
	// Granularity for usage measurement reports
	Granularity GranularityOfMeasurement `json:"granularityOfMeasurement,omitempty"`
}

// UpfEventMode contains the subscription's trigger and period (TS 29.564 clause 6.1.6.2.4).
type UpfEventMode struct {
	Trigger    UpfEventTrigger `json:"trigger"`
	RepPeriod  *int32          `json:"repPeriod,omitempty"` // seconds, required for PERIODIC
	MaxReports *int32          `json:"maxReports,omitempty"`
}

// UpfEventSubscription is the per-subscription data for Nupf_EventExposure
// (TS 29.564 clause 6.1.6.2.2). Sessions are identified by UE IP address, not TEID.
type UpfEventSubscription struct {
	EventNotifyUri string       `json:"eventNotifyUri"`
	NotifCorrId    string       `json:"notifyCorrelationId"`
	EventList      []UpfEvent   `json:"eventList"`
	EventMode      UpfEventMode `json:"eventReportingMode"`
	UeIpAddress    net.IP       `json:"ueIpAddress,omitempty"`
	AnyUe          bool         `json:"anyUe,omitempty"`
	Dnn            string       `json:"dnn,omitempty"`
	Snssai         *Snssai      `json:"snssai,omitempty"`
	NfId           string       `json:"nfId,omitempty"`
}

// CreateEventSubscription is the request body for POST /ee-subscriptions.
type CreateEventSubscription struct {
	Subscription UpfEventSubscription `json:"subscription"`
}

// CreatedEventSubscription is the 201 response body (TS 29.564 clause 6.1.6.3.1).
type CreatedEventSubscription struct {
	SubscriptionId string               `json:"subscriptionId"`
	Subscription   UpfEventSubscription `json:"subscription"`
	// ReportList may contain an immediate report if immediateFlag is true.
	ReportList []NotificationData `json:"reportList,omitempty"`
}

// VolumeMeasurement holds UL/DL/Total volume counts (bytes).
type VolumeMeasurement struct {
	TotalVolume    *uint64 `json:"totalVolume,omitempty"`
	UplinkVolume   *uint64 `json:"ulVolume,omitempty"`
	DownlinkVolume *uint64 `json:"dlVolume,omitempty"`
	TotalNbOfPkts  *uint64 `json:"totalNbOfPkts,omitempty"`
	UlNbOfPkts     *uint64 `json:"ulNbOfPkts,omitempty"`
	DlNbOfPkts     *uint64 `json:"dlNbOfPkts,omitempty"`
}

// ThroughputMeasurement holds UL/DL average throughput in bit/s.
type ThroughputMeasurement struct {
	UlThroughput *uint64 `json:"ulThroughput,omitempty"`
	DlThroughput *uint64 `json:"dlThroughput,omitempty"`
}

// UserDataUsageMeasurements holds the measurement data for USER_DATA_USAGE_MEASURES event.
type UserDataUsageMeasurements struct {
	VolumeMeasurement     *VolumeMeasurement     `json:"volumeMeasurement,omitempty"`
	ThroughputMeasurement *ThroughputMeasurement `json:"throughputMeasurement,omitempty"`
	ApplicationId         string                 `json:"appId,omitempty"`
}

// NotificationItem is one item in a notification (per session/UE).
type NotificationItem struct {
	SourceUeIpAddress net.IP                      `json:"sourceUeIpAddress,omitempty"`
	TimeStamp         time.Time                   `json:"timeStamp"`
	EventType         EventType                   `json:"eventType"`
	UsageData         []UserDataUsageMeasurements `json:"usageData,omitempty"`
}

// NotificationData is the body of a notification POST sent to eventNotifyUri.
type NotificationData struct {
	NotifCorrId       string             `json:"notifyCorrelationId"`
	NotificationItems []NotificationItem `json:"notificationItems"`
}

// ModifySubscriptionRequest is the body of PATCH /ee-subscriptions/{subscriptionId}.
type ModifySubscriptionRequest struct {
	Subscription UpfEventSubscription `json:"subscription"`
}
