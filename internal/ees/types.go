// Package ees contains types and interfaces for the UPF Event Exposure Service (EES)
// MVP: USER_DATA_USAGE_MEASURES with PER_SESSION granularity and PERIODIC/ONE_TIME reporting.

package ees

import (
	"sync"
	"time"
)

// EventType enumerates EES event IDs supported by the UPF.
// MVP only: USER_DATA_USAGE_MEASURES.
type EventType string

const (
	// EventUserDataUsageMeasures reports per-interval usage deltas (bytes/packets, UL/DL),
	// optionally with throughputs derived from (delta bytes) / (EndTime - StartTime).
	EventUserDataUsageMeasures EventType = "USER_DATA_USAGE_MEASURES"
	// EventUserDataUsageTrends is defined by TS 29.564 but not supported here.
	EventUserDataUsageTrends EventType = "USER_DATA_USAGE_TRENDS"
)

// UserDataUsageMeasurements represents PER_SESSION measurements per TS 29.564.
type UserDataUsageMeasurements struct {
	VolumeMeasurement     *VolumeMeasurement     `json:"volumeMeasurement,omitempty"`
	ThroughputMeasurement *ThroughputMeasurement `json:"throughputMeasurement,omitempty"`
}

// FlowInformation per TS 29.512; decoded only to reject PER_SESSION filters.
type FlowInformation struct {
	FlowDescription string `json:"flowDescription,omitempty"` // IPFilterRule format
	FlowDirection   string `json:"flowDirection,omitempty"`   // UPLINK, DOWNLINK, BIDIRECTIONAL
}

// VolumeMeasurement per TS 29.564 schema.
type VolumeMeasurement struct {
	TotalVolume      string `json:"totalVolume"`
	UlVolume         string `json:"ulVolume"`
	DlVolume         string `json:"dlVolume"`
	TotalNbOfPackets uint64 `json:"totalNbOfPackets"`
	UlNbOfPackets    uint64 `json:"ulNbOfPackets"`
	DlNbOfPackets    uint64 `json:"dlNbOfPackets"`
}

// ThroughputMeasurement per TS 29.564 schema.
type ThroughputMeasurement struct {
	UlThroughput       string `json:"ulThroughput,omitempty"`       // BitRate
	DlThroughput       string `json:"dlThroughput,omitempty"`       // BitRate
	UlPacketThroughput string `json:"ulPacketThroughput,omitempty"` // PacketRate
	DlPacketThroughput string `json:"dlPacketThroughput,omitempty"` // PacketRate
}

// Granularity controls the level of aggregation for the event.
// MVP only: PER_SESSION.
type Granularity string

const (
	// GranularityPerSession reports measurements per PDU session.
	GranularityPerSession Granularity = "PER_SESSION"
	// GranularityPerApplication is defined by TS 29.564 but not supported here.
	GranularityPerApplication Granularity = "PER_APPLICATION"
	// GranularityPerFlow is defined by TS 29.564 but not supported here.
	GranularityPerFlow Granularity = "PER_FLOW"
)

// Mode controls how a subscription is served.
type Mode string

const (
	// ModePeriodic: deliver measurements every PeriodSec seconds, rounded up to
	// whole URR measurement periods (see periodicDue).
	ModePeriodic Mode = "PERIODIC"
	// ModeOnDemand: wait for real data, report once, delete after successful delivery.
	ModeOnDemand Mode = "ON_DEMAND"
)

// MeasurementType specifies which measurements to include in reports.
// TS 29.564: Required when event type is USER_DATA_USAGE_MEASURES.
type MeasurementType string

const (
	// MeasureVolume requests volume measurements (bytes/packets).
	MeasureVolume MeasurementType = "VOLUME_MEASUREMENT"
	// MeasureThroughput requests throughput measurements (bit rate).
	MeasureThroughput MeasurementType = "THROUGHPUT_MEASUREMENT"
	// MeasureAppInfo is defined by TS 29.564 but not supported here.
	MeasureAppInfo MeasurementType = "APPLICATION_RELATED_INFO"
)

// TargetScope selects all sessions or sessions with a specific IPv4 address.
type TargetScope struct {
	AnyUE bool
	// Future: UEIP, SUPI, DNN, S-NSSAI, app filters...
	// UeIPAddress allows targeting a specific UE by IP.
	UeIPAddress string
}

// SessionKey uniquely identifies a session for reporting purposes.
// It combines both SEIDs, the local allocation generation and the UE IP.
type SessionKey struct {
	LocalSEID  uint64 // UPF user-plane SEID
	RemoteSEID uint64 // SMF control-plane SEID
	Generation uint64 // Distinguishes recycled SEIDs, even for the same UE.
	UEIPv4     string
}

// UsageMeasures is usage accumulated from reports over [StartTime, EndTime],
// plus derived metrics, ready to be sent in a Notify payload.
type UsageMeasures struct {
	Key SessionKey

	ULBytesDelta   uint64
	DLBytesDelta   uint64
	ULPacketsDelta uint64
	DLPacketsDelta uint64

	StartTime time.Time // interval start
	EndTime   time.Time // interval end

	// Derived bit rates, computed by the aggregator before sending.
	ULThroughputBps float64
	DLThroughputBps float64

	// Derived packet throughput (packets per second)
	ULPacketThroughputPps float64
	DLPacketThroughputPps float64

	// TS 29.564 UE identifiers
	UeIpv4Addr string // UE IPv4 Address from session context

	// URR measurement period the reports were produced at (0 if not periodic).
	MeasurePeriod time.Duration
}

// Subscription holds the in-memory state for a single EES subscription.
type Subscription struct {
	mu                  sync.RWMutex
	ID                  string
	NotifURI            string
	NotifyCorrelationID string // client-provided correlation ID
	NfID                string // consumer NF instance ID
	Event               EventType
	Target              TargetScope
	Granularity         Granularity
	Mode                Mode
	PeriodSec           int

	// TS 29.564: MeasurementTypes specifies which measurements are requested.
	MeasurementTypes []MeasurementType

	CreatedAt  time.Time
	LastNotify time.Time
}

// HasMeasurementType checks if the subscription requests the given measurement type.
func (s *Subscription) HasMeasurementType(mt MeasurementType) bool {
	for _, t := range s.MeasurementTypes {
		if t == mt {
			return true
		}
	}
	return false
}

// SessionContext is the session identity captured by PFCP with each report.
type SessionContext struct {
	RemoteSEID uint64
	Generation uint64
	UeIPv4Addr string
	// Periodic measurement period of SingleUPFMAQEURRID in this session;
	// 0 when that URR does not report periodically.
	MeasurePeriod time.Duration
}
