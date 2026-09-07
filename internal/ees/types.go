// Package ees contains types and interfaces for the UPF Event Exposure Service (EES)
// MVP: USER_DATA_USAGE_MEASURES with per-PDU-session granularity and periodic/on-demand reporting.

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
	// EventUserDataUsageTrends reports throughput statistics.
	EventUserDataUsageTrends EventType = "USER_DATA_USAGE_TRENDS"
)

// UserDataUsageMeasurements represents measurements per TS 29.564.
// Contains volume and/or throughput statistics measurements.
type UserDataUsageMeasurements struct {
	// Granularity identifiers
	AppId    string           `json:"appId,omitempty"`    // For PER_APPLICATION granularity
	FlowInfo *FlowInformation `json:"flowInfo,omitempty"` // For PER_FLOW granularity

	VolumeMeasurement               *VolumeMeasurement               `json:"volumeMeasurement,omitempty"`
	ThroughputMeasurement           *ThroughputMeasurement           `json:"throughputMeasurement,omitempty"`
	ThroughputStatisticsMeasurement *ThroughputStatisticsMeasurement `json:"throughputStatisticsMeasurement,omitempty"`
}

// FlowInformation per TS 29.512 FlowInformation schema.
type FlowInformation struct {
	FlowDescription string `json:"flowDescription,omitempty"` // IPFilterRule format
	FlowDirection   string `json:"flowDirection,omitempty"`   // UPLINK, DOWNLINK, BIDIRECTIONAL
}

// VolumeMeasurement per TS 29.564 schema.
type VolumeMeasurement struct {
	TotalVolume      uint64 `json:"totalVolume,omitempty"`
	UlVolume         uint64 `json:"ulVolume,omitempty"`
	DlVolume         uint64 `json:"dlVolume,omitempty"`
	TotalNbOfPackets uint64 `json:"totalNbOfPackets,omitempty"`
	UlNbOfPackets    uint64 `json:"ulNbOfPackets,omitempty"`
	DlNbOfPackets    uint64 `json:"dlNbOfPackets,omitempty"`
}

// ThroughputMeasurement per TS 29.564 schema.
type ThroughputMeasurement struct {
	UlThroughput       string `json:"ulThroughput,omitempty"`       // BitRate
	DlThroughput       string `json:"dlThroughput,omitempty"`       // BitRate
	UlPacketThroughput string `json:"ulPacketThroughput,omitempty"` // PacketRate
	DlPacketThroughput string `json:"dlPacketThroughput,omitempty"` // PacketRate
}

// ThroughputStatisticsMeasurement per TS 29.564 schema.
type ThroughputStatisticsMeasurement struct {
	UlAverageThroughput string `json:"ulAverageThroughput,omitempty"` // BitRate as string per spec
	DlAverageThroughput string `json:"dlAverageThroughput,omitempty"` // BitRate as string per spec
}

// Granularity controls the level of aggregation for the event.
// MVP only: perPduSession.
type Granularity string

const (
	// GranularityPerSession reports measurements per PDU session.
	GranularityPerSession Granularity = "PER_SESSION"
	// GranularityPerApplication reports measurements grouped by application ID.
	GranularityPerApplication Granularity = "PER_APPLICATION"
	// GranularityPerFlow reports measurements grouped by traffic flow.
	GranularityPerFlow Granularity = "PER_FLOW"
)

// Mode controls how a subscription is served.
type Mode string

const (
	// ModePeriodic: deliver reports every PeriodSec ticks.
	ModePeriodic Mode = "PERIODIC"
	// ModeOnDemand: deliver one immediate report using the current snapshot
	// relative to the last snapshot (then refresh the snapshot and typically
	// switch to PERIODIC in the aggregator per MVP behavior).
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
	// MeasureAppInfo requests application-related information.
	MeasureAppInfo MeasurementType = "APPLICATION_RELATED_INFO"
)

// TargetScope defines the target selection for a subscription.
// MVP: only AnyUE=true (all active PDU sessions).
type TargetScope struct {
	AnyUE bool
	// Future: UEIP, SUPI, DNN, S-NSSAI, app filters...
	// UeIPAddress allows targeting a specific UE by IP.
	UeIPAddress string
}

// SessionKey uniquely identifies a session for reporting purposes.
// MVP: use SEIDs; UE IP can be added later without breaking the map key.
type SessionKey struct {
	LocalSEID  uint64 // UPF user-plane SEID
	RemoteSEID uint64 // SMF control-plane SEID
	// Future: UEIP string
}

// Counters represents raw counters collected for a single session over an interval.
// The interval is [StartTime, EndTime]; think "time window start/end" but field names
// are strictly StartTime / EndTime per naming guideline.
type Counters struct {
	ULBytes   uint64
	DLBytes   uint64
	ULPackets uint64
	DLPackets uint64

	StartTime time.Time // measurement interval start time
	EndTime   time.Time // measurement interval end time
}

// UsageMeasures represents a delta (relative to last snapshot) plus derived metrics
// that are ready to be sent in a Notify payload.
type UsageMeasures struct {
	Key SessionKey

	ULBytesDelta   uint64
	DLBytesDelta   uint64
	ULPacketsDelta uint64
	DLPacketsDelta uint64

	StartTime time.Time // interval start
	EndTime   time.Time // interval end

	// Derived metrics (optional in MVP; aggregator may compute them).
	ULThroughputBps float64
	DLThroughputBps float64

	// Derived packet throughput (packets per second)
	ULPacketThroughputPps float64
	DLPacketThroughputPps float64

	// TS 29.564 UE identifiers
	UeIpv4Addr string // UE IPv4 Address from session context
}

// Subscription holds the in-memory state for a single EES subscription.
type Subscription struct {
	mu                  sync.RWMutex
	ID                  string
	NotifURI            string
	NotifyCorrelationID string // Added: Client-provided correlation ID
	NfID                string // Added: NF Instance ID
	Event               EventType
	Target              TargetScope
	Granularity         Granularity
	Mode                Mode
	PeriodSec           int

	// TS 29.564: MeasurementTypes specifies which measurements are requested.
	MeasurementTypes []MeasurementType

	// TS 29.564: Granularity-specific filters
	AppIds         []string          `json:"appIds,omitempty"`         // For PER_APPLICATION
	TrafficFilters []FlowInformation `json:"trafficFilters,omitempty"` // For PER_FLOW

	CreatedAt  time.Time
	LastNotify time.Time

	// Snapshots keeps the last seen per-session counters for delta computation.
	// Key: SessionKey (LocalSEID, RemoteSEID)
	// Val: last counters over [StartTime, EndTime]
	Snapshots map[SessionKey]Counters
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

// Source abstracts the producer of session-level counters for EES.
// SnapshotNow should return a *copy* of current per-session counters, each with
// their StartTime/EndTime representing the measurement interval the counters cover.
type Source interface {
	SnapshotNow() (map[SessionKey]Counters, error)
}

type PDRContext struct {
	PDRID  uint16
	URRIDs []uint32
}

type SessionContext struct {
	RemoteSEID uint64
	UeIPv4Addr string // Added: UE IPv4 Address
	URRIDs     []uint32
	PDRs       []*PDRContext
}

// SessionProvider defines the interface for obtaining active Session information.
// Used by API Server for provisioning Shadow URRs to all active sessions.
type SessionProvider interface {
	GetSessionContexts() map[uint64]SessionContext
	GetSessionContextUEIP(lSeid uint64) (string, bool)
}
