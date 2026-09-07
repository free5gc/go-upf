// Package rules defines UPF rule semantics independently of PFCP IEs and netlink.
package rules

import (
	"net"
	"time"
)

// Config values describe complete signalled configurations. Optional pointers
// preserve absence, including fields whose zero value has meaning. Patch values
// describe only signalled changes: nil means unchanged. A present PDI replaces
// the complete PDI; ForwardingParameters is a nested partial update. Non-nil
// QERIDs/URRIDs replace the relationship set. No generic clear marker is invented
// for fields whose PFCP encoding does not provide one.
type PDRConfig struct {
	PDRID              uint16
	Precedence         *uint32
	PDI                *PDI
	OuterHeaderRemoval *uint8
	FARID              *uint32
	QERIDs             []uint32
	URRIDs             []uint32
}
type PDRPatch PDRConfig

type PDI struct {
	SourceInterface uint8
	FTEID           *FTEID
	UEIPAddress     *UEIPAddress
	SDFFilters      []SDFFilter
}
type FTEID struct {
	Flags       uint8
	TEID        uint32
	IPv4Address net.IP
	IPv6Address net.IP
	ChooseID    uint8
}
type UEIPAddress struct {
	Flags                    uint8
	IPv4Address              net.IP
	IPv6Address              net.IP
	IPv6PrefixDelegationBits uint8
	IPv6PrefixLength         uint8
}
type SDFFilter struct {
	FlowDescription        *FlowDesc
	ToSTrafficClass        *string
	SecurityParameterIndex *string
	FlowLabel              *string
	SDFFilterID            *uint32
}
type FARConfig struct {
	FARID                uint32
	ApplyAction          *uint16
	ForwardingParameters *ForwardingParameters
	BARID                *uint8
}
type FARPatch FARConfig

type ForwardingParameters struct {
	DestinationInterface *uint8
	NetworkInstance      *string
	OuterHeaderCreation  *OuterHeaderCreation
	ForwardingPolicy     *string
	SMRequestFlags       *uint8
}
type OuterHeaderCreation struct {
	Description uint16
	TEID        *uint32
	IPv4Address net.IP
	IPv6Address net.IP
	PortNumber  uint16
	CTag        uint32
	STag        uint32
}
type DirectionalBitRate struct {
	UplinkBps   uint64
	DownlinkBps uint64
}
type GateStatus struct{ Uplink, Downlink uint8 }
type QERConfig struct {
	QERID                 uint32
	CorrelationID         *uint32
	GateStatus            *GateStatus
	MBR                   *DirectionalBitRate
	GBR                   *DirectionalBitRate
	QFI                   *uint8
	RQI                   *uint8
	PagingPolicyIndicator *uint8
}
type QERPatch QERConfig

type Volume struct {
	Flags    uint8
	Total    uint64
	Uplink   uint64
	Downlink uint64
}
type URRConfig struct {
	URRID              uint32
	MeasureMethod      *uint8
	ReportingTriggers  *uint32
	MeasurePeriod      *time.Duration
	MeasureInformation *uint64
	VolumeThreshold    *Volume
	VolumeQuota        *Volume
}
type URRPatch URRConfig

type BARConfig struct {
	BARID                          uint8
	DownlinkDataNotificationDelay  *time.Duration
	SuggestedBufferingPacketsCount *uint16
}
type BARPatch BARConfig

// RuleChangeSet owns decoded values; it retains no request payload or backend data.
type RuleChangeSet struct {
	SEID       uint64
	CreatePDRs []PDRConfig
	CreateFARs []FARConfig
	CreateQERs []QERConfig
	CreateURRs []URRConfig
	CreateBARs []BARConfig
	UpdatePDRs []PDRPatch
	UpdateFARs []FARPatch
	UpdateQERs []QERPatch
	UpdateURRs []URRPatch
	UpdateBARs []BARPatch
	RemovePDRs []uint16
	RemoveFARs []uint32
	RemoveQERs []uint32
	RemoveURRs []uint32
	RemoveBARs []uint8
	QueryURRs  []uint32
}
