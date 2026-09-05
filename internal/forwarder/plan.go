package forwarder

import (
	"time"

	"github.com/khirono/go-nl"
	"github.com/wmnsk/go-pfcp/ie"

	"github.com/free5gc/go-gtp5gnl"
	"github.com/free5gc/go-upf/internal/report"
)

// OpType represents the type of rule operation
type OpType int

const (
	OpCreate OpType = iota
	OpUpdate
	OpRemove
)

func (op OpType) String() string {
	switch op {
	case OpCreate:
		return "Create"
	case OpUpdate:
		return "Update"
	case OpRemove:
		return "Remove"
	default:
		return "Unknown"
	}
}

// FlowQoSBinding is the user-space representation published on a PDR.
// PolicyID is a UPF-local, globally unique 24-bit ID. TCClassID is the full
// Linux traffic-control classid.
type FlowQoSBinding struct {
	PolicyID   uint32
	TCClassID  uint32
	Generation uint32
}

// DirectionalBitRate is a directional rate expressed in bits per second.
// PFCP encodes QER GBR/MBR values in kilobits per second; builders convert
// them before placing them in desired state.
type DirectionalBitRate struct {
	UplinkBps   uint64
	DownlinkBps uint64
}

// QERGateStatus keeps the independently signalled uplink and downlink gates.
type QERGateStatus struct {
	Uplink   uint8
	Downlink uint8
}

// QERDesiredStatePatch records only QER fields present in one PFCP request.
// Pointer presence is required because Update QER is a partial update and a
// missing field must not clear the previously saved desired value.
type QERDesiredStatePatch struct {
	QFI        *uint8
	GateStatus *QERGateStatus
	GBR        *DirectionalBitRate
	MBR        *DirectionalBitRate
}

// PDRPlan contains validated PDR operation parameters
type PDRPlan struct {
	Op         OpType
	OID        gtp5gnl.OID
	Attrs      []nl.Attr
	OriginalIE *ie.IE
	// Parsed fields used by PFCP validation and committed Session state.
	PDRID uint16

	FARID        uint32
	FARIDPresent bool

	URRIDs        []uint32
	URRIDsPresent bool

	QERIDs        []uint32
	QERIDsPresent bool

	// SourceInterface uses pointer presence because zero is a valid PFCP value.
	// A nil pointer on Update PDR means that the saved value is unchanged.
	SourceInterface *uint8
}

// SetFlowQoSBinding adds or replaces the nested PDR FlowQoS attribute. The
// CreatePDROID and UpdatePDROID execution paths already publish every
// attribute in PDRPlan.Attrs, so no separate netlink command is required.
func (p *PDRPlan) SetFlowQoSBinding(binding FlowQoSBinding) error {
	return p.setFlowQoS(gtp5gnl.FlowQoS{
		Version:    gtp5gnl.SHARED_MARK_ABI_VERSION,
		PolicyID:   binding.PolicyID,
		TCClassID:  binding.TCClassID,
		Flags:      gtp5gnl.FLOW_QOS_VALID,
		Generation: binding.Generation,
	})
}

// ClearFlowQoSBinding publishes an explicit clear operation for an existing
// PDR binding.
func (p *PDRPlan) ClearFlowQoSBinding(generation uint32) error {
	return p.setFlowQoS(gtp5gnl.FlowQoS{
		Version:    gtp5gnl.SHARED_MARK_ABI_VERSION,
		Generation: generation,
	})
}

func (p *PDRPlan) setFlowQoS(flowQoS gtp5gnl.FlowQoS) error {
	attr, err := gtp5gnl.NewFlowQoSAttr(flowQoS)
	if err != nil {
		return err
	}

	for i := range p.Attrs {
		if p.Attrs[i].Type == gtp5gnl.PDR_FLOW_QOS {
			p.Attrs[i] = attr
			return nil
		}
	}

	p.Attrs = append(p.Attrs, attr)
	return nil
}

// FARPlan contains validated FAR operation parameters
type FARPlan struct {
	Op         OpType
	OID        gtp5gnl.OID
	Attrs      []nl.Attr
	OriginalIE *ie.IE
	// Parsed fields
	FARID       uint32
	ApplyAction *report.ApplyAction // for UpdateFAR side effects
}

// QERPlan contains validated QER operation parameters
type QERPlan struct {
	Op         OpType
	OID        gtp5gnl.OID
	Attrs      []nl.Attr
	OriginalIE *ie.IE
	// Parsed fields
	QERID        uint32
	DesiredState QERDesiredStatePatch
}

// URRPlan contains validated URR operation parameters
type URRPlan struct {
	Op         OpType
	OID        gtp5gnl.OID
	Attrs      []nl.Attr
	OriginalIE *ie.IE
	// Parsed fields
	URRID            uint32
	MeasureMethod    uint8
	ReportingTrigger report.ReportingTrigger
	MeasurePeriod    time.Duration
	// For QueryURR
	QueryURRID uint32
}

// BARPlan contains validated BAR operation parameters
type BARPlan struct {
	Op         OpType
	OID        gtp5gnl.OID
	Attrs      []nl.Attr
	OriginalIE *ie.IE
	// Parsed fields
	BARID uint8
}

// RollbackPlan contains the previously applied rule configurations for a
// transactional PFCP request. Create operations do not need prior configuration;
// Update and Remove operations use these plans to restore the previous rule.
type RollbackPlan struct {
	PDRs map[uint16]*PDRPlan
	FARs map[uint32]*FARPlan
	QERs map[uint32]*QERPlan
	URRs map[uint32]*URRPlan
	BARs map[uint8]*BARPlan
}

func NewRollbackPlan() *RollbackPlan {
	return &RollbackPlan{
		PDRs: make(map[uint16]*PDRPlan),
		FARs: make(map[uint32]*FARPlan),
		QERs: make(map[uint32]*QERPlan),
		URRs: make(map[uint32]*URRPlan),
		BARs: make(map[uint8]*BARPlan),
	}
}

// ModificationPlan contains all validated rule operations for a session modification
// The executor enforces dependency order across these groups:
// Create -> Update -> Query -> Remove.
type ModificationPlan struct {
	SEID uint64

	// Rollback is non-nil for transactional PFCP requests. It holds the
	// prior configurations needed to undo successful Update and Remove operations.
	// A nil value keeps the legacy best-effort behaviour used by session cleanup.
	Rollback *RollbackPlan

	// Create operations - order: FAR -> QER -> URR -> BAR -> PDR
	CreateFARs []*FARPlan
	CreateQERs []*QERPlan
	CreateURRs []*URRPlan
	CreateBARs []*BARPlan
	CreatePDRs []*PDRPlan

	// Remove operations - order: PDR -> BAR -> URR -> QER -> FAR
	RemovePDRs []*PDRPlan
	RemoveBARs []*BARPlan
	RemoveURRs []*URRPlan
	RemoveQERs []*QERPlan
	RemoveFARs []*FARPlan

	// Update operations - order: FAR -> QER -> URR -> BAR -> PDR
	UpdateFARs []*FARPlan
	UpdateQERs []*QERPlan
	UpdateURRs []*URRPlan
	UpdateBARs []*BARPlan
	UpdatePDRs []*PDRPlan

	// Query operations
	QueryURRs []*URRPlan
}

// NewModificationPlan creates a new empty ModificationPlan
func NewModificationPlan(seid uint64) *ModificationPlan {
	return &ModificationPlan{
		SEID: seid,
	}
}

// ExecutionResult describes what the datapath actually applied.
//
// AppliedPlan contains only state-changing operations that remain applied when
// execution returns. A successful transactional request contains the complete
// plan; a failed request whose rollback completed contains an empty plan.
type ExecutionResult struct {
	AppliedPlan *ModificationPlan

	// USAReports collected from successful URR operations (Update, Remove, Query).
	USAReports []report.USAReport
}

// NewExecutionResult creates an empty execution result for one session.
func NewExecutionResult(seid uint64) *ExecutionResult {
	return &ExecutionResult{
		AppliedPlan: NewModificationPlan(seid),
		USAReports:  make([]report.USAReport, 0),
	}
}

// NewSuccessfulExecutionResult records every operation in plan as applied.
func NewSuccessfulExecutionResult(plan *ModificationPlan) *ExecutionResult {
	if plan == nil {
		return NewExecutionResult(0)
	}
	result := NewExecutionResult(plan.SEID)
	result.AppliedPlan = plan
	return result
}
