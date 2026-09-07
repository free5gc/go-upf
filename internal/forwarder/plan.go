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

// pdrPlan contains validated PDR operation parameters
type pdrPlan struct {
	Op         OpType
	OID        gtp5gnl.OID
	Attrs      []nl.Attr
	OriginalIE *ie.IE
	// Transitional builder metadata, retained for encoding parity tests.
	// PFCP validates and stores rules.Config instead.
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
// attribute in pdrPlan.Attrs, so no separate netlink command is required.
func (p *pdrPlan) SetFlowQoSBinding(binding FlowQoSBinding) error {
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
func (p *pdrPlan) ClearFlowQoSBinding(generation uint32) error {
	return p.setFlowQoS(gtp5gnl.FlowQoS{
		Version:    gtp5gnl.SHARED_MARK_ABI_VERSION,
		Generation: generation,
	})
}

func (p *pdrPlan) setFlowQoS(flowQoS gtp5gnl.FlowQoS) error {
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

// farPlan contains validated FAR operation parameters
type farPlan struct {
	Op         OpType
	OID        gtp5gnl.OID
	Attrs      []nl.Attr
	OriginalIE *ie.IE
	// Parsed fields
	FARID       uint32
	ApplyAction *report.ApplyAction // for UpdateFAR side effects
}

// qerPlan contains validated QER operation parameters
type qerPlan struct {
	Op         OpType
	OID        gtp5gnl.OID
	Attrs      []nl.Attr
	OriginalIE *ie.IE
	// Parsed fields
	QERID        uint32
	DesiredState QERDesiredStatePatch
}

// URRReportingPatch records field presence independently of zero values.
// Retained for legacy builder parity and private URR timer restoration.
type URRReportingPatch struct {
	MeasureMethod      *uint8
	MeasureInformation *uint64
	ReportingTrigger   *report.ReportingTrigger
	MeasurePeriod      *time.Duration
}

// urrPlan contains validated URR operation parameters
type urrPlan struct {
	Op         OpType
	OID        gtp5gnl.OID
	Attrs      []nl.Attr
	OriginalIE *ie.IE
	// Parsed fields
	URRID            uint32
	MeasureMethod    uint8
	ReportingTrigger report.ReportingTrigger
	MeasurePeriod    time.Duration
	ReportingConfig  URRReportingPatch
	// For QueryURR
	QueryURRID uint32
}

// barPlan contains validated BAR operation parameters
type barPlan struct {
	Op         OpType
	OID        gtp5gnl.OID
	Attrs      []nl.Attr
	OriginalIE *ie.IE
	// Parsed fields
	BARID uint8
}

// rollbackPlan contains the previously applied rule configurations for a
// transactional PFCP request. Create operations do not need prior configuration;
// Update and Remove operations use these plans to restore the previous rule.
type rollbackPlan struct {
	PDRs map[uint16]*pdrPlan
	FARs map[uint32]*farPlan
	QERs map[uint32]*qerPlan
	URRs map[uint32]*urrPlan
	BARs map[uint8]*barPlan
}

func newRollbackPlan() *rollbackPlan {
	return &rollbackPlan{
		PDRs: make(map[uint16]*pdrPlan),
		FARs: make(map[uint32]*farPlan),
		QERs: make(map[uint32]*qerPlan),
		URRs: make(map[uint32]*urrPlan),
		BARs: make(map[uint8]*barPlan),
	}
}

// modificationPlan contains all validated rule operations for a session modification
// The executor enforces dependency order across these groups:
// Create -> Update -> Query -> Remove.
type modificationPlan struct {
	SEID uint64

	// Rollback is populated by SessionDatapath on its execution copy; PFCP
	// callers do not construct it. It is non-nil for transactions and holds the
	// prior configurations needed to undo successful Update and Remove operations.
	// A nil value keeps the legacy best-effort behaviour used by session cleanup.
	Rollback *rollbackPlan

	// Create operations - order: FAR -> QER -> URR -> BAR -> PDR
	CreateFARs []*farPlan
	CreateQERs []*qerPlan
	CreateURRs []*urrPlan
	CreateBARs []*barPlan
	CreatePDRs []*pdrPlan

	// Remove operations - order: PDR -> BAR -> URR -> QER -> FAR
	RemovePDRs []*pdrPlan
	RemoveBARs []*barPlan
	RemoveURRs []*urrPlan
	RemoveQERs []*qerPlan
	RemoveFARs []*farPlan

	// Update operations - order: FAR -> QER -> URR -> BAR -> PDR
	UpdateFARs []*farPlan
	UpdateQERs []*qerPlan
	UpdateURRs []*urrPlan
	UpdateBARs []*barPlan
	UpdatePDRs []*pdrPlan

	// Query operations
	QueryURRs []*urrPlan
}

// newModificationPlan creates a new empty modificationPlan
func newModificationPlan(seid uint64) *modificationPlan {
	return &modificationPlan{
		SEID: seid,
	}
}

// executionResult describes what the datapath actually applied.
//
// AppliedPlan contains only state-changing operations that remain applied when
// execution returns. A successful transactional request contains the complete
// plan; a failed request whose rollback completed contains an empty plan.
type executionResult struct {
	AppliedPlan *modificationPlan

	// USAReports collected from successful URR operations (Update, Remove, Query).
	USAReports []report.USAReport
}

// newExecutionResult creates an empty execution result for one session.
func newExecutionResult(seid uint64) *executionResult {
	return &executionResult{
		AppliedPlan: newModificationPlan(seid),
		USAReports:  make([]report.USAReport, 0),
	}
}

// newSuccessfulExecutionResult records every operation in plan as applied.
func newSuccessfulExecutionResult(plan *modificationPlan) *executionResult {
	if plan == nil {
		return newExecutionResult(0)
	}
	result := newExecutionResult(plan.SEID)
	result.AppliedPlan = plan
	return result
}
