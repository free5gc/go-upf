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

// PDRPlan contains validated PDR operation parameters
type PDRPlan struct {
	Op         OpType
	OID        gtp5gnl.OID
	Attrs      []nl.Attr
	OriginalIE *ie.IE
	// Parsed fields for node.go to use
	PDRID  uint16
	URRIDs []uint32
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
	QERID uint32
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
	MeasureInfoIE    *ie.IE // for node.go to extract MeasureInformation
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

// ModificationPlan contains all validated rule operations for a session modification
// Operations should be executed in the order defined here
type ModificationPlan struct {
	SEID uint64

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

// ExecutionResult contains the result of executing a ModificationPlan
type ExecutionResult struct {
	// USAReports collected from URR operations (Update, Remove, Query)
	USAReports []report.USAReport
}

// HasCreateFAR checks if the plan contains a CreateFAR with the given FAR ID
func (p *ModificationPlan) HasCreateFAR(farid uint32) bool {
	for _, f := range p.CreateFARs {
		if f.FARID == farid {
			return true
		}
	}
	return false
}

// HasCreateQER checks if the plan contains a CreateQER with the given QER ID
func (p *ModificationPlan) HasCreateQER(qerid uint32) bool {
	for _, q := range p.CreateQERs {
		if q.QERID == qerid {
			return true
		}
	}
	return false
}

// HasCreateURR checks if the plan contains a CreateURR with the given URR ID
func (p *ModificationPlan) HasCreateURR(urrid uint32) bool {
	for _, u := range p.CreateURRs {
		if u.URRID == urrid {
			return true
		}
	}
	return false
}

// HasCreateBAR checks if the plan contains a CreateBAR with the given BAR ID
func (p *ModificationPlan) HasCreateBAR(barid uint8) bool {
	for _, b := range p.CreateBARs {
		if b.BARID == barid {
			return true
		}
	}
	return false
}

// HasCreatePDR checks if the plan contains a CreatePDR with the given PDR ID
func (p *ModificationPlan) HasCreatePDR(pdrid uint16) bool {
	for _, d := range p.CreatePDRs {
		if d.PDRID == pdrid {
			return true
		}
	}
	return false
}

// NewExecutionResult creates a new empty ExecutionResult
func NewExecutionResult() *ExecutionResult {
	return &ExecutionResult{
		USAReports: make([]report.USAReport, 0),
	}
}
