package forwarder

import (
	"syscall"
	"time"

	"github.com/khirono/go-nl"
	"github.com/pkg/errors"

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

// pdrPlan contains validated PDR operation parameters
type pdrPlan struct {
	OID   gtp5gnl.OID
	Attrs []nl.Attr
	PDRID uint16
}

// farPlan contains validated FAR operation parameters
type farPlan struct {
	OID   gtp5gnl.OID
	Attrs []nl.Attr

	// Parsed fields
	FARID       uint32
	ApplyAction *report.ApplyAction // for UpdateFAR side effects
}

// qerPlan contains validated QER operation parameters
type qerPlan struct {
	OID   gtp5gnl.OID
	Attrs []nl.Attr

	// Parsed fields
	QERID uint32
}

// urrPlan contains validated URR operation parameters
type urrPlan struct {
	OID   gtp5gnl.OID
	Attrs []nl.Attr

	// Parsed fields
	URRID uint32

	ReportingTrigger report.ReportingTrigger
	MeasurePeriod    time.Duration
}

// barPlan contains validated BAR operation parameters
type barPlan struct {
	OID   gtp5gnl.OID
	Attrs []nl.Attr

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

// rollbackApplied attempts compensation in reverse dependency order.
//
// TODO: URR rollback restores configuration only. Remove-and-recreate does not
// preserve kernel accounting runtime; full restoration requires gtp5g support.
//
// TODO: Return and reconcile rollback failures. For now they are logged and the
// caller assumes the pre-request kernel state was restored.
func (g *Gtp5g) rollbackApplied(request, applied *modificationPlan) {
	if applied == nil {
		return
	}

	logFailure := func(operation string, err error) {
		if err != nil {
			g.log.Errorf("Rollback %s failed: %v", operation, err)
		}
	}
	before := request.Rollback

	for i := len(applied.RemoveFARs) - 1; i >= 0; i-- {
		p := applied.RemoveFARs[i]
		if before != nil && before.FARs[p.FARID] != nil {
			old := before.FARs[p.FARID]
			logFailure("CreateFAR", gtp5gnl.CreateFAROID(g.client, g.link.link, old.OID, old.Attrs))
		}
	}
	for i := len(applied.RemoveQERs) - 1; i >= 0; i-- {
		p := applied.RemoveQERs[i]
		if before != nil && before.QERs[p.QERID] != nil {
			old := before.QERs[p.QERID]
			logFailure("CreateQER", gtp5gnl.CreateQEROID(g.client, g.link.link, old.OID, old.Attrs))
		}
	}
	for i := len(applied.RemoveURRs) - 1; i >= 0; i-- {
		p := applied.RemoveURRs[i]
		if before != nil && before.URRs[p.URRID] != nil {
			old := before.URRs[p.URRID]
			err := gtp5gnl.CreateURROID(g.client, g.link.link, old.OID, old.Attrs)
			logFailure("CreateURR", err)
			if err == nil && old.ReportingTrigger.PERIO() && old.MeasurePeriod > 0 {
				g.ps.AddPeriodReportTimer(request.SEID, old.URRID, old.MeasurePeriod)
			}
		}
	}
	for i := len(applied.RemoveBARs) - 1; i >= 0; i-- {
		p := applied.RemoveBARs[i]
		if before != nil && before.BARs[p.BARID] != nil {
			old := before.BARs[p.BARID]
			logFailure("CreateBAR", gtp5gnl.CreateBAROID(g.client, g.link.link, old.OID, old.Attrs))
		}
	}
	for i := len(applied.RemovePDRs) - 1; i >= 0; i-- {
		p := applied.RemovePDRs[i]
		if before != nil && before.PDRs[p.PDRID] != nil {
			old := before.PDRs[p.PDRID]
			logFailure("CreatePDR", gtp5gnl.CreatePDROID(g.client, g.link.link, old.OID, old.Attrs))
		}
	}

	// Remove+Create restores optional attributes that Update cannot clear.
	for i := len(applied.UpdatePDRs) - 1; i >= 0; i-- {
		p := applied.UpdatePDRs[i]
		if before != nil && before.PDRs[p.PDRID] != nil {
			old := before.PDRs[p.PDRID]
			logFailure("Remove updated PDR", gtp5gnl.RemovePDROID(g.client, g.link.link, p.OID))
			logFailure("Restore updated PDR", gtp5gnl.CreatePDROID(g.client, g.link.link, old.OID, old.Attrs))
		}
	}
	for i := len(applied.UpdateBARs) - 1; i >= 0; i-- {
		p := applied.UpdateBARs[i]
		if before != nil && before.BARs[p.BARID] != nil {
			old := before.BARs[p.BARID]
			logFailure("Remove updated BAR", gtp5gnl.RemoveBAROID(g.client, g.link.link, p.OID))
			logFailure("Restore updated BAR", gtp5gnl.CreateBAROID(g.client, g.link.link, old.OID, old.Attrs))
		}
	}
	for i := len(applied.UpdateURRs) - 1; i >= 0; i-- {
		p := applied.UpdateURRs[i]
		if before != nil && before.URRs[p.URRID] != nil {
			old := before.URRs[p.URRID]
			_, err := gtp5gnl.RemoveURROID(g.client, g.link.link, p.OID)
			logFailure("Remove updated URR", err)
			if err == nil {
				g.ps.DelPeriodReportTimer(request.SEID, p.URRID)
			}
			err = gtp5gnl.CreateURROID(g.client, g.link.link, old.OID, old.Attrs)
			logFailure("Restore updated URR", err)
			if err == nil && old.ReportingTrigger.PERIO() && old.MeasurePeriod > 0 {
				g.ps.AddPeriodReportTimer(request.SEID, old.URRID, old.MeasurePeriod)
			}
		}
	}
	for i := len(applied.UpdateQERs) - 1; i >= 0; i-- {
		p := applied.UpdateQERs[i]
		if before != nil && before.QERs[p.QERID] != nil {
			old := before.QERs[p.QERID]
			logFailure("Remove updated QER", gtp5gnl.RemoveQEROID(g.client, g.link.link, p.OID))
			logFailure("Restore updated QER", gtp5gnl.CreateQEROID(g.client, g.link.link, old.OID, old.Attrs))
		}
	}
	for i := len(applied.UpdateFARs) - 1; i >= 0; i-- {
		p := applied.UpdateFARs[i]
		if before != nil && before.FARs[p.FARID] != nil {
			old := before.FARs[p.FARID]
			logFailure("Remove updated FAR", gtp5gnl.RemoveFAROID(g.client, g.link.link, p.OID))
			logFailure("Restore updated FAR", gtp5gnl.CreateFAROID(g.client, g.link.link, old.OID, old.Attrs))
		}
	}

	for i := len(applied.CreatePDRs) - 1; i >= 0; i-- {
		p := applied.CreatePDRs[i]
		logFailure("Remove created PDR", gtp5gnl.RemovePDROID(g.client, g.link.link, p.OID))
	}
	for i := len(applied.CreateBARs) - 1; i >= 0; i-- {
		p := applied.CreateBARs[i]
		logFailure("Remove created BAR", gtp5gnl.RemoveBAROID(g.client, g.link.link, p.OID))
	}
	for i := len(applied.CreateURRs) - 1; i >= 0; i-- {
		p := applied.CreateURRs[i]
		_, err := gtp5gnl.RemoveURROID(g.client, g.link.link, p.OID)
		logFailure("Remove created URR", err)
		if err == nil {
			g.ps.DelPeriodReportTimer(request.SEID, p.URRID)
		}
	}
	for i := len(applied.CreateQERs) - 1; i >= 0; i-- {
		p := applied.CreateQERs[i]
		logFailure("Remove created QER", gtp5gnl.RemoveQEROID(g.client, g.link.link, p.OID))
	}
	for i := len(applied.CreateFARs) - 1; i >= 0; i-- {
		p := applied.CreateFARs[i]
		logFailure("Remove created FAR", gtp5gnl.RemoveFAROID(g.client, g.link.link, p.OID))
	}
}

// With rollback metadata, stop at the first failure and attempt compensation.
// Without it, cleanup continues after individual removal failures.
func (g *Gtp5g) executeModificationPlan(
	plan *modificationPlan,
) (*executionResult, error) {
	result := newExecutionResult(plan.SEID)
	applied := result.AppliedPlan
	transactional := plan.Rollback != nil

	var executionErr error
	handleFailure := func(err error) bool {
		g.log.Error(err)
		if transactional {
			g.rollbackApplied(plan, applied)
			result.AppliedPlan = newModificationPlan(plan.SEID)
			result.USAReports = nil
			return true
		}
		if executionErr == nil {
			executionErr = err
		}
		return false
	}

	for _, p := range plan.CreateFARs {
		if err := gtp5gnl.CreateFAROID(g.client, g.link.link, p.OID, p.Attrs); err != nil {
			wrapped := errors.Wrapf(err, "modificationPlan: CreateFAR[%#x] failed", p.FARID)
			handleFailure(wrapped)
			return result, wrapped
		}
		applied.CreateFARs = append(applied.CreateFARs, p)
	}
	for _, p := range plan.CreateQERs {
		if err := gtp5gnl.CreateQEROID(g.client, g.link.link, p.OID, p.Attrs); err != nil {
			wrapped := errors.Wrapf(err, "modificationPlan: CreateQER[%#x] failed", p.QERID)
			handleFailure(wrapped)
			return result, wrapped
		}
		applied.CreateQERs = append(applied.CreateQERs, p)
	}
	for _, p := range plan.CreateURRs {
		if p.ReportingTrigger.PERIO() && p.MeasurePeriod > 0 {
			g.ps.AddPeriodReportTimer(plan.SEID, p.URRID, p.MeasurePeriod)
		}
		if err := gtp5gnl.CreateURROID(g.client, g.link.link, p.OID, p.Attrs); err != nil {
			g.ps.DelPeriodReportTimer(plan.SEID, p.URRID)
			wrapped := errors.Wrapf(err, "modificationPlan: CreateURR[%#x] failed", p.URRID)
			handleFailure(wrapped)
			return result, wrapped
		}
		applied.CreateURRs = append(applied.CreateURRs, p)
	}
	for _, p := range plan.CreateBARs {
		if err := gtp5gnl.CreateBAROID(g.client, g.link.link, p.OID, p.Attrs); err != nil {
			wrapped := errors.Wrapf(err, "modificationPlan: CreateBAR[%#x] failed", p.BARID)
			handleFailure(wrapped)
			return result, wrapped
		}
		applied.CreateBARs = append(applied.CreateBARs, p)
	}
	for _, p := range plan.CreatePDRs {
		if err := gtp5gnl.CreatePDROID(g.client, g.link.link, p.OID, p.Attrs); err != nil {
			wrapped := errors.Wrapf(err, "modificationPlan: CreatePDR[%#x] failed", p.PDRID)
			handleFailure(wrapped)
			return result, wrapped
		}
		applied.CreatePDRs = append(applied.CreatePDRs, p)
	}

	for _, p := range plan.UpdateFARs {
		if err := gtp5gnl.UpdateFAROID(g.client, g.link.link, p.OID, p.Attrs); err != nil {
			wrapped := errors.Wrapf(err, "executeModificationPlan: UpdateFAR[%#x] failed", p.FARID)
			if handleFailure(wrapped) {
				return result, wrapped
			}
			continue
		}
		applied.UpdateFARs = append(applied.UpdateFARs, p)
		if !transactional && p.ApplyAction != nil {
			g.applyAction(plan.SEID, int(p.FARID), *p.ApplyAction)
		}
	}
	for _, p := range plan.UpdateQERs {
		if err := gtp5gnl.UpdateQEROID(g.client, g.link.link, p.OID, p.Attrs); err != nil {
			wrapped := errors.Wrapf(err, "executeModificationPlan: UpdateQER[%#x] failed", p.QERID)
			if handleFailure(wrapped) {
				return result, wrapped
			}
			continue
		}
		applied.UpdateQERs = append(applied.UpdateQERs, p)
	}
	for _, p := range plan.UpdateURRs {
		rs, err := gtp5gnl.UpdateURROID(g.client, g.link.link, p.OID, p.Attrs)
		if err != nil {
			wrapped := errors.Wrapf(err, "executeModificationPlan: UpdateURR[%#x] failed", p.URRID)
			if handleFailure(wrapped) {
				return result, wrapped
			}
			continue
		}
		applied.UpdateURRs = append(applied.UpdateURRs, p)
		for _, r := range rs {
			result.USAReports = append(result.USAReports, g.convertUSAReport(r))
		}
	}
	for _, p := range plan.UpdateBARs {
		if err := gtp5gnl.UpdateBAROID(g.client, g.link.link, p.OID, p.Attrs); err != nil {
			wrapped := errors.Wrapf(err, "executeModificationPlan: UpdateBAR[%#x] failed", p.BARID)
			if handleFailure(wrapped) {
				return result, wrapped
			}
			continue
		}
		applied.UpdateBARs = append(applied.UpdateBARs, p)
	}
	for _, p := range plan.UpdatePDRs {
		if err := gtp5gnl.UpdatePDROID(g.client, g.link.link, p.OID, p.Attrs); err != nil {
			wrapped := errors.Wrapf(err, "executeModificationPlan: UpdatePDR[%#x] failed", p.PDRID)
			if handleFailure(wrapped) {
				return result, wrapped
			}
			continue
		}
		applied.UpdatePDRs = append(applied.UpdatePDRs, p)
	}

	for _, p := range plan.QueryURRs {
		rs, err := gtp5gnl.GetReportOID(g.client, g.link.link, p.OID)
		if err != nil {
			wrapped := errors.Wrapf(err, "executeModificationPlan: QueryURR[%#x] failed", p.URRID)
			if handleFailure(wrapped) {
				return result, wrapped
			}
			continue
		}
		applied.QueryURRs = append(applied.QueryURRs, p)
		for _, r := range rs {
			result.USAReports = append(result.USAReports, g.convertUSAReport(r))
		}
	}

	for _, p := range plan.RemovePDRs {
		if err := cleanupRemovalError(gtp5gnl.RemovePDROID(g.client, g.link.link, p.OID), transactional); err != nil {
			wrapped := errors.Wrapf(err, "executeModificationPlan: RemovePDR[%#x] failed", p.PDRID)
			if handleFailure(wrapped) {
				return result, wrapped
			}
			continue
		}
		applied.RemovePDRs = append(applied.RemovePDRs, p)
	}
	for _, p := range plan.RemoveBARs {
		if err := cleanupRemovalError(gtp5gnl.RemoveBAROID(g.client, g.link.link, p.OID), transactional); err != nil {
			wrapped := errors.Wrapf(err, "executeModificationPlan: RemoveBAR[%#x] failed", p.BARID)
			if handleFailure(wrapped) {
				return result, wrapped
			}
			continue
		}
		applied.RemoveBARs = append(applied.RemoveBARs, p)
	}
	for _, p := range plan.RemoveURRs {
		rs, err := gtp5gnl.RemoveURROID(g.client, g.link.link, p.OID)
		err = cleanupRemovalError(err, transactional)
		if err != nil {
			wrapped := errors.Wrapf(err, "executeModificationPlan: RemoveURR[%#x] failed", p.URRID)
			if handleFailure(wrapped) {
				return result, wrapped
			}
			continue
		}
		g.ps.DelPeriodReportTimer(plan.SEID, p.URRID)
		applied.RemoveURRs = append(applied.RemoveURRs, p)
		for _, r := range rs {
			result.USAReports = append(result.USAReports, g.convertUSAReport(r))
		}
	}
	for _, p := range plan.RemoveQERs {
		if err := cleanupRemovalError(gtp5gnl.RemoveQEROID(g.client, g.link.link, p.OID), transactional); err != nil {
			wrapped := errors.Wrapf(err, "executeModificationPlan: RemoveQER[%#x] failed", p.QERID)
			if handleFailure(wrapped) {
				return result, wrapped
			}
			continue
		}
		applied.RemoveQERs = append(applied.RemoveQERs, p)
	}
	for _, p := range plan.RemoveFARs {
		if err := cleanupRemovalError(gtp5gnl.RemoveFAROID(g.client, g.link.link, p.OID), transactional); err != nil {
			wrapped := errors.Wrapf(err, "executeModificationPlan: RemoveFAR[%#x] failed", p.FARID)
			if handleFailure(wrapped) {
				return result, wrapped
			}
			continue
		}
		applied.RemoveFARs = append(applied.RemoveFARs, p)
	}

	// Delay non-kernel FAR side effects until the transaction has succeeded.
	if transactional {
		for _, p := range applied.UpdateFARs {
			if p.ApplyAction != nil {
				g.applyAction(plan.SEID, int(p.FARID), *p.ApplyAction)
			}
		}
	}

	return result, executionErr
}

// A failed Create triggers compensation for earlier successful Creates.
func (g *Gtp5g) executeEstablishmentPlan(
	plan *modificationPlan,
) (*executionResult, error) {
	result := newExecutionResult(plan.SEID)
	applied := result.AppliedPlan
	fail := func(err error) (*executionResult, error) {
		g.rollbackApplied(plan, applied)
		result.AppliedPlan = newModificationPlan(plan.SEID)
		result.USAReports = nil
		return result, err
	}

	for _, p := range plan.CreateFARs {
		if err := gtp5gnl.CreateFAROID(g.client, g.link.link, p.OID, p.Attrs); err != nil {
			return fail(errors.Wrapf(err, "EstablishmentPlan: CreateFAR[%#x] failed", p.FARID))
		}
		applied.CreateFARs = append(applied.CreateFARs, p)
	}
	for _, p := range plan.CreateQERs {
		if err := gtp5gnl.CreateQEROID(g.client, g.link.link, p.OID, p.Attrs); err != nil {
			return fail(errors.Wrapf(err, "EstablishmentPlan: CreateQER[%#x] failed", p.QERID))
		}
		applied.CreateQERs = append(applied.CreateQERs, p)
	}
	for _, p := range plan.CreateURRs {
		if p.ReportingTrigger.PERIO() && p.MeasurePeriod > 0 {
			g.ps.AddPeriodReportTimer(plan.SEID, p.URRID, p.MeasurePeriod)
		}
		if err := gtp5gnl.CreateURROID(g.client, g.link.link, p.OID, p.Attrs); err != nil {
			g.ps.DelPeriodReportTimer(plan.SEID, p.URRID)
			return fail(errors.Wrapf(err, "EstablishmentPlan: CreateURR[%#x] failed", p.URRID))
		}
		applied.CreateURRs = append(applied.CreateURRs, p)
	}
	for _, p := range plan.CreateBARs {
		if err := gtp5gnl.CreateBAROID(g.client, g.link.link, p.OID, p.Attrs); err != nil {
			return fail(errors.Wrapf(err, "EstablishmentPlan: CreateBAR[%#x] failed", p.BARID))
		}
		applied.CreateBARs = append(applied.CreateBARs, p)
	}
	for _, p := range plan.CreatePDRs {
		if err := gtp5gnl.CreatePDROID(g.client, g.link.link, p.OID, p.Attrs); err != nil {
			return fail(errors.Wrapf(err, "EstablishmentPlan: CreatePDR[%#x] failed", p.PDRID))
		}
		applied.CreatePDRs = append(applied.CreatePDRs, p)
	}

	return result, nil
}

// An already-absent rule satisfies cleanup, but remains an error in a transaction.
func cleanupRemovalError(err error, transactional bool) error {
	if !transactional && errors.Is(err, syscall.ENOENT) {
		return nil
	}
	return err
}
