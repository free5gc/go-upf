package pfcp

import (
	"time"

	"github.com/khirono/go-nl"
	"github.com/pkg/errors"
	"github.com/wmnsk/go-pfcp/ie"

	"github.com/free5gc/go-gtp5gnl"
	"github.com/free5gc/go-upf/internal/forwarder"
	"github.com/free5gc/go-upf/internal/report"
)

var (
	ErrMissingMandatoryIE             = errors.New("mandatory IE missing or incorrect")
	ErrMissingConditionalIE           = errors.New("conditional IE missing or incorrect")
	ErrRuleNotFound                   = errors.New("rule not found")
	ErrRuleCreationModificationFailed = errors.New("rule creation/modification failed")
	ErrMutualExclusionConflict        = errors.New("conflicting operations on same rule")
)

func (s *Session) Close() []report.USAReport {
	plan := forwarder.NewModificationPlan(s.LocalID)

	// Build Remove plans for all rules
	for id := range s.FARIDs {
		req := ie.NewRemoveFAR(ie.NewFARID(id))
		p, err := s.driver.BuildRemoveFARPlan(s.LocalID, req)
		if err != nil {
			s.log.Errorf("Close BuildRemoveFARPlan[%#x] err: %v", id, err)
			continue
		}
		plan.RemoveFARs = append(plan.RemoveFARs, p)
	}
	for id := range s.QERIDs {
		req := ie.NewRemoveQER(ie.NewQERID(id))
		p, err := s.driver.BuildRemoveQERPlan(s.LocalID, req)
		if err != nil {
			s.log.Errorf("Close BuildRemoveQERPlan[%#x] err: %v", id, err)
			continue
		}
		plan.RemoveQERs = append(plan.RemoveQERs, p)
	}
	for id := range s.URRIDs {
		req := ie.NewRemoveURR(ie.NewURRID(id))
		p, err := s.driver.BuildRemoveURRPlan(s.LocalID, req)
		if err != nil {
			s.log.Errorf("Close BuildRemoveURRPlan[%#x] err: %v", id, err)
			continue
		}
		plan.RemoveURRs = append(plan.RemoveURRs, p)
	}
	for id := range s.BARIDs {
		req := ie.NewRemoveBAR(ie.NewBARID(id))
		p, err := s.driver.BuildRemoveBARPlan(s.LocalID, req)
		if err != nil {
			s.log.Errorf("Close BuildRemoveBARPlan[%#x] err: %v", id, err)
			continue
		}
		plan.RemoveBARs = append(plan.RemoveBARs, p)
	}
	for id := range s.PDRIDs {
		req := ie.NewRemovePDR(ie.NewPDRID(id))
		p, err := s.driver.BuildRemovePDRPlan(s.LocalID, req)
		if err != nil {
			s.log.Errorf("Close BuildRemovePDRPlan[%#x] err: %v", id, err)
			continue
		}
		plan.RemovePDRs = append(plan.RemovePDRs, p)
	}

	// Execute all Remove operations (best-effort)
	execResult, err := s.driver.ExecuteModificationPlan(plan)
	if err != nil {
		s.log.Errorf("Execute Deletion Plan err: %v", err)
	}

	// Apply state changes and collect USAReports
	var usars []report.USAReport

	for _, p := range plan.RemovePDRs {
		rs := s.ApplyRemovePDR(p)
		if len(rs) > 0 {
			usars = append(usars, rs...)
		}
	}
	for _, p := range plan.RemoveBARs {
		s.ApplyRemoveBAR(p)
	}
	for _, p := range plan.RemoveURRs {
		s.ApplyRemoveURR(p)
	}
	for _, p := range plan.RemoveQERs {
		s.ApplyRemoveQER(p)
	}
	for _, p := range plan.RemoveFARs {
		s.ApplyRemoveFAR(p)
	}

	// Collect USAReports from execution result (RemoveURR)
	if execResult != nil && len(execResult.USAReports) > 0 {
		for i := range execResult.USAReports {
			execResult.USAReports[i].USARTrigger.Flags |= report.USAR_TRIG_TERMR
		}
		usars = append(usars, execResult.USAReports...)
	}

	for _, q := range s.q {
		close(q)
	}
	return usars
}

func (s *Session) diassociateURR(urrid uint32) []report.USAReport {
	urrInfo, ok := s.URRIDs[urrid]
	if !ok {
		return nil
	}

	if urrInfo.refPdrNum > 0 {
		urrInfo.refPdrNum--
		if urrInfo.refPdrNum == 0 {
			// indicates usage report being reported for a URR due to dissociated from the last PDR
			usars, err := s.driver.QueryURR(s.LocalID, urrid)
			if err != nil {
				return nil
			}
			for i := range usars {
				usars[i].USARTrigger.Flags |= report.USAR_TRIG_TERMR
			}
			return usars
		}
	} else {
		s.log.Errorf("diassociateURR: wrong refPdrNum(%d)", urrInfo.refPdrNum)
	}
	return nil
}

// ============================================================================
// Apply* methods - apply phase (update internal state after execution)
// ============================================================================

func cloneRuleAttrs(attrs []nl.Attr) []nl.Attr {
	cloned := make([]nl.Attr, 0, len(attrs))
	for _, attr := range attrs {
		var value nl.Encoder
		switch v := attr.Value.(type) {
		case nl.AttrList:
			value = nl.AttrList(cloneRuleAttrs(v))
		case nl.AttrBytes:
			value = nl.AttrBytes(append([]byte(nil), v...))
		default:
			value = v
		}
		cloned = append(cloned, nl.Attr{Type: attr.Type, Value: value})
	}
	return cloned
}

func mergeRuleAttrs(current, patch []nl.Attr) []nl.Attr {
	replaced := make(map[uint16]struct{}, len(patch))
	for _, attr := range patch {
		replaced[attr.Type] = struct{}{}
	}

	merged := make([]nl.Attr, 0, len(current)+len(patch))
	for _, attr := range current {
		if _, replace := replaced[attr.Type]; !replace {
			merged = append(merged, cloneRuleAttrs([]nl.Attr{attr})[0])
		}
	}
	merged = append(merged, cloneRuleAttrs(patch)...)
	return merged
}

func mergeFARRuleAttrs(current, patch []nl.Attr) []nl.Attr {
	merged := mergeRuleAttrs(current, patch)
	for i := range merged {
		if merged[i].Type != gtp5gnl.FAR_FORWARDING_PARAMETER {
			continue
		}
		patchNested, patchOK := merged[i].Value.(nl.AttrList)
		if !patchOK {
			continue
		}
		for _, old := range current {
			oldNested, oldOK := old.Value.(nl.AttrList)
			if old.Type == merged[i].Type && oldOK {
				// Update Forwarding Parameters is the only partial nested rule
				// attribute merged here. Rule families use overlapping numeric
				// attribute IDs, so this must remain FAR-specific.
				merged[i].Value = nl.AttrList(mergeRuleAttrs(oldNested, patchNested))
				break
			}
		}
	}
	return merged
}

func clonePDRRulePlan(plan *forwarder.PDRPlan) *forwarder.PDRPlan {
	if plan == nil {
		return nil
	}
	cloned := *plan
	cloned.Op = forwarder.OpCreate
	cloned.Attrs = cloneRuleAttrs(plan.Attrs)
	cloned.URRIDs = append([]uint32(nil), plan.URRIDs...)
	cloned.QERIDs = append([]uint32(nil), plan.QERIDs...)
	if plan.SourceInterface != nil {
		value := *plan.SourceInterface
		cloned.SourceInterface = &value
	}
	return &cloned
}

func mergePDRRulePlan(current, patch *forwarder.PDRPlan) *forwarder.PDRPlan {
	if current == nil {
		return clonePDRRulePlan(patch)
	}
	next := clonePDRRulePlan(current)
	next.Attrs = mergeRuleAttrs(current.Attrs, patch.Attrs)
	next.OriginalIE = patch.OriginalIE
	if patch.FARIDPresent {
		next.FARID = patch.FARID
		next.FARIDPresent = true
	}
	if patch.URRIDsPresent {
		next.URRIDs = append([]uint32(nil), patch.URRIDs...)
		next.URRIDsPresent = true
	}
	if patch.QERIDsPresent {
		next.QERIDs = append([]uint32(nil), patch.QERIDs...)
		next.QERIDsPresent = true
	}
	if patch.SourceInterface != nil {
		value := *patch.SourceInterface
		next.SourceInterface = &value
	}
	return next
}

func cloneFARRulePlan(plan *forwarder.FARPlan) *forwarder.FARPlan {
	if plan == nil {
		return nil
	}
	cloned := *plan
	cloned.Op = forwarder.OpCreate
	cloned.Attrs = cloneRuleAttrs(plan.Attrs)
	cloned.ApplyAction = nil
	return &cloned
}

func mergeFARRulePlan(current, patch *forwarder.FARPlan) *forwarder.FARPlan {
	if current == nil {
		return cloneFARRulePlan(patch)
	}
	next := cloneFARRulePlan(current)
	next.Attrs = mergeFARRuleAttrs(current.Attrs, patch.Attrs)
	next.OriginalIE = patch.OriginalIE
	return next
}

func cloneQERRulePlan(plan *forwarder.QERPlan) *forwarder.QERPlan {
	if plan == nil {
		return nil
	}
	cloned := *plan
	cloned.Op = forwarder.OpCreate
	cloned.Attrs = cloneRuleAttrs(plan.Attrs)
	return &cloned
}

func mergeQERRulePlan(current, patch *forwarder.QERPlan) *forwarder.QERPlan {
	if current == nil {
		return cloneQERRulePlan(patch)
	}
	next := cloneQERRulePlan(current)
	next.Attrs = mergeRuleAttrs(current.Attrs, patch.Attrs)
	next.OriginalIE = patch.OriginalIE
	return next
}

func cloneURRRulePlan(plan *forwarder.URRPlan) *forwarder.URRPlan {
	if plan == nil {
		return nil
	}
	cloned := *plan
	cloned.Op = forwarder.OpCreate
	cloned.Attrs = cloneRuleAttrs(plan.Attrs)
	return &cloned
}

func mergeURRRulePlan(current, patch *forwarder.URRPlan) *forwarder.URRPlan {
	if current == nil {
		return cloneURRRulePlan(patch)
	}
	next := cloneURRRulePlan(current)
	next.Attrs = mergeRuleAttrs(current.Attrs, patch.Attrs)
	next.OriginalIE = patch.OriginalIE
	if patch.MeasureMethod != 0 {
		next.MeasureMethod = patch.MeasureMethod
	}
	if patch.MeasureInfoIE != nil {
		next.MeasureInfoIE = patch.MeasureInfoIE
	}
	for _, attr := range next.Attrs {
		switch attr.Type {
		case gtp5gnl.URR_REPORTING_TRIGGER:
			if value, ok := attr.Value.(nl.AttrU32); ok {
				next.ReportingTrigger.Flags = uint32(value)
			}
		case gtp5gnl.URR_MEASUREMENT_PERIOD:
			if value, ok := attr.Value.(nl.AttrU32); ok {
				next.MeasurePeriod = time.Duration(value)
			}
		}
	}
	return next
}

func cloneBARRulePlan(plan *forwarder.BARPlan) *forwarder.BARPlan {
	if plan == nil {
		return nil
	}
	cloned := *plan
	cloned.Op = forwarder.OpCreate
	cloned.Attrs = cloneRuleAttrs(plan.Attrs)
	return &cloned
}

func mergeBARRulePlan(current, patch *forwarder.BARPlan) *forwarder.BARPlan {
	if current == nil {
		return cloneBARRulePlan(patch)
	}
	next := cloneBARRulePlan(current)
	next.Attrs = mergeRuleAttrs(current.Attrs, patch.Attrs)
	next.OriginalIE = patch.OriginalIE
	return next
}

func uint32Set(ids []uint32) map[uint32]struct{} {
	set := make(map[uint32]struct{}, len(ids))
	for _, id := range ids {
		set[id] = struct{}{}
	}
	return set
}
func newPDRInfo(plan *forwarder.PDRPlan) *PDRInfo {
	info := &PDRInfo{
		FARID:         plan.FARID,
		HasFARID:      plan.FARIDPresent,
		RelatedURRIDs: uint32Set(plan.URRIDs),
		RelatedQERIDs: uint32Set(plan.QERIDs),
	}
	if plan.SourceInterface != nil {
		info.SourceInterface = *plan.SourceInterface
		info.HasSourceInterface = true
	}
	return info
}

func mergePDRInfo(current *PDRInfo, patch *forwarder.PDRPlan) *PDRInfo {
	if current == nil {
		return newPDRInfo(patch)
	}

	next := *current
	if patch.FARIDPresent {
		next.FARID = patch.FARID
		next.HasFARID = true
	}
	if patch.URRIDsPresent {
		next.RelatedURRIDs = uint32Set(patch.URRIDs)
	}
	if patch.QERIDsPresent {
		next.RelatedQERIDs = uint32Set(patch.QERIDs)
	}
	if patch.SourceInterface != nil {
		next.SourceInterface = *patch.SourceInterface
		next.HasSourceInterface = true
	}
	return &next
}

// ApplyCreatePDR updates session state after CreatePDR execution
func (s *Session) ApplyCreatePDR(plan *forwarder.PDRPlan) {
	s.ensureAppliedRulePlans().pdrs[plan.PDRID] = clonePDRRulePlan(plan)
	info := newPDRInfo(plan)
	for urrid := range info.RelatedURRIDs {
		s.URRIDs[urrid].refPdrNum++
	}

	s.PDRIDs[plan.PDRID] = info
}

// ApplyUpdatePDR updates session state after UpdatePDR execution
// Returns USAReports from disassociated URRs
func (s *Session) ApplyUpdatePDR(plan *forwarder.PDRPlan) []report.USAReport {
	applied := s.ensureAppliedRulePlans()
	applied.pdrs[plan.PDRID] = mergePDRRulePlan(applied.pdrs[plan.PDRID], plan)
	current := s.PDRIDs[plan.PDRID]
	next := mergePDRInfo(current, plan)

	var reports []report.USAReport
	if plan.URRIDsPresent {
		for urrid := range current.RelatedURRIDs {
			if _, exists := next.RelatedURRIDs[urrid]; !exists {
				reports = append(reports, s.diassociateURR(urrid)...)
			}
		}
		for urrid := range next.RelatedURRIDs {
			if _, exists := current.RelatedURRIDs[urrid]; !exists {
				s.URRIDs[urrid].refPdrNum++
			}
		}
	}

	s.PDRIDs[plan.PDRID] = next
	return reports
}

// ApplyRemovePDR updates session state after RemovePDR execution
// Returns USAReports from disassociated URRs
func (s *Session) ApplyRemovePDR(plan *forwarder.PDRPlan) []report.USAReport {
	pdrInfo := s.PDRIDs[plan.PDRID]

	var usars []report.USAReport
	for urrid := range pdrInfo.RelatedURRIDs {
		usars = append(usars, s.diassociateURR(urrid)...)
	}
	delete(s.PDRIDs, plan.PDRID)
	delete(s.ensureAppliedRulePlans().pdrs, plan.PDRID)

	return usars
}

// ApplyCreateFAR updates session state after CreateFAR execution
func (s *Session) ApplyCreateFAR(plan *forwarder.FARPlan) {
	s.FARIDs[plan.FARID] = struct{}{}
	s.ensureAppliedRulePlans().fars[plan.FARID] = cloneFARRulePlan(plan)
}

// ApplyUpdateFAR refreshes the stored kernel-applied rule image.
func (s *Session) ApplyUpdateFAR(plan *forwarder.FARPlan) {
	applied := s.ensureAppliedRulePlans()
	applied.fars[plan.FARID] = mergeFARRulePlan(applied.fars[plan.FARID], plan)
}

// ApplyRemoveFAR updates session state after RemoveFAR execution
func (s *Session) ApplyRemoveFAR(plan *forwarder.FARPlan) {
	delete(s.FARIDs, plan.FARID)
	delete(s.ensureAppliedRulePlans().fars, plan.FARID)
}

func newQERInfo(patch forwarder.QERDesiredStatePatch) *QERInfo {
	return mergeQERInfo(nil, patch)
}

func mergeQERInfo(current *QERInfo, patch forwarder.QERDesiredStatePatch) *QERInfo {
	next := &QERInfo{}
	if current != nil {
		*next = *current
	}
	next.applyDesiredStatePatch(patch)
	return next
}

func (q *QERInfo) applyDesiredStatePatch(patch forwarder.QERDesiredStatePatch) {
	if patch.QFI != nil {
		q.QFI = *patch.QFI
	}
	if patch.GateStatus != nil {
		q.GateUL = patch.GateStatus.Uplink
		q.GateDL = patch.GateStatus.Downlink
		q.HasGate = true
	}
	if patch.GBR != nil {
		q.GBRULBps = patch.GBR.UplinkBps
		q.GBRDLBps = patch.GBR.DownlinkBps
		q.HasGBR = true
	}
	if patch.MBR != nil {
		q.MBRULBps = patch.MBR.UplinkBps
		q.MBRDLBps = patch.MBR.DownlinkBps
		q.HasMBR = true
	}
}

// ApplyCreateQER updates session state after CreateQER execution
func (s *Session) ApplyCreateQER(plan *forwarder.QERPlan) {
	s.QERIDs[plan.QERID] = newQERInfo(plan.DesiredState)
	s.ensureAppliedRulePlans().qers[plan.QERID] = cloneQERRulePlan(plan)
}

// ApplyUpdateQER merges fields present in Update QER into desired state.
func (s *Session) ApplyUpdateQER(plan *forwarder.QERPlan) {
	s.QERIDs[plan.QERID] = mergeQERInfo(s.QERIDs[plan.QERID], plan.DesiredState)
	applied := s.ensureAppliedRulePlans()
	applied.qers[plan.QERID] = mergeQERRulePlan(applied.qers[plan.QERID], plan)
}

// ApplyRemoveQER updates session state after RemoveQER execution
func (s *Session) ApplyRemoveQER(plan *forwarder.QERPlan) {
	delete(s.QERIDs, plan.QERID)
	delete(s.ensureAppliedRulePlans().qers, plan.QERID)
}

// ApplyCreateURR updates session state after CreateURR execution
func (s *Session) ApplyCreateURR(plan *forwarder.URRPlan) {
	s.ensureAppliedRulePlans().urrs[plan.URRID] = cloneURRRulePlan(plan)
	mInfo := &ie.IE{}
	if plan.MeasureInfoIE != nil {
		mInfo = plan.MeasureInfoIE
	}

	s.URRIDs[plan.URRID] = &URRInfo{
		MeasureMethod: report.MeasureMethod{
			DURAT: plan.OriginalIE.HasDURAT(),
			VOLUM: plan.OriginalIE.HasVOLUM(),
			EVENT: plan.OriginalIE.HasEVENT(),
		},
		MeasureInformation: report.MeasureInformation{
			MBQE: mInfo.HasMBQE(),
			INAM: mInfo.HasINAM(),
			RADI: mInfo.HasRADI(),
			ISTM: mInfo.HasISTM(),
			MNOP: mInfo.HasMNOP(),
		},
	}
}

// ApplyUpdateURR updates session state after UpdateURR execution
func (s *Session) ApplyUpdateURR(plan *forwarder.URRPlan) {
	applied := s.ensureAppliedRulePlans()
	applied.urrs[plan.URRID] = mergeURRRulePlan(applied.urrs[plan.URRID], plan)
	urrInfo, ok := s.URRIDs[plan.URRID]
	if !ok {
		return
	}

	// Update MeasureMethod if present in the plan
	if plan.MeasureMethod != 0 {
		urrInfo.DURAT = (plan.MeasureMethod & 0x01) != 0
		urrInfo.VOLUM = (plan.MeasureMethod & 0x02) != 0
		urrInfo.EVENT = (plan.MeasureMethod & 0x04) != 0
	}

	// Update MeasureInformation if present
	if plan.MeasureInfoIE != nil {
		urrInfo.MBQE = plan.MeasureInfoIE.HasMBQE()
		urrInfo.INAM = plan.MeasureInfoIE.HasINAM()
		urrInfo.RADI = plan.MeasureInfoIE.HasRADI()
		urrInfo.ISTM = plan.MeasureInfoIE.HasISTM()
		urrInfo.MNOP = plan.MeasureInfoIE.HasMNOP()
	}
}

// ApplyRemoveURR updates session state after RemoveURR execution
func (s *Session) ApplyRemoveURR(plan *forwarder.URRPlan) {
	if info, ok := s.URRIDs[plan.URRID]; ok {
		info.removed = true
	}
	delete(s.ensureAppliedRulePlans().urrs, plan.URRID)
}

// ApplyCreateBAR updates session state after CreateBAR execution
func (s *Session) ApplyCreateBAR(plan *forwarder.BARPlan) {
	s.BARIDs[plan.BARID] = struct{}{}
	s.ensureAppliedRulePlans().bars[plan.BARID] = cloneBARRulePlan(plan)
}

// ApplyUpdateBAR refreshes the stored kernel-applied rule image.
func (s *Session) ApplyUpdateBAR(plan *forwarder.BARPlan) {
	applied := s.ensureAppliedRulePlans()
	applied.bars[plan.BARID] = mergeBARRulePlan(applied.bars[plan.BARID], plan)
}

// ApplyRemoveBAR updates session state after RemoveBAR execution
func (s *Session) ApplyRemoveBAR(plan *forwarder.BARPlan) {
	delete(s.BARIDs, plan.BARID)
	delete(s.ensureAppliedRulePlans().bars, plan.BARID)
}

// CleanupRemovedURRs removes URRInfo entries marked as removed
func (s *Session) CleanupRemovedURRs() {
	for id, info := range s.URRIDs {
		if info.removed {
			delete(s.URRIDs, id)
		}
	}
}
