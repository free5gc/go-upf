package pfcp

import (
	"github.com/pkg/errors"
	"github.com/wmnsk/go-pfcp/ie"

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
// Validate* methods - validation phase (check state, build plans)
// ============================================================================

// ValidateCreatePDR validates CreatePDR and builds plan without modifying state
func (s *Session) ValidateCreatePDR(req *ie.IE) (*forwarder.PDRPlan, error) {
	plan, err := s.driver.BuildCreatePDRPlan(s.LocalID, req)
	if err != nil {
		return nil, ErrRuleCreationModificationFailed
	}

	return plan, nil
}

// ValidateUpdatePDR validates UpdatePDR and builds plan without modifying state
func (s *Session) ValidateUpdatePDR(req *ie.IE) (*forwarder.PDRPlan, error) {
	plan, err := s.driver.BuildUpdatePDRPlan(s.LocalID, req)
	if err != nil {
		return nil, ErrMissingMandatoryIE
	}

	return plan, nil
}

// ValidateRemovePDR validates RemovePDR and builds plan without modifying state
func (s *Session) ValidateRemovePDR(req *ie.IE) (*forwarder.PDRPlan, error) {
	plan, err := s.driver.BuildRemovePDRPlan(s.LocalID, req)
	if err != nil {
		return nil, ErrMissingMandatoryIE
	}

	return plan, nil
}

// ValidateCreateFAR validates CreateFAR and builds plan without modifying state
func (s *Session) ValidateCreateFAR(req *ie.IE) (*forwarder.FARPlan, error) {
	plan, err := s.driver.BuildCreateFARPlan(s.LocalID, req)
	if err != nil {
		return nil, ErrMissingMandatoryIE
	}

	return plan, nil
}

// ValidateUpdateFAR validates UpdateFAR and builds plan without modifying state
func (s *Session) ValidateUpdateFAR(req *ie.IE) (*forwarder.FARPlan, error) {
	plan, err := s.driver.BuildUpdateFARPlan(s.LocalID, req)
	if err != nil {
		return nil, ErrMissingMandatoryIE
	}

	return plan, nil
}

// ValidateRemoveFAR validates RemoveFAR and builds plan without modifying state
func (s *Session) ValidateRemoveFAR(req *ie.IE) (*forwarder.FARPlan, error) {
	plan, err := s.driver.BuildRemoveFARPlan(s.LocalID, req)
	if err != nil {
		return nil, ErrMissingMandatoryIE
	}

	return plan, nil
}

// ValidateCreateQER validates CreateQER and builds plan without modifying state
func (s *Session) ValidateCreateQER(req *ie.IE) (*forwarder.QERPlan, error) {
	plan, err := s.driver.BuildCreateQERPlan(s.LocalID, req)
	if err != nil {
		return nil, ErrMissingMandatoryIE
	}

	return plan, nil
}

// ValidateUpdateQER validates UpdateQER and builds plan without modifying state
func (s *Session) ValidateUpdateQER(req *ie.IE) (*forwarder.QERPlan, error) {
	plan, err := s.driver.BuildUpdateQERPlan(s.LocalID, req)
	if err != nil {
		return nil, ErrMissingMandatoryIE
	}

	return plan, nil
}

// ValidateRemoveQER validates RemoveQER and builds plan without modifying state
func (s *Session) ValidateRemoveQER(req *ie.IE) (*forwarder.QERPlan, error) {
	plan, err := s.driver.BuildRemoveQERPlan(s.LocalID, req)
	if err != nil {
		return nil, ErrMissingMandatoryIE
	}

	return plan, nil
}

// ValidateCreateURR validates CreateURR and builds plan without modifying state
func (s *Session) ValidateCreateURR(req *ie.IE) (*forwarder.URRPlan, error) {
	plan, err := s.driver.BuildCreateURRPlan(s.LocalID, req)
	if err != nil {
		return nil, ErrMissingMandatoryIE
	}

	return plan, nil
}

// ValidateUpdateURR validates UpdateURR and builds plan without modifying state
func (s *Session) ValidateUpdateURR(req *ie.IE) (*forwarder.URRPlan, error) {
	plan, err := s.driver.BuildUpdateURRPlan(s.LocalID, req)
	if err != nil {
		return nil, ErrMissingMandatoryIE
	}

	return plan, nil
}

// ValidateRemoveURR validates RemoveURR and builds plan without modifying state
func (s *Session) ValidateRemoveURR(req *ie.IE) (*forwarder.URRPlan, error) {
	plan, err := s.driver.BuildRemoveURRPlan(s.LocalID, req)
	if err != nil {
		return nil, ErrMissingMandatoryIE
	}

	return plan, nil
}

// ValidateQueryURR validates QueryURR and builds plan without modifying state
func (s *Session) ValidateQueryURR(req *ie.IE) (*forwarder.URRPlan, error) {
	plan, err := s.driver.BuildQueryURRPlan(s.LocalID, req)
	if err != nil {
		return nil, ErrMissingMandatoryIE
	}

	return plan, nil
}

// ValidateCreateBAR validates CreateBAR and builds plan without modifying state
func (s *Session) ValidateCreateBAR(req *ie.IE) (*forwarder.BARPlan, error) {
	plan, err := s.driver.BuildCreateBARPlan(s.LocalID, req)
	if err != nil {
		return nil, ErrMissingMandatoryIE
	}

	return plan, nil
}

// ValidateUpdateBAR validates UpdateBAR and builds plan without modifying state
func (s *Session) ValidateUpdateBAR(req *ie.IE) (*forwarder.BARPlan, error) {
	plan, err := s.driver.BuildUpdateBARPlan(s.LocalID, req)
	if err != nil {
		return nil, ErrMissingMandatoryIE
	}

	return plan, nil
}

// ValidateRemoveBAR validates RemoveBAR and builds plan without modifying state
func (s *Session) ValidateRemoveBAR(req *ie.IE) (*forwarder.BARPlan, error) {
	plan, err := s.driver.BuildRemoveBARPlan(s.LocalID, req)
	if err != nil {
		return nil, ErrMissingMandatoryIE
	}

	return plan, nil
}

// ============================================================================
// Apply* methods - apply phase (update internal state after execution)
// ============================================================================

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
	info := newPDRInfo(plan)
	for urrid := range info.RelatedURRIDs {
		s.URRIDs[urrid].refPdrNum++
	}

	s.PDRIDs[plan.PDRID] = info
}

// ApplyUpdatePDR updates session state after UpdatePDR execution
// Returns USAReports from disassociated URRs
func (s *Session) ApplyUpdatePDR(plan *forwarder.PDRPlan) []report.USAReport {
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

	return usars
}

// ApplyCreateFAR updates session state after CreateFAR execution
func (s *Session) ApplyCreateFAR(plan *forwarder.FARPlan) {
	s.FARIDs[plan.FARID] = struct{}{}
}

// ApplyRemoveFAR updates session state after RemoveFAR execution
func (s *Session) ApplyRemoveFAR(plan *forwarder.FARPlan) {
	delete(s.FARIDs, plan.FARID)
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
}

// ApplyUpdateQER merges fields present in Update QER into desired state.
func (s *Session) ApplyUpdateQER(plan *forwarder.QERPlan) {
	s.QERIDs[plan.QERID] = mergeQERInfo(s.QERIDs[plan.QERID], plan.DesiredState)
}

// ApplyRemoveQER updates session state after RemoveQER execution
func (s *Session) ApplyRemoveQER(plan *forwarder.QERPlan) {
	delete(s.QERIDs, plan.QERID)
}

// ApplyCreateURR updates session state after CreateURR execution
func (s *Session) ApplyCreateURR(plan *forwarder.URRPlan) {
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
}

// ApplyCreateBAR updates session state after CreateBAR execution
func (s *Session) ApplyCreateBAR(plan *forwarder.BARPlan) {
	s.BARIDs[plan.BARID] = struct{}{}
}

// ApplyRemoveBAR updates session state after RemoveBAR execution
func (s *Session) ApplyRemoveBAR(plan *forwarder.BARPlan) {
	delete(s.BARIDs, plan.BARID)
}

// CleanupRemovedURRs removes URRInfo entries marked as removed
func (s *Session) CleanupRemovedURRs() {
	for id, info := range s.URRIDs {
		if info.removed {
			delete(s.URRIDs, id)
		}
	}
}
