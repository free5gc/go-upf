package pfcp

import (
	"github.com/pkg/errors"

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

func newFARInfo(plan *forwarder.FARPlan) *FARInfo {
	return &FARInfo{}
}

func newQERInfo(plan *forwarder.QERPlan) *QERInfo {
	return mergeQERInfo(nil, plan)
}

func mergeQERInfo(current *QERInfo, plan *forwarder.QERPlan) *QERInfo {
	next := &QERInfo{}
	if current != nil {
		*next = *current
	}
	next.applyDesiredStatePatch(plan.DesiredState)
	return next
}

func (q *QERInfo) applyDesiredStatePatch(patch forwarder.QERDesiredStatePatch) {
	if patch.QFI != nil {
		q.QFI = *patch.QFI
		q.HasQFI = true
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

func measurementMethodFromBits(value uint8) report.MeasureMethod {
	return report.MeasureMethod{
		DURAT: value&0x01 != 0,
		VOLUM: value&0x02 != 0,
		EVENT: value&0x04 != 0,
	}
}

func measurementInformationFromBits(value uint64) report.MeasureInformation {
	return report.MeasureInformation{
		MBQE: value&0x01 != 0,
		INAM: value&0x02 != 0,
		RADI: value&0x04 != 0,
		ISTM: value&0x08 != 0,
		MNOP: value&0x10 != 0,
	}
}

func newURRInfo(plan *forwarder.URRPlan) *URRInfo {
	info := &URRInfo{}
	info.applyPatch(plan)
	return info
}

// applyPatch updates only signalled reporting fields and preserves PFCP runtime.
func (info *URRInfo) applyPatch(plan *forwarder.URRPlan) {
	patch := plan.ReportingConfig
	if patch.MeasureMethod != nil {
		info.MeasureMethod = measurementMethodFromBits(*patch.MeasureMethod)
	}
	if patch.MeasureInformation != nil {
		info.MeasureInformation = measurementInformationFromBits(*patch.MeasureInformation)
	}
	if patch.ReportingTrigger != nil {
		info.ReportingTrigger = *patch.ReportingTrigger
	}
	if patch.MeasurePeriod != nil {
		info.MeasurePeriod = *patch.MeasurePeriod
	}
}

func newBARInfo(plan *forwarder.BARPlan) *BARInfo {
	return &BARInfo{}
}

// ApplyCreatePDR publishes a successfully created PDR into Session state.
func (s *Session) ApplyCreatePDR(plan *forwarder.PDRPlan) {
	info := newPDRInfo(plan)
	for urrid := range info.RelatedURRIDs {
		s.URRIDs[urrid].refPdrNum++
	}
	s.PDRIDs[plan.PDRID] = info
}

// ApplyUpdatePDR applies only fields present in a successful UpdatePDR.
func (s *Session) ApplyUpdatePDR(plan *forwarder.PDRPlan) []report.USAReport {
	current := s.PDRIDs[plan.PDRID]
	if current == nil {
		s.ApplyCreatePDR(plan)
		return nil
	}
	next := mergePDRInfo(current, plan)

	var reports []report.USAReport
	if plan.URRIDsPresent {
		for urrid := range current.RelatedURRIDs {
			if _, exists := next.RelatedURRIDs[urrid]; !exists {
				reports = append(reports, s.dissociateURR(urrid)...)
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

// ApplyRemovePDR removes a successfully deleted PDR from Session state.
func (s *Session) ApplyRemovePDR(plan *forwarder.PDRPlan) []report.USAReport {
	pdrInfo := s.PDRIDs[plan.PDRID]
	if pdrInfo == nil {
		return nil
	}

	var usars []report.USAReport
	for urrid := range pdrInfo.RelatedURRIDs {
		usars = append(usars, s.dissociateURR(urrid)...)
	}
	delete(s.PDRIDs, plan.PDRID)
	return usars
}

func (s *Session) dissociateURR(urrid uint32) []report.USAReport {
	urrInfo, ok := s.URRIDs[urrid]
	if !ok {
		return nil
	}

	if urrInfo.refPdrNum > 0 {
		urrInfo.refPdrNum--
		if urrInfo.refPdrNum == 0 {
			usars, err := s.datapath.QueryURR(urrid)
			if err != nil {
				return nil
			}
			for i := range usars {
				usars[i].USARTrigger.Flags |= report.USAR_TRIG_TERMR
			}
			return usars
		}
	} else {
		s.log.Errorf("dissociateURR: wrong refPdrNum(%d)", urrInfo.refPdrNum)
	}
	return nil
}

func (s *Session) ApplyCreateFAR(plan *forwarder.FARPlan) {
	s.FARIDs[plan.FARID] = newFARInfo(plan)
}

// ApplyUpdateFAR has no PFCP metadata to publish yet; configuration is owned by the datapath.
func (s *Session) ApplyUpdateFAR(plan *forwarder.FARPlan) {}

func (s *Session) ApplyRemoveFAR(plan *forwarder.FARPlan) {
	delete(s.FARIDs, plan.FARID)
}

func (s *Session) ApplyCreateQER(plan *forwarder.QERPlan) {
	s.QERIDs[plan.QERID] = newQERInfo(plan)
}

func (s *Session) ApplyUpdateQER(plan *forwarder.QERPlan) {
	s.QERIDs[plan.QERID] = mergeQERInfo(s.QERIDs[plan.QERID], plan)
}

func (s *Session) ApplyRemoveQER(plan *forwarder.QERPlan) {
	delete(s.QERIDs, plan.QERID)
}

func (s *Session) ApplyCreateURR(plan *forwarder.URRPlan) {
	s.URRIDs[plan.URRID] = newURRInfo(plan)
}

func (s *Session) ApplyUpdateURR(plan *forwarder.URRPlan) {
	if info := s.URRIDs[plan.URRID]; info != nil {
		info.applyPatch(plan)
	}
}

// ApplyRemoveURR retains reporting runtime until the response is assembled.
func (s *Session) ApplyRemoveURR(plan *forwarder.URRPlan) {
	if info := s.URRIDs[plan.URRID]; info != nil {
		info.removed = true
	}
}

func (s *Session) ApplyCreateBAR(plan *forwarder.BARPlan) {
	s.BARIDs[plan.BARID] = newBARInfo(plan)
}

// ApplyUpdateBAR has no PFCP metadata to publish yet; configuration is owned by the datapath.
func (s *Session) ApplyUpdateBAR(plan *forwarder.BARPlan) {}

func (s *Session) ApplyRemoveBAR(plan *forwarder.BARPlan) {
	delete(s.BARIDs, plan.BARID)
}

func (s *Session) CleanupRemovedURRs() {
	for id, info := range s.URRIDs {
		if info.removed {
			delete(s.URRIDs, id)
		}
	}
}
