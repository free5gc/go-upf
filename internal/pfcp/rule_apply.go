package pfcp

import (
	"sort"
	"time"

	"github.com/khirono/go-nl"
	"github.com/pkg/errors"

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
				// Update Forwarding Parameters is a partial nested update.
				merged[i].Value = nl.AttrList(mergeRuleAttrs(oldNested, patchNested))
				break
			}
		}
	}
	return merged
}

func newRuleConfig(oid gtp5gnl.OID, attrs []nl.Attr) ruleConfig {
	return ruleConfig{
		OID:   oid,
		Attrs: cloneRuleAttrs(attrs),
	}
}

func (current ruleConfig) merge(attrs []nl.Attr) ruleConfig {
	return ruleConfig{
		OID:   current.OID,
		Attrs: mergeRuleAttrs(current.Attrs, attrs),
	}
}

func (current ruleConfig) mergeFAR(attrs []nl.Attr) ruleConfig {
	return ruleConfig{
		OID:   current.OID,
		Attrs: mergeFARRuleAttrs(current.Attrs, attrs),
	}
}

func uint32Set(ids []uint32) map[uint32]struct{} {
	set := make(map[uint32]struct{}, len(ids))
	for _, id := range ids {
		set[id] = struct{}{}
	}
	return set
}

func sortedUint32Set(set map[uint32]struct{}) []uint32 {
	ids := make([]uint32, 0, len(set))
	for id := range set {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}

func newPDRInfo(plan *forwarder.PDRPlan) *PDRInfo {
	info := &PDRInfo{
		ruleConfig:    newRuleConfig(plan.OID, plan.Attrs),
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
	next.ruleConfig = current.ruleConfig.merge(patch.Attrs)
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

func (info *PDRInfo) rollbackPlan(id uint16) *forwarder.PDRPlan {
	if info == nil {
		return nil
	}
	plan := &forwarder.PDRPlan{
		Op:            forwarder.OpCreate,
		OID:           info.OID,
		Attrs:         cloneRuleAttrs(info.Attrs),
		PDRID:         id,
		FARID:         info.FARID,
		FARIDPresent:  info.HasFARID,
		URRIDs:        sortedUint32Set(info.RelatedURRIDs),
		URRIDsPresent: true,
		QERIDs:        sortedUint32Set(info.RelatedQERIDs),
		QERIDsPresent: true,
	}
	if info.HasSourceInterface {
		sourceInterface := info.SourceInterface
		plan.SourceInterface = &sourceInterface
	}
	return plan
}

func newFARInfo(plan *forwarder.FARPlan) *FARInfo {
	return &FARInfo{ruleConfig: newRuleConfig(plan.OID, plan.Attrs)}
}

func (info *FARInfo) rollbackPlan(id uint32) *forwarder.FARPlan {
	if info == nil {
		return nil
	}
	return &forwarder.FARPlan{
		Op:    forwarder.OpCreate,
		OID:   info.OID,
		Attrs: cloneRuleAttrs(info.Attrs),
		FARID: id,
	}
}

func newQERInfo(plan *forwarder.QERPlan) *QERInfo {
	return mergeQERInfo(nil, plan)
}

func mergeQERInfo(current *QERInfo, plan *forwarder.QERPlan) *QERInfo {
	next := &QERInfo{}
	if current != nil {
		*next = *current
		next.ruleConfig = current.ruleConfig.merge(plan.Attrs)
	} else {
		next.ruleConfig = newRuleConfig(plan.OID, plan.Attrs)
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

func (info *QERInfo) rollbackPlan(id uint32) *forwarder.QERPlan {
	if info == nil {
		return nil
	}
	desired := forwarder.QERDesiredStatePatch{}
	if info.HasQFI {
		qfi := info.QFI
		desired.QFI = &qfi
	}
	if info.HasGate {
		desired.GateStatus = &forwarder.QERGateStatus{
			Uplink:   info.GateUL,
			Downlink: info.GateDL,
		}
	}
	if info.HasGBR {
		desired.GBR = &forwarder.DirectionalBitRate{
			UplinkBps:   info.GBRULBps,
			DownlinkBps: info.GBRDLBps,
		}
	}
	if info.HasMBR {
		desired.MBR = &forwarder.DirectionalBitRate{
			UplinkBps:   info.MBRULBps,
			DownlinkBps: info.MBRDLBps,
		}
	}
	return &forwarder.QERPlan{
		Op:           forwarder.OpCreate,
		OID:          info.OID,
		Attrs:        cloneRuleAttrs(info.Attrs),
		QERID:        id,
		DesiredState: desired,
	}
}

func measurementMethodFromBits(value uint8) report.MeasureMethod {
	return report.MeasureMethod{
		DURAT: value&0x01 != 0,
		VOLUM: value&0x02 != 0,
		EVENT: value&0x04 != 0,
	}
}

func measurementMethodBits(method report.MeasureMethod) uint8 {
	var value uint8
	if method.DURAT {
		value |= 0x01
	}
	if method.VOLUM {
		value |= 0x02
	}
	if method.EVENT {
		value |= 0x04
	}
	return value
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
	info := &URRInfo{
		ruleConfig: newRuleConfig(plan.OID, plan.Attrs),
	}
	info.syncReportingConfig()
	return info
}

// syncReportingConfig projects the complete applied netlink configuration into the
// PFCP reporting fields while leaving SEQN/refPdrNum/removed untouched.
func (info *URRInfo) syncReportingConfig() {
	info.MeasureMethod = report.MeasureMethod{}
	info.MeasureInformation = report.MeasureInformation{}
	info.ReportingTrigger = report.ReportingTrigger{}
	info.MeasurePeriod = 0

	for _, attr := range info.Attrs {
		switch attr.Type {
		case gtp5gnl.URR_MEASUREMENT_METHOD:
			if value, ok := attr.Value.(nl.AttrU8); ok {
				info.MeasureMethod = measurementMethodFromBits(uint8(value))
			}
		case gtp5gnl.URR_MEASUREMENT_INFO:
			if value, ok := attr.Value.(nl.AttrU64); ok {
				info.MeasureInformation = measurementInformationFromBits(uint64(value))
			}
		case gtp5gnl.URR_REPORTING_TRIGGER:
			if value, ok := attr.Value.(nl.AttrU32); ok {
				info.ReportingTrigger.Flags = uint32(value)
			}
		case gtp5gnl.URR_MEASUREMENT_PERIOD:
			if value, ok := attr.Value.(nl.AttrU32); ok {
				info.MeasurePeriod = time.Duration(value)
			}
		}
	}
}

func (info *URRInfo) applyPatch(plan *forwarder.URRPlan) {
	info.ruleConfig = info.ruleConfig.merge(plan.Attrs)
	info.syncReportingConfig()
}

func (info *URRInfo) rollbackPlan(id uint32) *forwarder.URRPlan {
	if info == nil {
		return nil
	}
	return &forwarder.URRPlan{
		Op:               forwarder.OpCreate,
		OID:              info.OID,
		Attrs:            cloneRuleAttrs(info.Attrs),
		URRID:            id,
		MeasureMethod:    measurementMethodBits(info.MeasureMethod),
		ReportingTrigger: info.ReportingTrigger,
		MeasurePeriod:    info.MeasurePeriod,
	}
}

func newBARInfo(plan *forwarder.BARPlan) *BARInfo {
	return &BARInfo{ruleConfig: newRuleConfig(plan.OID, plan.Attrs)}
}

func (info *BARInfo) rollbackPlan(id uint8) *forwarder.BARPlan {
	if info == nil {
		return nil
	}
	return &forwarder.BARPlan{
		Op:    forwarder.OpCreate,
		OID:   info.OID,
		Attrs: cloneRuleAttrs(info.Attrs),
		BARID: id,
	}
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
		s.log.Errorf("dissociateURR: wrong refPdrNum(%d)", urrInfo.refPdrNum)
	}
	return nil
}

func (s *Session) ApplyCreateFAR(plan *forwarder.FARPlan) {
	s.FARIDs[plan.FARID] = newFARInfo(plan)
}

func (s *Session) ApplyUpdateFAR(plan *forwarder.FARPlan) {
	if current := s.FARIDs[plan.FARID]; current != nil {
		current.ruleConfig = current.ruleConfig.mergeFAR(plan.Attrs)
	}
}

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

func (s *Session) ApplyUpdateBAR(plan *forwarder.BARPlan) {
	if current := s.BARIDs[plan.BARID]; current != nil {
		current.ruleConfig = current.ruleConfig.merge(plan.Attrs)
	}
}

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
