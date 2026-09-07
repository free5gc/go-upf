package pfcp

import (
	"github.com/pkg/errors"

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

func (info *URRInfo) measurementMethod() report.MeasureMethod {
	if info.Config.MeasureMethod == nil {
		return report.MeasureMethod{}
	}
	return measurementMethodFromBits(*info.Config.MeasureMethod)
}
func (info *URRInfo) measurementInformation() report.MeasureInformation {
	if info.Config.MeasureInformation == nil {
		return report.MeasureInformation{}
	}
	return measurementInformationFromBits(*info.Config.MeasureInformation)
}

// Commit publishes the validated candidate after the entire request succeeds.
// No patch is merged here. Reporting I/O remains transitional until the
// coordinator/report lifecycle step; validation itself never queries the driver.
func (state *RuleState) Commit() []report.USAReport {
	s := state.sess
	for id, c := range state.farOverrides {
		n := c.Clone()
		s.FARIDs[id] = &n
	}
	for id, c := range state.qerOverrides {
		n := c.Clone()
		s.QERIDs[id] = &n
	}
	for id, c := range state.barOverrides {
		n := c.Clone()
		s.BARIDs[id] = &n
	}
	for id, c := range state.urrOverrides {
		info := s.URRIDs[id]
		if info == nil {
			info = &URRInfo{}
			s.URRIDs[id] = info
		}
		info.Config = c.Clone()
	}
	var reports []report.USAReport
	// Add new references across the whole candidate before dropping old ones, so
	// moving a URR between PDRs cannot transiently trigger a termination query.
	for id, c := range state.pdrOverrides {
		if _, removed := state.removedPDRs[id]; removed {
			continue
		}
		old := map[uint32]struct{}{}
		if p := s.PDRIDs[id]; p != nil {
			old = uint32Set(p.URRIDs)
		}
		for uid := range uint32Set(c.URRIDs) {
			if _, exists := old[uid]; !exists {
				s.URRIDs[uid].refPdrNum++
			}
		}
	}
	for id, c := range state.pdrOverrides {
		if _, removed := state.removedPDRs[id]; removed {
			continue
		}
		next := uint32Set(c.URRIDs)
		if old := s.PDRIDs[id]; old != nil {
			for uid := range uint32Set(old.URRIDs) {
				if _, exists := next[uid]; !exists {
					reports = append(reports, s.dissociateURR(uid)...)
				}
			}
		}
		n := c.Clone()
		s.PDRIDs[id] = &n
	}
	for id := range state.removedPDRs {
		reports = append(reports, s.ApplyRemovePDR(id)...)
	}
	for id := range state.removedFARs {
		s.ApplyRemoveFAR(id)
	}
	for id := range state.removedQERs {
		s.ApplyRemoveQER(id)
	}
	for id := range state.removedURRs {
		s.ApplyRemoveURR(id)
	}
	for id := range state.removedBARs {
		s.ApplyRemoveBAR(id)
	}
	return reports
}

func (s *Session) ApplyRemovePDR(id uint16) []report.USAReport {
	c := s.PDRIDs[id]
	if c == nil {
		return nil
	}
	var reports []report.USAReport
	for uid := range uint32Set(c.URRIDs) {
		reports = append(reports, s.dissociateURR(uid)...)
	}
	delete(s.PDRIDs, id)
	return reports
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

func (s *Session) ApplyRemoveFAR(id uint32) { delete(s.FARIDs, id) }
func (s *Session) ApplyRemoveQER(id uint32) { delete(s.QERIDs, id) }

// Retain removed URR configuration/runtime until response reports are assembled.
func (s *Session) ApplyRemoveURR(id uint32) {
	if info := s.URRIDs[id]; info != nil {
		info.removed = true
	}
}
func (s *Session) ApplyRemoveBAR(id uint8) { delete(s.BARIDs, id) }
func (s *Session) CleanupRemovedURRs() {
	for id, info := range s.URRIDs {
		if info.removed {
			delete(s.URRIDs, id)
		}
	}
}
