package forwarder

import (
	"github.com/free5gc/go-gtp5gnl"
	"github.com/khirono/go-nl"
	"github.com/pkg/errors"
	"time"
)

// ruleConfig is a private, owned copy of the last confirmed datapath configuration.
// It deliberately contains no PFCP IE or reporting runtime.
type ruleConfig struct {
	OID   gtp5gnl.OID
	Attrs []nl.Attr
}

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
		OID:   append(gtp5gnl.OID(nil), oid...),
		Attrs: cloneRuleAttrs(attrs),
	}
}

// appliedRules belongs exclusively to one SessionDatapath; no global SEID store.
type appliedRules struct {
	pdrs map[uint16]ruleConfig
	fars map[uint32]ruleConfig
	qers map[uint32]ruleConfig
	urrs map[uint32]ruleConfig
	bars map[uint8]ruleConfig
}

func newAppliedRules() appliedRules {
	return appliedRules{
		pdrs: make(map[uint16]ruleConfig),
		fars: make(map[uint32]ruleConfig),
		qers: make(map[uint32]ruleConfig),
		urrs: make(map[uint32]ruleConfig),
		bars: make(map[uint8]ruleConfig),
	}
}

func snapshotBefore[K comparable, P any](current map[K]ruleConfig, creates, updates, removes []P,
	idOf func(P) K, save func(K, ruleConfig)) error {
	created := make(map[K]bool, len(creates))
	for _, p := range creates {
		created[idOf(p)] = true
	}
	for _, group := range [][]P{updates, removes} {
		for _, p := range group {
			id := idOf(p)
			if old, ok := current[id]; ok {
				save(id, newRuleConfig(old.OID, old.Attrs))
			} else if !created[id] {
				return errors.Errorf("missing applied snapshot for rule ID %v", id)
			}
		}
	}
	return nil
}

func (s *sessionDatapath) buildRollbackPlan(plan *modificationPlan) (*rollbackPlan, error) {
	before := newRollbackPlan()
	if err := snapshotBefore(s.applied.pdrs, plan.CreatePDRs, plan.UpdatePDRs, plan.RemovePDRs,
		func(p *pdrPlan) uint16 { return p.PDRID },
		func(id uint16, old ruleConfig) {
			before.PDRs[id] = &pdrPlan{OID: old.OID, Attrs: old.Attrs, PDRID: id}
		}); err != nil {
		return nil, errors.Wrap(err, "PDR rollback")
	}
	if err := snapshotBefore(s.applied.fars, plan.CreateFARs, plan.UpdateFARs, plan.RemoveFARs,
		func(p *farPlan) uint32 { return p.FARID },
		func(id uint32, old ruleConfig) {
			before.FARs[id] = &farPlan{OID: old.OID, Attrs: old.Attrs, FARID: id}
		}); err != nil {
		return nil, errors.Wrap(err, "FAR rollback")
	}
	if err := snapshotBefore(s.applied.qers, plan.CreateQERs, plan.UpdateQERs, plan.RemoveQERs,
		func(p *qerPlan) uint32 { return p.QERID },
		func(id uint32, old ruleConfig) {
			before.QERs[id] = &qerPlan{OID: old.OID, Attrs: old.Attrs, QERID: id}
		}); err != nil {
		return nil, errors.Wrap(err, "QER rollback")
	}
	if err := snapshotBefore(s.applied.urrs, plan.CreateURRs, plan.UpdateURRs, plan.RemoveURRs,
		func(p *urrPlan) uint32 { return p.URRID },
		func(id uint32, old ruleConfig) {
			before.URRs[id] = &urrPlan{OID: old.OID, Attrs: old.Attrs, URRID: id}
			restoreURRTimer(before.URRs[id])
		}); err != nil {
		return nil, errors.Wrap(err, "URR rollback")
	}
	if err := snapshotBefore(s.applied.bars, plan.CreateBARs, plan.UpdateBARs, plan.RemoveBARs,
		func(p *barPlan) uint8 { return p.BARID },
		func(id uint8, old ruleConfig) {
			before.BARs[id] = &barPlan{OID: old.OID, Attrs: old.Attrs, BARID: id}
		}); err != nil {
		return nil, errors.Wrap(err, "BAR rollback")
	}
	return before, nil
}

func publishRules[K comparable, P any](current map[K]ruleConfig, creates, updates, removes []P,
	idOf func(P) K, configOf func(P) ruleConfig, merge func([]nl.Attr, []nl.Attr) []nl.Attr) {
	for _, p := range creates {
		cfg := configOf(p)
		current[idOf(p)] = newRuleConfig(cfg.OID, cfg.Attrs)
	}
	for _, p := range updates {
		id := idOf(p)
		patch := configOf(p)
		if old, ok := current[id]; ok {
			current[id] = ruleConfig{OID: old.OID, Attrs: merge(old.Attrs, patch.Attrs)}
		}
	}
	for _, p := range removes {
		delete(current, idOf(p))
	}
}

// publish records only operations confirmed by the executor. Transactional
// failures do not call this method; cleanup may report partial success.
func (s *sessionDatapath) publish(result *executionResult) {
	if result == nil || result.AppliedPlan == nil {
		return
	}
	plan := result.AppliedPlan
	publishRules(s.applied.pdrs, plan.CreatePDRs, plan.UpdatePDRs, plan.RemovePDRs,
		func(p *pdrPlan) uint16 { return p.PDRID },
		func(p *pdrPlan) ruleConfig { return ruleConfig{OID: p.OID, Attrs: p.Attrs} }, mergeRuleAttrs)
	publishRules(s.applied.fars, plan.CreateFARs, plan.UpdateFARs, plan.RemoveFARs,
		func(p *farPlan) uint32 { return p.FARID },
		func(p *farPlan) ruleConfig { return ruleConfig{OID: p.OID, Attrs: p.Attrs} }, mergeFARRuleAttrs)
	publishRules(s.applied.qers, plan.CreateQERs, plan.UpdateQERs, plan.RemoveQERs,
		func(p *qerPlan) uint32 { return p.QERID },
		func(p *qerPlan) ruleConfig { return ruleConfig{OID: p.OID, Attrs: p.Attrs} }, mergeRuleAttrs)
	publishRules(s.applied.urrs, plan.CreateURRs, plan.UpdateURRs, plan.RemoveURRs,
		func(p *urrPlan) uint32 { return p.URRID },
		func(p *urrPlan) ruleConfig { return ruleConfig{OID: p.OID, Attrs: p.Attrs} }, mergeRuleAttrs)
	publishRules(s.applied.bars, plan.CreateBARs, plan.UpdateBARs, plan.RemoveBARs,
		func(p *barPlan) uint8 { return p.BARID },
		func(p *barPlan) ruleConfig { return ruleConfig{OID: p.OID, Attrs: p.Attrs} }, mergeRuleAttrs)
}

// restoreURRTimer reads the backend timer settings needed by rollback.
// Counter restoration still requires kernel support. Duration decoding retains
// the existing applied-attribute representation.
func restoreURRTimer(p *urrPlan) {
	for _, attr := range p.Attrs {
		switch attr.Type {
		case gtp5gnl.URR_REPORTING_TRIGGER:
			if v, ok := attr.Value.(nl.AttrU32); ok {
				p.ReportingTrigger.Flags = uint32(v)
			}
		case gtp5gnl.URR_MEASUREMENT_PERIOD:
			if v, ok := attr.Value.(nl.AttrU32); ok {
				p.MeasurePeriod = time.Duration(v)
			}
		}
	}
}
