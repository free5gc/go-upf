package pfcp

import (
	"errors"
	"testing"
	"time"

	"github.com/khirono/go-nl"

	"github.com/free5gc/go-gtp5gnl"
	"github.com/free5gc/go-upf/internal/forwarder"
)

func newRuleStateTestSession() *Session {
	pdr := &forwarder.PDRPlan{
		PDRID:         11,
		FARID:         1,
		FARIDPresent:  true,
		QERIDs:        []uint32{7},
		QERIDsPresent: true,
		URRIDs:        []uint32{3},
		URRIDsPresent: true,
	}
	return &Session{
		PDRIDs: map[uint16]*PDRInfo{
			11: newPDRInfo(pdr),
		},
		FARIDs: map[uint32]*FARInfo{
			1: newFARInfo(&forwarder.FARPlan{FARID: 1}),
		},
		QERIDs: map[uint32]*QERInfo{
			7: newQERInfo(&forwarder.QERPlan{QERID: 7}),
		},
		URRIDs: map[uint32]*URRInfo{
			3: newURRInfo(&forwarder.URRPlan{URRID: 3}),
		},
		BARIDs: make(map[uint8]*BARInfo),
	}
}

func TestRuleStateAllowsAtomicPDRRewire(t *testing.T) {
	sess := newRuleStateTestSession()
	plan := forwarder.NewModificationPlan(10)
	plan.CreateFARs = []*forwarder.FARPlan{{FARID: 2}}
	plan.CreateQERs = []*forwarder.QERPlan{{QERID: 8}}
	plan.CreateURRs = []*forwarder.URRPlan{{URRID: 4}}
	plan.UpdatePDRs = []*forwarder.PDRPlan{{
		PDRID:         11,
		FARID:         2,
		FARIDPresent:  true,
		QERIDs:        []uint32{8},
		QERIDsPresent: true,
		URRIDs:        []uint32{4},
		URRIDsPresent: true,
	}}
	plan.RemoveFARs = []*forwarder.FARPlan{{FARID: 1}}
	plan.RemoveQERs = []*forwarder.QERPlan{{QERID: 7}}
	plan.RemoveURRs = []*forwarder.URRPlan{{URRID: 3}}

	ruleState, err := sess.ValidateRuleState(plan)
	if err != nil {
		t.Fatalf("valid atomic PDR rewire was rejected: %v", err)
	}

	effective, exists := ruleState.PDR(11)
	if !exists {
		t.Fatal("effective PDR 11 is missing")
	}
	if effective.FARID != 2 {
		t.Fatalf("effective PDR retained old FAR: %+v", effective)
	}
	if _, exists := effective.RelatedQERIDs[8]; !exists {
		t.Fatalf("effective PDR is missing QER 8: %+v", effective.RelatedQERIDs)
	}
	if _, exists := effective.RelatedURRIDs[4]; !exists {
		t.Fatalf("effective PDR is missing URR 4: %+v", effective.RelatedURRIDs)
	}
	if got := ruleState.AffectedPDRIDs(); len(got) != 1 || got[0] != 11 {
		t.Fatalf("unexpected affected PDRs: %v", got)
	}

	// Preparing must be side-effect free.
	current := sess.PDRIDs[11]
	if current.FARID != 1 {
		t.Fatalf("prepare changed current PDR state: %+v", current)
	}
	if _, exists := current.RelatedQERIDs[7]; !exists {
		t.Fatalf("prepare changed current QER references: %+v", current.RelatedQERIDs)
	}
}

func TestRuleStateRejectsDanglingPDRReferences(t *testing.T) {
	tests := []struct {
		name string
		plan *forwarder.ModificationPlan
	}{
		{
			name: "FAR",
			plan: &forwarder.ModificationPlan{
				RemoveFARs: []*forwarder.FARPlan{{FARID: 1}},
			},
		},
		{
			name: "QER",
			plan: &forwarder.ModificationPlan{
				RemoveQERs: []*forwarder.QERPlan{{QERID: 7}},
			},
		},
		{
			name: "URR",
			plan: &forwarder.ModificationPlan{
				RemoveURRs: []*forwarder.URRPlan{{URRID: 3}},
			},
		},
		{
			name: "updated PDR",
			plan: &forwarder.ModificationPlan{
				UpdatePDRs: []*forwarder.PDRPlan{{
					PDRID:         11,
					QERIDs:        []uint32{99},
					QERIDsPresent: true,
				}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := newRuleStateTestSession().ValidateRuleState(tt.plan)
			if !errors.Is(err, ErrRuleCreationModificationFailed) {
				t.Fatalf("expected dangling %s reference rejection, got %v", tt.name, err)
			}
		})
	}
}

func TestRuleStateMergesPartialPDRUpdate(t *testing.T) {
	sess := newRuleStateTestSession()
	plan := &forwarder.ModificationPlan{
		UpdatePDRs: []*forwarder.PDRPlan{{PDRID: 11}},
		RemoveQERs: []*forwarder.QERPlan{{QERID: 7}},
	}

	_, err := sess.ValidateRuleState(plan)
	if !errors.Is(err, ErrRuleCreationModificationFailed) {
		t.Fatalf("omitted QERIDs incorrectly cleared the saved reference: %v", err)
	}
}

func TestRuleStateAllowsReferencedRulesToLeaveWithPDR(t *testing.T) {
	sess := newRuleStateTestSession()
	plan := &forwarder.ModificationPlan{
		RemovePDRs: []*forwarder.PDRPlan{{PDRID: 11}},
		RemoveFARs: []*forwarder.FARPlan{{FARID: 1}},
		RemoveQERs: []*forwarder.QERPlan{{QERID: 7}},
		RemoveURRs: []*forwarder.URRPlan{{URRID: 3}},
	}

	if _, err := sess.ValidateRuleState(plan); err != nil {
		t.Fatalf("removing a PDR with its referenced rules was rejected: %v", err)
	}
}

func TestRuleStateAcceptsReferencesToInFlightCreates(t *testing.T) {
	sess := &Session{
		PDRIDs: make(map[uint16]*PDRInfo),
		FARIDs: make(map[uint32]*FARInfo),
		QERIDs: make(map[uint32]*QERInfo),
		URRIDs: make(map[uint32]*URRInfo),
		BARIDs: make(map[uint8]*BARInfo),
	}
	plan := &forwarder.ModificationPlan{
		CreateFARs: []*forwarder.FARPlan{{FARID: 2}},
		CreateQERs: []*forwarder.QERPlan{{QERID: 8}},
		CreateURRs: []*forwarder.URRPlan{{URRID: 4}},
		CreatePDRs: []*forwarder.PDRPlan{{
			PDRID:         12,
			FARID:         2,
			FARIDPresent:  true,
			QERIDs:        []uint32{8},
			QERIDsPresent: true,
			URRIDs:        []uint32{4},
			URRIDsPresent: true,
		}},
	}

	if _, err := sess.ValidateRuleState(plan); err != nil {
		t.Fatalf("references to in-flight creates were rejected: %v", err)
	}
}

func TestRuleStateValidatesOperationTargets(t *testing.T) {
	t.Run("update missing rule", func(t *testing.T) {
		plan := &forwarder.ModificationPlan{
			UpdateQERs: []*forwarder.QERPlan{{QERID: 99}},
		}
		_, err := newRuleStateTestSession().ValidateRuleState(plan)
		if !errors.Is(err, ErrRuleNotFound) {
			t.Fatalf("expected ErrRuleNotFound, got %v", err)
		}
	})

	t.Run("create existing rule", func(t *testing.T) {
		plan := &forwarder.ModificationPlan{
			CreateQERs: []*forwarder.QERPlan{{QERID: 7}},
		}
		_, err := newRuleStateTestSession().ValidateRuleState(plan)
		if !errors.Is(err, ErrRuleCreationModificationFailed) {
			t.Fatalf("expected duplicate create rejection, got %v", err)
		}
	})

	conflicts := []struct {
		name string
		plan *forwarder.ModificationPlan
	}{
		{
			name: "duplicate create",
			plan: &forwarder.ModificationPlan{
				CreateQERs: []*forwarder.QERPlan{{QERID: 8}, {QERID: 8}},
			},
		},
		{
			name: "duplicate remove",
			plan: &forwarder.ModificationPlan{
				RemoveQERs: []*forwarder.QERPlan{{QERID: 7}, {QERID: 7}},
			},
		},
		{
			name: "remove and update",
			plan: &forwarder.ModificationPlan{
				UpdateQERs: []*forwarder.QERPlan{{QERID: 7}},
				RemoveQERs: []*forwarder.QERPlan{{QERID: 7}},
			},
		},
		{
			name: "remove and query URR",
			plan: &forwarder.ModificationPlan{
				QueryURRs:  []*forwarder.URRPlan{{QueryURRID: 3}},
				RemoveURRs: []*forwarder.URRPlan{{URRID: 3}},
			},
		},
	}

	for _, tt := range conflicts {
		t.Run(tt.name, func(t *testing.T) {
			_, err := newRuleStateTestSession().ValidateRuleState(tt.plan)
			if !errors.Is(err, ErrMutualExclusionConflict) {
				t.Fatalf("expected ErrMutualExclusionConflict, got %v", err)
			}
		})
	}
}

func TestRuleStateUsesChangedRuleOverlays(t *testing.T) {
	sess := newRuleStateTestSession()
	unchanged := &PDRInfo{}
	sess.PDRIDs[12] = unchanged
	source := uint8(1)
	plan := &forwarder.ModificationPlan{
		UpdatePDRs: []*forwarder.PDRPlan{{
			PDRID:           11,
			SourceInterface: &source,
		}},
	}

	ruleState, err := sess.ValidateRuleState(plan)
	if err != nil {
		t.Fatalf("ValidateRuleState: %v", err)
	}
	if len(ruleState.pdrOverrides) != 1 {
		t.Fatalf("RuleState copied unchanged PDRs: %d overrides", len(ruleState.pdrOverrides))
	}

	effective, exists := ruleState.PDR(11)
	if !exists || !effective.HasSourceInterface || effective.SourceInterface != source {
		t.Fatalf("PDR update was not reflected in effective state: %+v", effective)
	}
	if sess.PDRIDs[11].HasSourceInterface {
		t.Fatal("staging changed the base PDR")
	}

	readThrough, exists := ruleState.PDR(12)
	if !exists || readThrough != unchanged {
		t.Fatal("unchanged PDR did not read through to base session state")
	}
}

func TestRuleStateMergesQERPatchAndCommits(t *testing.T) {
	sess := newRuleStateTestSession()
	sess.QERIDs[7] = &QERInfo{
		QFI:      9,
		GateUL:   1,
		GateDL:   0,
		HasGate:  true,
		GBRULBps: 1_000_000,
		GBRDLBps: 500_000,
		HasGBR:   true,
	}
	mbr := &forwarder.DirectionalBitRate{
		UplinkBps:   2_000_000,
		DownlinkBps: 1_000_000,
	}
	plan := &forwarder.ModificationPlan{
		UpdateQERs: []*forwarder.QERPlan{{
			QERID: 7,
			DesiredState: forwarder.QERDesiredStatePatch{
				MBR: mbr,
			},
		}},
	}

	ruleState, err := sess.ValidateRuleState(plan)
	if err != nil {
		t.Fatalf("ValidateRuleState: %v", err)
	}
	effective, exists := ruleState.QER(7)
	if !exists || effective.QFI != 9 || !effective.HasGate || !effective.HasGBR {
		t.Fatalf("partial QER update cleared existing fields: %+v", effective)
	}
	if !effective.HasMBR || effective.MBRULBps != mbr.UplinkBps ||
		effective.MBRDLBps != mbr.DownlinkBps {
		t.Fatalf("partial QER update did not reflect MBR: %+v", effective)
	}
	if sess.QERIDs[7].HasMBR {
		t.Fatal("staging changed the base QER")
	}
	if got := ruleState.AffectedPDRIDs(); len(got) != 1 || got[0] != 11 {
		t.Fatalf("QER-only update did not affect referencing PDR: %v", got)
	}

	ruleState.Commit(plan)
	committed := sess.QERIDs[7]
	if !committed.HasMBR || committed.MBRULBps != mbr.UplinkBps {
		t.Fatalf("commit did not publish validated QER state: %+v", committed)
	}
}

func TestRuleStateCommitAppliesOnlyExecutorResult(t *testing.T) {
	session := newRuleStateTestSession()
	qfi := uint8(9)
	mbr := &forwarder.DirectionalBitRate{
		UplinkBps:   2_000_000,
		DownlinkBps: 1_000_000,
	}
	requested := &forwarder.ModificationPlan{
		CreateQERs: []*forwarder.QERPlan{{
			QERID: 8,
			DesiredState: forwarder.QERDesiredStatePatch{
				QFI: &qfi,
			},
		}},
		UpdateQERs: []*forwarder.QERPlan{{
			QERID: 7,
			DesiredState: forwarder.QERDesiredStatePatch{
				MBR: mbr,
			},
		}},
	}

	state, err := session.ValidateRuleState(requested)
	if err != nil {
		t.Fatalf("ValidateRuleState: %v", err)
	}

	applied := forwarder.NewModificationPlan(requested.SEID)
	applied.CreateQERs = requested.CreateQERs
	state.Commit(applied)

	if _, exists := session.QERIDs[8]; !exists {
		t.Fatal("successfully applied CreateQER was not committed")
	}
	if session.QERIDs[7].HasMBR {
		t.Fatal("failed UpdateQER was committed to Session")
	}
}

func TestRuleStateBuildsRollbackFromCanonicalInfo(t *testing.T) {
	sess := &Session{
		PDRIDs: make(map[uint16]*PDRInfo),
		FARIDs: make(map[uint32]*FARInfo),
		QERIDs: make(map[uint32]*QERInfo),
		URRIDs: make(map[uint32]*URRInfo),
		BARIDs: make(map[uint8]*BARInfo),
	}

	create := &forwarder.QERPlan{
		QERID: 7,
		Attrs: []nl.Attr{{
			Type:  gtp5gnl.QER_GATE,
			Value: nl.AttrU8(1),
		}},
	}
	sess.ApplyCreateQER(create)

	update := &forwarder.QERPlan{
		QERID: 7,
		Attrs: []nl.Attr{{
			Type:  gtp5gnl.QER_QFI,
			Value: nl.AttrU8(9),
		}},
	}
	first := &forwarder.ModificationPlan{UpdateQERs: []*forwarder.QERPlan{update}}
	state, err := sess.ValidateRuleState(first)
	if err != nil {
		t.Fatalf("ValidateRuleState first update: %v", err)
	}
	before := first.Rollback.QERs[7]
	if before == nil || len(before.Attrs) != 1 || before.Attrs[0].Type != gtp5gnl.QER_GATE {
		t.Fatalf("first rollback configuration does not contain original QER: %+v", before)
	}

	state.Commit(first)

	second := &forwarder.ModificationPlan{
		UpdateQERs: []*forwarder.QERPlan{{
			QERID: 7,
			Attrs: []nl.Attr{{
				Type:  gtp5gnl.QER_MBR,
				Value: nl.AttrList{},
			}},
		}},
	}
	if _, err := sess.ValidateRuleState(second); err != nil {
		t.Fatalf("ValidateRuleState second update: %v", err)
	}
	before = second.Rollback.QERs[7]
	if before == nil || len(before.Attrs) != 2 {
		t.Fatalf("second rollback configuration is not the complete applied QER: %+v", before)
	}
	if before.Attrs[0].Type != gtp5gnl.QER_GATE ||
		before.Attrs[1].Type != gtp5gnl.QER_QFI {
		t.Fatalf("unexpected merged rollback attrs: %+v", before.Attrs)
	}
}

func TestURRCanonicalInfoPatchPreservesRuntime(t *testing.T) {
	sess := &Session{
		PDRIDs: make(map[uint16]*PDRInfo),
		FARIDs: make(map[uint32]*FARInfo),
		QERIDs: make(map[uint32]*QERInfo),
		URRIDs: make(map[uint32]*URRInfo),
		BARIDs: make(map[uint8]*BARInfo),
	}
	create := &forwarder.URRPlan{
		OID:   gtp5gnl.OID{10, 20},
		URRID: 20,
		Attrs: []nl.Attr{
			{Type: gtp5gnl.URR_MEASUREMENT_METHOD, Value: nl.AttrU8(0x03)},
			{Type: gtp5gnl.URR_REPORTING_TRIGGER, Value: nl.AttrU32(0x01)},
			{Type: gtp5gnl.URR_MEASUREMENT_PERIOD, Value: nl.AttrU32(10)},
		},
	}
	sess.ApplyCreateURR(create)
	info := sess.URRIDs[20]
	info.SEQN = 7
	info.refPdrNum = 2

	update := &forwarder.URRPlan{
		OID:   create.OID,
		URRID: 20,
		Attrs: []nl.Attr{
			{Type: gtp5gnl.URR_MEASUREMENT_PERIOD, Value: nl.AttrU32(20)},
			{Type: gtp5gnl.URR_MEASUREMENT_INFO, Value: nl.AttrU64(0x1f)},
		},
	}
	request := &forwarder.ModificationPlan{
		SEID:       10,
		UpdateURRs: []*forwarder.URRPlan{update},
	}
	state, err := sess.ValidateRuleState(request)
	if err != nil {
		t.Fatalf("ValidateRuleState: %v", err)
	}
	before := request.Rollback.URRs[20]
	if before == nil || before.MeasurePeriod != 10 {
		t.Fatalf("rollback did not capture the pre-update URR: %+v", before)
	}

	state.Commit(request)
	got := sess.URRIDs[20]
	if got != info {
		t.Fatal("UpdateURR replaced the canonical URRInfo instead of patching it")
	}
	if got.SEQN != 7 || got.refPdrNum != 2 {
		t.Fatalf(
			"UpdateURR changed runtime state: SEQN=%d refPdrNum=%d",
			got.SEQN,
			got.refPdrNum,
		)
	}
	if got.MeasurePeriod != 20*time.Nanosecond {
		t.Fatalf("measurement period was not patched: %s", got.MeasurePeriod)
	}
	if !got.DURAT || !got.VOLUM || got.EVENT {
		t.Fatalf("omitted measurement method was not preserved: %+v", got.MeasureMethod)
	}
	if !got.MBQE || !got.INAM || !got.RADI || !got.ISTM || !got.MNOP {
		t.Fatalf("measurement information was not projected from the applied configuration: %+v", got.MeasureInformation)
	}

	next := &forwarder.ModificationPlan{
		SEID: 10,
		UpdateURRs: []*forwarder.URRPlan{{
			OID:   create.OID,
			URRID: 20,
			Attrs: []nl.Attr{{
				Type:  gtp5gnl.URR_MEASUREMENT_METHOD,
				Value: nl.AttrU8(0),
			}},
		}},
	}
	if _, err := sess.ValidateRuleState(next); err != nil {
		t.Fatalf("ValidateRuleState next update: %v", err)
	}
	current := next.Rollback.URRs[20]
	if current == nil || current.MeasurePeriod != 20*time.Nanosecond ||
		len(current.Attrs) != 4 {
		t.Fatalf("next rollback configuration is not the complete patched URR: %+v", current)
	}
}

func TestAppliedRuleAttrMergeKeepsRuleNamespacesSeparate(t *testing.T) {
	t.Run("PDR PDI is replaced as a complete field", func(t *testing.T) {
		current := &forwarder.PDRPlan{Attrs: []nl.Attr{{
			Type: gtp5gnl.PDR_PDI,
			Value: nl.AttrList{
				{Type: gtp5gnl.PDI_SRC_INTF, Value: nl.AttrU8(1)},
				{Type: gtp5gnl.PDI_UE_ADDR_IPV4, Value: nl.AttrBytes{10, 0, 0, 1}},
			},
		}}}
		patch := &forwarder.PDRPlan{Attrs: []nl.Attr{{
			Type: gtp5gnl.PDR_PDI,
			Value: nl.AttrList{
				{Type: gtp5gnl.PDI_SRC_INTF, Value: nl.AttrU8(2)},
			},
		}}}

		merged := mergePDRInfo(newPDRInfo(current), patch)
		pdi, ok := merged.Attrs[0].Value.(nl.AttrList)
		if !ok || len(pdi) != 1 || pdi[0].Type != gtp5gnl.PDI_SRC_INTF {
			t.Fatalf("PDI was recursively merged across rule namespaces: %+v", merged.Attrs)
		}
	})

	t.Run("FAR forwarding parameters preserve omitted nested fields", func(t *testing.T) {
		current := &forwarder.FARPlan{Attrs: []nl.Attr{{
			Type: gtp5gnl.FAR_FORWARDING_PARAMETER,
			Value: nl.AttrList{
				{Type: gtp5gnl.FORWARDING_PARAMETER_OUTER_HEADER_CREATION, Value: nl.AttrList{}},
				{Type: gtp5gnl.FORWARDING_PARAMETER_FORWARDING_POLICY, Value: nl.AttrString("1")},
			},
		}}}
		patch := &forwarder.FARPlan{Attrs: []nl.Attr{{
			Type: gtp5gnl.FAR_FORWARDING_PARAMETER,
			Value: nl.AttrList{
				{Type: gtp5gnl.FORWARDING_PARAMETER_FORWARDING_POLICY, Value: nl.AttrString("2")},
			},
		}}}

		info := newFARInfo(current)
		info.ruleConfig = info.ruleConfig.mergeFAR(patch.Attrs)
		params, ok := info.Attrs[0].Value.(nl.AttrList)
		if !ok || len(params) != 2 {
			t.Fatalf("FAR nested state was not preserved: %+v", info.Attrs)
		}
		if params[0].Type != gtp5gnl.FORWARDING_PARAMETER_OUTER_HEADER_CREATION ||
			params[1].Type != gtp5gnl.FORWARDING_PARAMETER_FORWARDING_POLICY {
			t.Fatalf("unexpected FAR nested merge: %+v", params)
		}
	})
}
