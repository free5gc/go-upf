package pfcp

import (
	"errors"
	"testing"
	"time"

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

func TestURRReportingPatchPreservesRuntime(t *testing.T) {
	method, information := uint8(3), uint64(0x1f)
	period := time.Second
	sess := &Session{URRIDs: make(map[uint32]*URRInfo)}
	sess.ApplyCreateURR(&forwarder.URRPlan{URRID: 20, ReportingConfig: forwarder.URRReportingPatch{
		MeasureMethod: &method, MeasurePeriod: &period,
	}})
	info := sess.URRIDs[20]
	info.SEQN, info.refPdrNum, info.removed = 7, 2, true
	nextPeriod := 2 * time.Second
	sess.ApplyUpdateURR(&forwarder.URRPlan{URRID: 20, ReportingConfig: forwarder.URRReportingPatch{
		MeasurePeriod: &nextPeriod, MeasureInformation: &information,
	}})
	if sess.URRIDs[20] != info || info.SEQN != 7 || info.refPdrNum != 2 || !info.removed {
		t.Fatal("reporting patch changed PFCP runtime")
	}
	if info.MeasurePeriod != nextPeriod || !info.DURAT || !info.VOLUM || info.EVENT {
		t.Fatalf("omitted fields were not preserved: %+v", info)
	}
	if !info.MBQE || !info.INAM || !info.RADI || !info.ISTM || !info.MNOP {
		t.Fatalf("measurement information was not applied: %+v", info)
	}
	zero := uint8(0)
	sess.ApplyUpdateURR(&forwarder.URRPlan{URRID: 20, ReportingConfig: forwarder.URRReportingPatch{MeasureMethod: &zero}})
	if info.DURAT || info.VOLUM || info.EVENT || info.MeasurePeriod != nextPeriod {
		t.Fatalf("explicit zero was not distinguished from omitted: %+v", info)
	}
}

func TestRuleStateValidationDoesNotPrepareRollback(t *testing.T) {
	sess := newRuleStateTestSession()
	plan := &forwarder.ModificationPlan{UpdateQERs: []*forwarder.QERPlan{{QERID: 7}}}
	if _, err := sess.ValidateRuleState(plan); err != nil {
		t.Fatal(err)
	}
	if plan.Rollback != nil {
		t.Fatal("PFCP validation populated datapath rollback metadata")
	}
}
