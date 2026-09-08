package pfcp

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/free5gc/go-upf/internal/forwarder"
	"github.com/free5gc/go-upf/internal/report"
	"github.com/free5gc/go-upf/internal/rules"
)

func statePtr[T any](v T) *T { return &v }
func newRuleStateTestSession() *Session {
	return &Session{
		PDRIDs:   map[uint16]*rules.PDRConfig{11: {PDRID: 11, FARID: statePtr(uint32(1)), QERIDs: []uint32{7}, URRIDs: []uint32{3}}},
		FARIDs:   map[uint32]*rules.FARConfig{1: {FARID: 1}},
		QERIDs:   map[uint32]*rules.QERConfig{7: {QERID: 7}},
		URRIDs:   map[uint32]*URRInfo{3: {Config: rules.URRConfig{URRID: 3}, refPdrNum: 1}},
		BARIDs:   make(map[uint8]*rules.BARConfig),
		datapath: forwarder.NewSessionDatapath(forwarder.Empty{}, 0),
	}
}
func commitChanges(t *testing.T, s *Session, c *rules.RuleChangeSet) {
	t.Helper()
	state, err := s.ValidateRuleState(c)
	if err != nil {
		t.Fatal(err)
	}
	state.Commit()
}

func TestRuleStateAllowsAtomicPDRRewire(t *testing.T) {
	sess := newRuleStateTestSession()
	plan := &rules.RuleChangeSet{}
	plan.CreateFARs = []rules.FARConfig{{FARID: 2}}
	plan.CreateQERs = []rules.QERConfig{{QERID: 8}}
	plan.CreateURRs = []rules.URRConfig{{URRID: 4}}
	plan.UpdatePDRs = []rules.PDRPatch{{
		PDRID: 11,
		FARID: statePtr(uint32(2)),

		QERIDs: []uint32{8},

		URRIDs: []uint32{4},
	}}
	plan.RemoveFARs = []uint32{1}
	plan.RemoveQERs = []uint32{7}
	plan.RemoveURRs = []uint32{3}

	ruleState, err := sess.ValidateRuleState(plan)
	if err != nil {
		t.Fatalf("valid atomic PDR rewire was rejected: %v", err)
	}

	effective, exists := ruleState.PDR(11)
	if !exists {
		t.Fatal("effective PDR 11 is missing")
	}
	if *effective.FARID != 2 {
		t.Fatalf("effective PDR retained old FAR: %+v", effective)
	}
	if _, exists := uint32Set(effective.QERIDs)[8]; !exists {
		t.Fatalf("effective PDR is missing QER 8: %+v", effective.QERIDs)
	}
	if _, exists := uint32Set(effective.URRIDs)[4]; !exists {
		t.Fatalf("effective PDR is missing URR 4: %+v", effective.URRIDs)
	}
	if got := ruleState.AffectedPDRIDs(); len(got) != 1 || got[0] != 11 {
		t.Fatalf("unexpected affected PDRs: %v", got)
	}

	// Preparing must be side-effect free.
	current := sess.PDRIDs[11]
	if *current.FARID != 1 {
		t.Fatalf("prepare changed current PDR state: %+v", current)
	}
	if _, exists := uint32Set(current.QERIDs)[7]; !exists {
		t.Fatalf("prepare changed current QER references: %+v", current.QERIDs)
	}
}

func TestRuleStateRejectsDanglingPDRReferences(t *testing.T) {
	tests := []struct {
		name string
		plan *rules.RuleChangeSet
	}{
		{
			name: "FAR",
			plan: &rules.RuleChangeSet{
				RemoveFARs: []uint32{1},
			},
		},
		{
			name: "QER",
			plan: &rules.RuleChangeSet{
				RemoveQERs: []uint32{7},
			},
		},
		{
			name: "URR",
			plan: &rules.RuleChangeSet{
				RemoveURRs: []uint32{3},
			},
		},
		{
			name: "updated PDR",
			plan: &rules.RuleChangeSet{
				UpdatePDRs: []rules.PDRPatch{{
					PDRID:  11,
					QERIDs: []uint32{99},
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
	plan := &rules.RuleChangeSet{
		UpdatePDRs: []rules.PDRPatch{{PDRID: 11}},
		RemoveQERs: []uint32{7},
	}

	_, err := sess.ValidateRuleState(plan)
	if !errors.Is(err, ErrRuleCreationModificationFailed) {
		t.Fatalf("omitted QERIDs incorrectly cleared the saved reference: %v", err)
	}
}

func TestRuleStateAllowsReferencedRulesToLeaveWithPDR(t *testing.T) {
	sess := newRuleStateTestSession()
	plan := &rules.RuleChangeSet{
		RemovePDRs: []uint16{11},
		RemoveFARs: []uint32{1},
		RemoveQERs: []uint32{7},
		RemoveURRs: []uint32{3},
	}

	if _, err := sess.ValidateRuleState(plan); err != nil {
		t.Fatalf("removing a PDR with its referenced rules was rejected: %v", err)
	}
}

func TestRuleStateAcceptsReferencesToInFlightCreates(t *testing.T) {
	sess := &Session{
		PDRIDs: make(map[uint16]*rules.PDRConfig),
		FARIDs: make(map[uint32]*rules.FARConfig),
		QERIDs: make(map[uint32]*rules.QERConfig),
		URRIDs: make(map[uint32]*URRInfo),
		BARIDs: make(map[uint8]*rules.BARConfig),
	}
	plan := &rules.RuleChangeSet{
		CreateFARs: []rules.FARConfig{{FARID: 2}},
		CreateQERs: []rules.QERConfig{{QERID: 8}},
		CreateURRs: []rules.URRConfig{{URRID: 4}},
		CreatePDRs: []rules.PDRConfig{{
			PDRID: 12,
			FARID: statePtr(uint32(2)),

			QERIDs: []uint32{8},

			URRIDs: []uint32{4},
		}},
	}

	if _, err := sess.ValidateRuleState(plan); err != nil {
		t.Fatalf("references to in-flight creates were rejected: %v", err)
	}
}

func TestRuleStateValidatesOperationTargets(t *testing.T) {
	t.Run("update missing rule", func(t *testing.T) {
		plan := &rules.RuleChangeSet{
			UpdateQERs: []rules.QERPatch{{QERID: 99}},
		}
		_, err := newRuleStateTestSession().ValidateRuleState(plan)
		if !errors.Is(err, ErrRuleNotFound) {
			t.Fatalf("expected ErrRuleNotFound, got %v", err)
		}
	})

	t.Run("create existing rule", func(t *testing.T) {
		plan := &rules.RuleChangeSet{
			CreateQERs: []rules.QERConfig{{QERID: 7}},
		}
		_, err := newRuleStateTestSession().ValidateRuleState(plan)
		if !errors.Is(err, ErrRuleCreationModificationFailed) {
			t.Fatalf("expected duplicate create rejection, got %v", err)
		}
	})

	conflicts := []struct {
		name string
		plan *rules.RuleChangeSet
	}{
		{
			name: "duplicate create",
			plan: &rules.RuleChangeSet{
				CreateQERs: []rules.QERConfig{{QERID: 8}, {QERID: 8}},
			},
		},
		{
			name: "duplicate remove",
			plan: &rules.RuleChangeSet{
				RemoveQERs: []uint32{7, 7},
			},
		},
		{
			name: "remove and update",
			plan: &rules.RuleChangeSet{
				UpdateQERs: []rules.QERPatch{{QERID: 7}},
				RemoveQERs: []uint32{7},
			},
		},
		{
			name: "remove and query URR",
			plan: &rules.RuleChangeSet{
				QueryURRs:  []uint32{3},
				RemoveURRs: []uint32{3},
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
	unchanged := &rules.PDRConfig{}
	sess.PDRIDs[12] = unchanged
	source := uint8(1)
	plan := &rules.RuleChangeSet{
		UpdatePDRs: []rules.PDRPatch{{
			PDRID: 11,
			PDI:   &rules.PDI{SourceInterface: source},
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
	if !exists || effective.PDI == nil || effective.PDI.SourceInterface != source {
		t.Fatalf("PDR update was not reflected in effective state: %+v", effective)
	}
	if sess.PDRIDs[11].PDI != nil {
		t.Fatal("staging changed the base PDR")
	}

	readThrough, exists := ruleState.PDR(12)
	if !exists || readThrough != unchanged {
		t.Fatal("unchanged PDR did not read through to base session state")
	}
}

func TestRuleStateMergesQERPatchAndCommits(t *testing.T) {
	sess := newRuleStateTestSession()
	sess.QERIDs[7] = &rules.QERConfig{QERID: 7, QFI: statePtr(uint8(9)), GateStatus: &rules.GateStatus{Uplink: 1}, GBR: &rules.DirectionalBitRate{UplinkBps: 1000000, DownlinkBps: 500000}}
	patch := &rules.RuleChangeSet{UpdateQERs: []rules.QERPatch{{QERID: 7, MBR: &rules.DirectionalBitRate{UplinkBps: 2000000, DownlinkBps: 1000000}}}}
	state, err := sess.ValidateRuleState(patch)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := state.QER(7)
	if *c.QFI != 9 || c.GateStatus.Uplink != 1 || c.GBR.UplinkBps != 1000000 || c.MBR.UplinkBps != 2000000 {
		t.Fatalf("bad merged QER: %+v", c)
	}
	if sess.QERIDs[7].MBR != nil {
		t.Fatal("validation mutated session")
	}
	if !reflect.DeepEqual(state.AffectedPDRIDs(), []uint16{11}) {
		t.Fatal("missing affected PDR")
	}
	// Candidate owns patch values, and commit publishes that candidate, not a
	// second interpretation of the request or the executor's backend plan.
	patch.UpdateQERs[0].MBR.UplinkBps = 99
	state.Commit()
	if !reflect.DeepEqual(sess.QERIDs[7], c) {
		t.Fatal("commit differs from validated candidate")
	}
	c.MBR.UplinkBps = 88
	if sess.QERIDs[7].MBR.UplinkBps != 2000000 {
		t.Fatal("published config aliases candidate")
	}
}

func TestURRReportingPatchPreservesRuntime(t *testing.T) {
	sess := newRuleStateTestSession()
	commitChanges(t, sess, &rules.RuleChangeSet{CreateURRs: []rules.URRConfig{{URRID: 20, MeasureMethod: statePtr(uint8(3)), MeasurePeriod: statePtr(time.Second)}}})
	info := sess.URRIDs[20]
	info.SEQN, info.refPdrNum, info.removed = 7, 2, true
	commitChanges(t, sess, &rules.RuleChangeSet{UpdateURRs: []rules.URRPatch{{URRID: 20, MeasurePeriod: statePtr(2 * time.Second), MeasureInformation: statePtr(uint64(0x1f))}}})
	if sess.URRIDs[20] != info || info.SEQN != 7 || info.refPdrNum != 2 || !info.removed {
		t.Fatal("config update changed runtime")
	}
	method, information := info.measurementMethod(), info.measurementInformation()
	if *info.Config.MeasurePeriod != 2*time.Second || !method.DURAT || !method.VOLUM || method.EVENT {
		t.Fatal("omitted measurement method lost")
	}
	if !information.MBQE || !information.INAM || !information.RADI || !information.ISTM || !information.MNOP {
		t.Fatal("measurement information not applied")
	}
	commitChanges(t, sess, &rules.RuleChangeSet{UpdateURRs: []rules.URRPatch{{URRID: 20, MeasureMethod: statePtr(uint8(0))}}})
	method = info.measurementMethod()
	if method.DURAT || method.VOLUM || method.EVENT || *info.Config.MeasurePeriod != 2*time.Second {
		t.Fatal("zero confused with absence")
	}
}

func TestRuleStateAllConfigurationsAndOwnership(t *testing.T) {
	sess := newRuleStateTestSession()
	sess.FARIDs[1].ForwardingParameters = &rules.ForwardingParameters{NetworkInstance: statePtr("internet"), OuterHeaderCreation: &rules.OuterHeaderCreation{TEID: statePtr(uint32(42))}}
	sess.BARIDs[1] = &rules.BARConfig{BARID: 1, DownlinkDataNotificationDelay: statePtr(time.Second)}
	changes := &rules.RuleChangeSet{
		UpdateFARs: []rules.FARPatch{{FARID: 1, ForwardingParameters: &rules.ForwardingParameters{SMRequestFlags: statePtr(uint8(0))}}},
		UpdateBARs: []rules.BARPatch{{BARID: 1, SuggestedBufferingPacketsCount: statePtr(uint16(0))}},
		UpdatePDRs: []rules.PDRPatch{{PDRID: 11, Precedence: statePtr(uint32(0))}},
	}
	state, err := sess.ValidateRuleState(changes)
	if err != nil {
		t.Fatal(err)
	}
	far, _ := state.FAR(1)
	bar, _ := state.BAR(1)
	pdr, _ := state.PDR(11)
	if *far.ForwardingParameters.NetworkInstance != "internet" ||
		*far.ForwardingParameters.OuterHeaderCreation.TEID != 42 ||
		*far.ForwardingParameters.SMRequestFlags != 0 {
		t.Fatal("nested FAR merge lost fields")
	}
	if *bar.DownlinkDataNotificationDelay != time.Second ||
		*bar.SuggestedBufferingPacketsCount != 0 ||
		*pdr.Precedence != 0 {
		t.Fatal("BAR/PDR merge failed")
	}
	if sess.FARIDs[1].ForwardingParameters.SMRequestFlags != nil ||
		sess.BARIDs[1].SuggestedBufferingPacketsCount != nil ||
		sess.PDRIDs[11].Precedence != nil {
		t.Fatal("validation mutated base")
	}
	state.Commit()
	if !reflect.DeepEqual(sess.FARIDs[1], far) ||
		!reflect.DeepEqual(sess.BARIDs[1], bar) ||
		!reflect.DeepEqual(sess.PDRIDs[11], pdr) {
		t.Fatal("not all candidate configs published")
	}
}

func TestRuleStateRejectsWrongSession(t *testing.T) {
	if _, err := newRuleStateTestSession().ValidateRuleState(&rules.RuleChangeSet{SEID: 99}); err == nil {
		t.Fatal("wrong SEID accepted")
	}
}

type queryRecordingDatapath struct {
	forwarder.SessionDatapath
	queries []uint32
}

func (d *queryRecordingDatapath) QueryURR(id uint32) ([]report.USAReport, error) {
	d.queries = append(d.queries, id)
	return []report.USAReport{{URRID: id}}, nil
}

func TestRuleStateURRReferenceTransfer(t *testing.T) {
	sess := newRuleStateTestSession()
	datapath := &queryRecordingDatapath{}
	sess.datapath = datapath
	changes := &rules.RuleChangeSet{
		CreatePDRs: []rules.PDRConfig{{PDRID: 12, URRIDs: []uint32{3, 3}}},
		RemovePDRs: []uint16{11},
	}
	state, err := sess.ValidateRuleState(changes)
	if err != nil {
		t.Fatal(err)
	}
	if len(datapath.queries) != 0 || sess.URRIDs[3].refPdrNum != 1 {
		t.Fatal("validation changed URR runtime")
	}
	state.Commit()
	if len(datapath.queries) != 0 || sess.URRIDs[3].refPdrNum != 1 {
		t.Fatal("transfer triggered termination or counted duplicate references")
	}
	state, err = sess.ValidateRuleState(&rules.RuleChangeSet{RemovePDRs: []uint16{12}})
	if err != nil {
		t.Fatal(err)
	}
	terminal := state.terminalURRIDs()
	state.Commit()
	if !reflect.DeepEqual(terminal, []uint32{3}) || sess.URRIDs[3].refPdrNum != 0 || len(datapath.queries) != 0 {
		t.Fatal("publication must update references without querying the datapath")
	}

}

func TestRuleStateSequentialUpdatesAndCreateRemove(t *testing.T) {
	sess := newRuleStateTestSession()
	changes := &rules.RuleChangeSet{
		CreateQERs: []rules.QERConfig{{QERID: 8, QFI: statePtr(uint8(9))}, {QERID: 9}},
		UpdateQERs: []rules.QERPatch{{QERID: 8, MBR: &rules.DirectionalBitRate{UplinkBps: 1000}}, {QERID: 8, RQI: statePtr(uint8(0))}},
		RemoveQERs: []uint32{9},
	}
	state, err := sess.ValidateRuleState(changes)
	if err != nil {
		t.Fatal(err)
	}
	q, _ := state.QER(8)
	if *q.QFI != 9 || q.MBR.UplinkBps != 1000 || *q.RQI != 0 {
		t.Fatal("sequential updates lost fields")
	}
	if _, ok := state.QER(9); ok {
		t.Fatal("removed create visible in candidate")
	}
	state.Commit()
	if _, ok := sess.QERIDs[9]; ok {
		t.Fatal("removed create published")
	}
}
