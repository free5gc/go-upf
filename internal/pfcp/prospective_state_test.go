package pfcp

import (
	"errors"
	"testing"

	"github.com/free5gc/go-upf/internal/forwarder"
)

func newProspectiveTestSession() *Sess {
	return &Sess{
		PDRIDs: map[uint16]*PDRInfo{
			11: {
				FARID:         1,
				HasFARID:      true,
				RelatedQERIDs: uint32Set([]uint32{7}),
				RelatedURRIDs: uint32Set([]uint32{3}),
			},
		},
		FARIDs: map[uint32]struct{}{1: {}},
		QERIDs: map[uint32]*QERInfo{7: {}},
		URRIDs: map[uint32]*URRInfo{3: {}},
		BARIDs: make(map[uint8]struct{}),
	}
}

func TestProspectiveStateAllowsAtomicPDRRewire(t *testing.T) {
	sess := newProspectiveTestSession()
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

	if err := sess.validateProspectiveState(plan); err != nil {
		t.Fatalf("valid atomic PDR rewire was rejected: %v", err)
	}

	// Validation must be side-effect free.
	got := sess.PDRIDs[11]
	if got.FARID != 1 {
		t.Fatalf("validation changed current PDR state: %+v", got)
	}
	if _, exists := got.RelatedQERIDs[7]; !exists {
		t.Fatalf("validation changed current QER references: %+v", got.RelatedQERIDs)
	}
}

func TestProspectiveStateRejectsDanglingPDRReferences(t *testing.T) {
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := newProspectiveTestSession().validateProspectiveState(tt.plan)
			if !errors.Is(err, ErrRuleCreationModificationFailed) {
				t.Fatalf("expected dangling %s reference rejection, got %v", tt.name, err)
			}
		})
	}
}

func TestProspectiveStateMergesPartialPDRUpdate(t *testing.T) {
	sess := newProspectiveTestSession()
	plan := &forwarder.ModificationPlan{
		UpdatePDRs: []*forwarder.PDRPlan{{PDRID: 11}},
		RemoveQERs: []*forwarder.QERPlan{{QERID: 7}},
	}

	err := sess.validateProspectiveState(plan)
	if !errors.Is(err, ErrRuleCreationModificationFailed) {
		t.Fatalf("omitted QERIDs incorrectly cleared the saved reference: %v", err)
	}
}

func TestProspectiveStateAllowsReferencedRulesToLeaveWithPDR(t *testing.T) {
	sess := newProspectiveTestSession()
	plan := &forwarder.ModificationPlan{
		RemovePDRs: []*forwarder.PDRPlan{{PDRID: 11}},
		RemoveFARs: []*forwarder.FARPlan{{FARID: 1}},
		RemoveQERs: []*forwarder.QERPlan{{QERID: 7}},
		RemoveURRs: []*forwarder.URRPlan{{URRID: 3}},
	}

	if err := sess.validateProspectiveState(plan); err != nil {
		t.Fatalf("removing a PDR with its referenced rules was rejected: %v", err)
	}
}

func TestProspectiveStateAcceptsReferencesToInFlightCreates(t *testing.T) {
	sess := &Sess{
		PDRIDs: make(map[uint16]*PDRInfo),
		FARIDs: make(map[uint32]struct{}),
		QERIDs: make(map[uint32]*QERInfo),
		URRIDs: make(map[uint32]*URRInfo),
		BARIDs: make(map[uint8]struct{}),
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

	if err := sess.validateProspectiveState(plan); err != nil {
		t.Fatalf("references to in-flight creates were rejected: %v", err)
	}
}

func TestProspectiveStateValidatesOperationTargets(t *testing.T) {
	t.Run("update missing rule", func(t *testing.T) {
		plan := &forwarder.ModificationPlan{
			UpdateQERs: []*forwarder.QERPlan{{QERID: 99}},
		}
		err := newProspectiveTestSession().validateProspectiveState(plan)
		if !errors.Is(err, ErrRuleNotFound) {
			t.Fatalf("expected ErrRuleNotFound, got %v", err)
		}
	})

	t.Run("create existing rule", func(t *testing.T) {
		plan := &forwarder.ModificationPlan{
			CreateQERs: []*forwarder.QERPlan{{QERID: 7}},
		}
		err := newProspectiveTestSession().validateProspectiveState(plan)
		if !errors.Is(err, ErrRuleCreationModificationFailed) {
			t.Fatalf("expected duplicate create rejection, got %v", err)
		}
	})
}
