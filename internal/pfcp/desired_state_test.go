package pfcp

import (
	"testing"

	"github.com/wmnsk/go-pfcp/ie"

	"github.com/free5gc/go-upf/internal/rules"
)

func TestQERDesiredStateCreateAndPartialUpdate(t *testing.T) {
	createPlan, err := parseCreateQER(ie.NewCreateQER(
		ie.NewQERID(7),
		ie.NewQFI(9),
		ie.NewGateStatus(ie.GateStatusClosed, ie.GateStatusOpen),
		ie.NewGBR(1500, 750),
		ie.NewMBR(3000, 2000),
	))
	if err != nil {
		t.Fatalf("BuildCreateQERPlan: %v", err)
	}

	sess := newRuleStateTestSession()
	delete(sess.QERIDs, 7)
	delete(sess.PDRIDs, 11)
	commitChanges(t, sess, &rules.RuleChangeSet{CreateQERs: []rules.QERConfig{createPlan}})

	got := sess.QERIDs[7]
	if got == nil {
		t.Fatal("QER desired state was not saved")
	}
	if *got.QFI != 9 || got.GateStatus == nil || got.GateStatus.Uplink != ie.GateStatusClosed || got.GateStatus.Downlink != ie.GateStatusOpen {
		t.Fatalf("unexpected QFI/gate desired state: %+v", got)
	}
	if got.GBR == nil || got.GBR.UplinkBps != 1_500_000 || got.GBR.DownlinkBps != 750_000 {
		t.Fatalf("unexpected GBR desired state: %+v", got)
	}
	if got.MBR == nil || got.MBR.UplinkBps != 3_000_000 || got.MBR.DownlinkBps != 2_000_000 {
		t.Fatalf("unexpected MBR desired state: %+v", got)
	}

	updatePlan, err := parseUpdateQER(ie.NewUpdateQER(
		ie.NewQERID(7),
		ie.NewMBR(4000, 2500),
	))
	if err != nil {
		t.Fatalf("BuildUpdateQERPlan: %v", err)
	}
	commitChanges(t, sess, &rules.RuleChangeSet{UpdateQERs: []rules.QERPatch{updatePlan}})

	got = sess.QERIDs[7]
	if *got.QFI != 9 || got.GateStatus.Uplink != ie.GateStatusClosed || got.GateStatus.Downlink != ie.GateStatusOpen {
		t.Fatalf("partial update cleared QFI/gate: %+v", got)
	}
	if got.GBR.UplinkBps != 1_500_000 || got.GBR.DownlinkBps != 750_000 {
		t.Fatalf("partial update cleared GBR: %+v", got)
	}
	if got.MBR.UplinkBps != 4_000_000 || got.MBR.DownlinkBps != 2_500_000 {
		t.Fatalf("partial update did not replace MBR: %+v", got)
	}

	sess.ApplyRemoveQER(7)
	if _, ok := sess.QERIDs[7]; ok {
		t.Fatal("QER desired state survived Remove QER")
	}
}

func TestPDRDesiredStateCreateAndPartialUpdate(t *testing.T) {
	createPlan, err := parseCreatePDR(ie.NewCreatePDR(
		ie.NewPDRID(11),
		ie.NewPrecedence(100),
		ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess)),
		ie.NewFARID(5),
		ie.NewURRID(20),
		ie.NewQERID(7),
		ie.NewQERID(8),
	))
	if err != nil {
		t.Fatalf("BuildCreatePDRPlan: %v", err)
	}

	sess := newRuleStateTestSession()
	delete(sess.PDRIDs, 11)
	sess.FARIDs[5], sess.FARIDs[6] = &rules.FARConfig{FARID: 5}, &rules.FARConfig{FARID: 6}
	sess.QERIDs[8] = &rules.QERConfig{QERID: 8}
	sess.URRIDs[20], sess.URRIDs[21] = &URRInfo{Config: rules.URRConfig{URRID: 20}}, &URRInfo{Config: rules.URRConfig{URRID: 21}}
	commitChanges(t, sess, &rules.RuleChangeSet{CreatePDRs: []rules.PDRConfig{createPlan}})

	got := sess.PDRIDs[11]
	if got == nil || got.PDI == nil || got.PDI.SourceInterface != ie.SrcInterfaceAccess {
		t.Fatalf("unexpected PDR direction desired state: %+v", got)
	}
	if got.FARID == nil || *got.FARID != 5 {
		t.Fatalf("unexpected PDR FAR desired state: %+v", got)
	}
	if _, ok := uint32Set(got.URRIDs)[20]; !ok {
		t.Fatalf("PDR missing URR 20: %+v", got.URRIDs)
	}
	if sess.URRIDs[20].refPdrNum != 1 {
		t.Fatalf("unexpected URR 20 refcount: %d", sess.URRIDs[20].refPdrNum)
	}
	if _, ok := uint32Set(got.QERIDs)[7]; !ok {
		t.Fatalf("PDR missing QER 7: %+v", got.QERIDs)
	}
	if _, ok := uint32Set(got.QERIDs)[8]; !ok {
		t.Fatalf("PDR missing QER 8: %+v", got.QERIDs)
	}

	partialPlan, err := parseUpdatePDR(ie.NewUpdatePDR(
		ie.NewPDRID(11),
		ie.NewPrecedence(100),
	))
	if err != nil {
		t.Fatalf("BuildUpdatePDRPlan partial: %v", err)
	}
	if partialPlan.FARID != nil ||
		partialPlan.URRIDs != nil ||
		partialPlan.QERIDs != nil ||
		partialPlan.PDI != nil {
		t.Fatalf("absent PDR fields were marked present: %+v", partialPlan)
	}
	commitChanges(t, sess, &rules.RuleChangeSet{UpdatePDRs: []rules.PDRPatch{partialPlan}})

	got = sess.PDRIDs[11]
	if *got.FARID != 5 || len(got.URRIDs) != 1 || sess.URRIDs[20].refPdrNum != 1 {
		t.Fatalf("partial PDR update cleared FAR/URR desired state: %+v", got)
	}
	if got.PDI.SourceInterface != ie.SrcInterfaceAccess || len(got.QERIDs) != 2 {
		t.Fatalf("partial PDR update cleared desired state: %+v", got)
	}

	replacePlan, err := parseUpdatePDR(ie.NewUpdatePDR(
		ie.NewPDRID(11),
		ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceCore)),
		ie.NewFARID(6),
		ie.NewURRID(21),
		ie.NewQERID(8),
	))
	if err != nil {
		t.Fatalf("BuildUpdatePDRPlan replacement: %v", err)
	}
	commitChanges(t, sess, &rules.RuleChangeSet{UpdatePDRs: []rules.PDRPatch{replacePlan}})

	got = sess.PDRIDs[11]
	if *got.FARID != 6 {
		t.Fatalf("PDR FAR relationship was not replaced: %+v", got)
	}
	if _, ok := uint32Set(got.URRIDs)[21]; !ok || len(got.URRIDs) != 1 {
		t.Fatalf("PDR URR relationships were not replaced: %+v", got.URRIDs)
	}
	if sess.URRIDs[20].refPdrNum != 0 || sess.URRIDs[21].refPdrNum != 1 {
		t.Fatalf(
			"unexpected URR refcounts after replacement: old=%d new=%d",
			sess.URRIDs[20].refPdrNum,
			sess.URRIDs[21].refPdrNum,
		)
	}
	if got.PDI.SourceInterface != ie.SrcInterfaceCore {
		t.Fatalf("PDR source interface was not replaced: %+v", got)
	}
	if len(got.QERIDs) != 1 {
		t.Fatalf("PDR QER relationships were not replaced: %+v", got.QERIDs)
	}
	if _, ok := uint32Set(got.QERIDs)[8]; !ok {
		t.Fatalf("PDR replacement missing QER 8: %+v", got.QERIDs)
	}

	sess.ApplyRemovePDR(11)
	if sess.URRIDs[21].refPdrNum != 0 {
		t.Fatalf("unexpected URR 21 refcount after PDR removal: %d", sess.URRIDs[21].refPdrNum)
	}
	if _, ok := sess.PDRIDs[11]; ok {
		t.Fatal("PDR desired state survived Remove PDR")
	}
}

func TestQERDesiredStateRejectsInvalidQFIAndGate(t *testing.T) {

	if _, err := parseCreateQER(ie.NewCreateQER(
		ie.NewQERID(1),
		ie.NewGateStatus(ie.GateStatusOpen, ie.GateStatusOpen),
		ie.NewQFI(64),
	)); err == nil {
		t.Fatal("QFI 64 was accepted")
	}

	if _, err := parseCreateQER(ie.NewCreateQER(
		ie.NewQERID(1),
		ie.NewGateStatus(2, ie.GateStatusOpen),
	)); err == nil {
		t.Fatal("reserved uplink Gate Status was accepted")
	}
}
