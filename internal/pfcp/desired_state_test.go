package pfcp

import (
	"testing"

	"github.com/wmnsk/go-pfcp/ie"

	"github.com/free5gc/go-upf/internal/forwarder"
)

func TestQERDesiredStateCreateAndPartialUpdate(t *testing.T) {
	g := new(forwarder.Gtp5g)
	createPlan, err := g.BuildCreateQERPlan(10, ie.NewCreateQER(
		ie.NewQERID(7),
		ie.NewQFI(9),
		ie.NewGateStatus(ie.GateStatusClosed, ie.GateStatusOpen),
		ie.NewGBR(1500, 750),
		ie.NewMBR(3000, 2000),
	))
	if err != nil {
		t.Fatalf("BuildCreateQERPlan: %v", err)
	}

	sess := &Sess{QERIDs: make(map[uint32]*QERInfo)}
	sess.ApplyCreateQER(createPlan)

	got := sess.QERIDs[7]
	if got == nil {
		t.Fatal("QER desired state was not saved")
	}
	if got.QFI != 9 || !got.HasGate || got.GateUL != ie.GateStatusClosed || got.GateDL != ie.GateStatusOpen {
		t.Fatalf("unexpected QFI/gate desired state: %+v", got)
	}
	if !got.HasGBR || got.GBRULBps != 1_500_000 || got.GBRDLBps != 750_000 {
		t.Fatalf("unexpected GBR desired state: %+v", got)
	}
	if !got.HasMBR || got.MBRULBps != 3_000_000 || got.MBRDLBps != 2_000_000 {
		t.Fatalf("unexpected MBR desired state: %+v", got)
	}

	updatePlan, err := g.BuildUpdateQERPlan(10, ie.NewUpdateQER(
		ie.NewQERID(7),
		ie.NewMBR(4000, 2500),
	))
	if err != nil {
		t.Fatalf("BuildUpdateQERPlan: %v", err)
	}
	sess.ApplyUpdateQER(updatePlan)

	got = sess.QERIDs[7]
	if got.QFI != 9 || got.GateUL != ie.GateStatusClosed || got.GateDL != ie.GateStatusOpen {
		t.Fatalf("partial update cleared QFI/gate: %+v", got)
	}
	if got.GBRULBps != 1_500_000 || got.GBRDLBps != 750_000 {
		t.Fatalf("partial update cleared GBR: %+v", got)
	}
	if got.MBRULBps != 4_000_000 || got.MBRDLBps != 2_500_000 {
		t.Fatalf("partial update did not replace MBR: %+v", got)
	}

	sess.ApplyRemoveQER(&forwarder.QERPlan{QERID: 7})
	if _, ok := sess.QERIDs[7]; ok {
		t.Fatal("QER desired state survived Remove QER")
	}
}

func TestPDRDesiredStateCreateAndPartialUpdate(t *testing.T) {
	g := new(forwarder.Gtp5g)
	createPlan, err := g.BuildCreatePDRPlan(10, ie.NewCreatePDR(
		ie.NewPDRID(11),
		ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess)),
		ie.NewFARID(5),
		ie.NewURRID(20),
		ie.NewQERID(7),
		ie.NewQERID(8),
	))
	if err != nil {
		t.Fatalf("BuildCreatePDRPlan: %v", err)
	}

	sess := &Sess{
		PDRIDs: make(map[uint16]*PDRInfo),
		URRIDs: map[uint32]*URRInfo{
			20: {},
			21: {},
		},
		rnode: &RemoteNode{driver: forwarder.Empty{}},
	}
	sess.ApplyCreatePDR(createPlan)

	got := sess.PDRIDs[11]
	if got == nil || !got.HasSourceInterface || got.SourceInterface != ie.SrcInterfaceAccess {
		t.Fatalf("unexpected PDR direction desired state: %+v", got)
	}
	if !got.HasFARID || got.FARID != 5 {
		t.Fatalf("unexpected PDR FAR desired state: %+v", got)
	}
	if _, ok := got.RelatedURRIDs[20]; !ok {
		t.Fatalf("PDR missing URR 20: %+v", got.RelatedURRIDs)
	}
	if sess.URRIDs[20].refPdrNum != 1 {
		t.Fatalf("unexpected URR 20 refcount: %d", sess.URRIDs[20].refPdrNum)
	}
	if _, ok := got.RelatedQERIDs[7]; !ok {
		t.Fatalf("PDR missing QER 7: %+v", got.RelatedQERIDs)
	}
	if _, ok := got.RelatedQERIDs[8]; !ok {
		t.Fatalf("PDR missing QER 8: %+v", got.RelatedQERIDs)
	}

	partialPlan, err := g.BuildUpdatePDRPlan(10, ie.NewUpdatePDR(
		ie.NewPDRID(11),
		ie.NewPrecedence(100),
	))
	if err != nil {
		t.Fatalf("BuildUpdatePDRPlan partial: %v", err)
	}
	if partialPlan.FARIDPresent ||
		partialPlan.URRIDsPresent ||
		partialPlan.QERIDsPresent ||
		partialPlan.SourceInterface != nil {
		t.Fatalf("absent PDR fields were marked present: %+v", partialPlan)
	}
	sess.ApplyUpdatePDR(partialPlan)

	got = sess.PDRIDs[11]
	if got.FARID != 5 || len(got.RelatedURRIDs) != 1 || sess.URRIDs[20].refPdrNum != 1 {
		t.Fatalf("partial PDR update cleared FAR/URR desired state: %+v", got)
	}
	if got.SourceInterface != ie.SrcInterfaceAccess || len(got.RelatedQERIDs) != 2 {
		t.Fatalf("partial PDR update cleared desired state: %+v", got)
	}

	replacePlan, err := g.BuildUpdatePDRPlan(10, ie.NewUpdatePDR(
		ie.NewPDRID(11),
		ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceCore)),
		ie.NewFARID(6),
		ie.NewURRID(21),
		ie.NewQERID(8),
	))
	if err != nil {
		t.Fatalf("BuildUpdatePDRPlan replacement: %v", err)
	}
	sess.ApplyUpdatePDR(replacePlan)

	got = sess.PDRIDs[11]
	if got.FARID != 6 {
		t.Fatalf("PDR FAR relationship was not replaced: %+v", got)
	}
	if _, ok := got.RelatedURRIDs[21]; !ok || len(got.RelatedURRIDs) != 1 {
		t.Fatalf("PDR URR relationships were not replaced: %+v", got.RelatedURRIDs)
	}
	if sess.URRIDs[20].refPdrNum != 0 || sess.URRIDs[21].refPdrNum != 1 {
		t.Fatalf(
			"unexpected URR refcounts after replacement: old=%d new=%d",
			sess.URRIDs[20].refPdrNum,
			sess.URRIDs[21].refPdrNum,
		)
	}
	if got.SourceInterface != ie.SrcInterfaceCore {
		t.Fatalf("PDR source interface was not replaced: %+v", got)
	}
	if len(got.RelatedQERIDs) != 1 {
		t.Fatalf("PDR QER relationships were not replaced: %+v", got.RelatedQERIDs)
	}
	if _, ok := got.RelatedQERIDs[8]; !ok {
		t.Fatalf("PDR replacement missing QER 8: %+v", got.RelatedQERIDs)
	}

	sess.ApplyRemovePDR(&forwarder.PDRPlan{PDRID: 11})
	if sess.URRIDs[21].refPdrNum != 0 {
		t.Fatalf("unexpected URR 21 refcount after PDR removal: %d", sess.URRIDs[21].refPdrNum)
	}
	if _, ok := sess.PDRIDs[11]; ok {
		t.Fatal("PDR desired state survived Remove PDR")
	}
}

func TestQERDesiredStateRejectsInvalidQFIAndGate(t *testing.T) {
	g := new(forwarder.Gtp5g)

	if _, err := g.BuildCreateQERPlan(10, ie.NewCreateQER(
		ie.NewQERID(1),
		ie.NewQFI(64),
	)); err == nil {
		t.Fatal("QFI 64 was accepted")
	}

	if _, err := g.BuildCreateQERPlan(10, ie.NewCreateQER(
		ie.NewQERID(1),
		ie.NewGateStatus(2, ie.GateStatusOpen),
	)); err == nil {
		t.Fatal("reserved uplink Gate Status was accepted")
	}
}
