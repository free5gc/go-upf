package pfcp

import (
	"errors"
	"reflect"
	"testing"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"

	"github.com/free5gc/go-upf/internal/forwarder"
)

type recordingPlanDriver struct {
	forwarder.Empty
	calls  []string
	failOn string
}

func (d *recordingPlanDriver) record(operation string) error {
	d.calls = append(d.calls, operation)
	if d.failOn == operation {
		return errors.New("builder failed")
	}
	return nil
}

func (d *recordingPlanDriver) BuildCreatePDRPlan(
	localSEID uint64,
	req *ie.IE,
) (*forwarder.PDRPlan, error) {
	if err := d.record("CreatePDR"); err != nil {
		return nil, err
	}
	return &forwarder.PDRPlan{PDRID: 1}, nil
}

func (d *recordingPlanDriver) BuildUpdatePDRPlan(
	localSEID uint64,
	req *ie.IE,
) (*forwarder.PDRPlan, error) {
	if err := d.record("UpdatePDR"); err != nil {
		return nil, err
	}
	return &forwarder.PDRPlan{PDRID: 1}, nil
}

func (d *recordingPlanDriver) BuildRemovePDRPlan(
	localSEID uint64,
	req *ie.IE,
) (*forwarder.PDRPlan, error) {
	if err := d.record("RemovePDR"); err != nil {
		return nil, err
	}
	return &forwarder.PDRPlan{PDRID: 1}, nil
}

func (d *recordingPlanDriver) BuildCreateFARPlan(
	localSEID uint64,
	req *ie.IE,
) (*forwarder.FARPlan, error) {
	if err := d.record("CreateFAR"); err != nil {
		return nil, err
	}
	return &forwarder.FARPlan{FARID: 1}, nil
}

func (d *recordingPlanDriver) BuildUpdateFARPlan(
	localSEID uint64,
	req *ie.IE,
) (*forwarder.FARPlan, error) {
	if err := d.record("UpdateFAR"); err != nil {
		return nil, err
	}
	return &forwarder.FARPlan{FARID: 1}, nil
}

func (d *recordingPlanDriver) BuildRemoveFARPlan(
	localSEID uint64,
	req *ie.IE,
) (*forwarder.FARPlan, error) {
	if err := d.record("RemoveFAR"); err != nil {
		return nil, err
	}
	return &forwarder.FARPlan{FARID: 1}, nil
}

func (d *recordingPlanDriver) BuildCreateQERPlan(
	localSEID uint64,
	req *ie.IE,
) (*forwarder.QERPlan, error) {
	if err := d.record("CreateQER"); err != nil {
		return nil, err
	}
	return &forwarder.QERPlan{QERID: 1}, nil
}

func (d *recordingPlanDriver) BuildUpdateQERPlan(
	localSEID uint64,
	req *ie.IE,
) (*forwarder.QERPlan, error) {
	if err := d.record("UpdateQER"); err != nil {
		return nil, err
	}
	return &forwarder.QERPlan{QERID: 1}, nil
}

func (d *recordingPlanDriver) BuildRemoveQERPlan(
	localSEID uint64,
	req *ie.IE,
) (*forwarder.QERPlan, error) {
	if err := d.record("RemoveQER"); err != nil {
		return nil, err
	}
	return &forwarder.QERPlan{QERID: 1}, nil
}

func (d *recordingPlanDriver) BuildCreateURRPlan(
	localSEID uint64,
	req *ie.IE,
) (*forwarder.URRPlan, error) {
	if err := d.record("CreateURR"); err != nil {
		return nil, err
	}
	return &forwarder.URRPlan{URRID: 1}, nil
}

func (d *recordingPlanDriver) BuildUpdateURRPlan(
	localSEID uint64,
	req *ie.IE,
) (*forwarder.URRPlan, error) {
	if err := d.record("UpdateURR"); err != nil {
		return nil, err
	}
	return &forwarder.URRPlan{URRID: 1}, nil
}

func (d *recordingPlanDriver) BuildRemoveURRPlan(
	localSEID uint64,
	req *ie.IE,
) (*forwarder.URRPlan, error) {
	if err := d.record("RemoveURR"); err != nil {
		return nil, err
	}
	return &forwarder.URRPlan{URRID: 1}, nil
}

func (d *recordingPlanDriver) BuildQueryURRPlan(
	localSEID uint64,
	req *ie.IE,
) (*forwarder.URRPlan, error) {
	if err := d.record("QueryURR"); err != nil {
		return nil, err
	}
	return &forwarder.URRPlan{QueryURRID: 1}, nil
}

func (d *recordingPlanDriver) BuildCreateBARPlan(
	localSEID uint64,
	req *ie.IE,
) (*forwarder.BARPlan, error) {
	if err := d.record("CreateBAR"); err != nil {
		return nil, err
	}
	return &forwarder.BARPlan{BARID: 1}, nil
}

func (d *recordingPlanDriver) BuildUpdateBARPlan(
	localSEID uint64,
	req *ie.IE,
) (*forwarder.BARPlan, error) {
	if err := d.record("UpdateBAR"); err != nil {
		return nil, err
	}
	return &forwarder.BARPlan{BARID: 1}, nil
}

func (d *recordingPlanDriver) BuildRemoveBARPlan(
	localSEID uint64,
	req *ie.IE,
) (*forwarder.BARPlan, error) {
	if err := d.record("RemoveBAR"); err != nil {
		return nil, err
	}
	return &forwarder.BARPlan{BARID: 1}, nil
}

func ruleIEs() []*ie.IE {
	return []*ie.IE{{}}
}

func TestBuildEstablishmentPlan(t *testing.T) {
	driver := &recordingPlanDriver{}
	session := &Session{LocalID: 42, driver: driver}
	req := &message.SessionEstablishmentRequest{
		CreateFAR: ruleIEs(),
		CreateQER: ruleIEs(),
		CreateURR: ruleIEs(),
		CreateBAR: &ie.IE{},
		CreatePDR: ruleIEs(),
	}

	plan, err := session.BuildEstablishmentPlan(req)
	if err != nil {
		t.Fatalf("BuildEstablishmentPlan: %v", err)
	}
	if plan.SEID != session.LocalID {
		t.Fatalf("unexpected plan SEID: got %d want %d", plan.SEID, session.LocalID)
	}
	wantCalls := []string{"CreateFAR", "CreateQER", "CreateURR", "CreateBAR", "CreatePDR"}
	if !reflect.DeepEqual(driver.calls, wantCalls) {
		t.Fatalf("unexpected builder order: got %v want %v", driver.calls, wantCalls)
	}
	if len(plan.CreateFARs) != 1 || len(plan.CreateQERs) != 1 ||
		len(plan.CreateURRs) != 1 || len(plan.CreateBARs) != 1 ||
		len(plan.CreatePDRs) != 1 {
		t.Fatalf("request operations were not collected: %+v", plan)
	}
}

func TestBuildEstablishmentPlanMapsMissingPDRIEToMandatoryCause(t *testing.T) {
	session := &Session{LocalID: 42, driver: new(forwarder.Gtp5g)}
	req := &message.SessionEstablishmentRequest{
		CreatePDR: []*ie.IE{ie.NewCreatePDR(
			ie.NewPrecedence(100),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess)),
		)},
	}

	_, err := session.BuildEstablishmentPlan(req)
	if !errors.Is(err, ErrMissingMandatoryIE) {
		t.Fatalf("expected PFCP mandatory-IE error, got %v", err)
	}
}

func TestBuildModificationPlan(t *testing.T) {
	driver := &recordingPlanDriver{}
	session := &Session{LocalID: 42, driver: driver}
	req := &message.SessionModificationRequest{
		CreateFAR: ruleIEs(),
		CreateQER: ruleIEs(),
		CreateURR: ruleIEs(),
		CreateBAR: &ie.IE{},
		CreatePDR: ruleIEs(),
		UpdateFAR: ruleIEs(),
		UpdateQER: ruleIEs(),
		UpdateURR: ruleIEs(),
		UpdateBAR: &ie.IE{},
		UpdatePDR: ruleIEs(),
		QueryURR:  ruleIEs(),
		RemoveFAR: ruleIEs(),
		RemoveQER: ruleIEs(),
		RemoveURR: ruleIEs(),
		RemoveBAR: &ie.IE{},
		RemovePDR: ruleIEs(),
	}

	plan, err := session.BuildModificationPlan(req)
	if err != nil {
		t.Fatalf("BuildModificationPlan: %v", err)
	}
	if plan.SEID != session.LocalID {
		t.Fatalf("unexpected plan SEID: got %d want %d", plan.SEID, session.LocalID)
	}
	wantCalls := []string{
		"CreateFAR", "CreateQER", "CreateURR", "CreateBAR", "CreatePDR",
		"UpdateFAR", "UpdateQER", "UpdateURR", "UpdateBAR", "UpdatePDR",
		"QueryURR",
		"RemoveFAR", "RemoveQER", "RemoveURR", "RemoveBAR", "RemovePDR",
	}
	if !reflect.DeepEqual(driver.calls, wantCalls) {
		t.Fatalf("unexpected builder order: got %v want %v", driver.calls, wantCalls)
	}
	if len(plan.CreatePDRs) != 1 || len(plan.UpdatePDRs) != 1 ||
		len(plan.QueryURRs) != 1 || len(plan.RemovePDRs) != 1 {
		t.Fatalf("request operations were not collected: %+v", plan)
	}
}

func TestBuildRequestPlanMapsBuilderErrors(t *testing.T) {
	t.Run("CreatePDR", func(t *testing.T) {
		driver := &recordingPlanDriver{failOn: "CreatePDR"}
		session := &Session{LocalID: 42, driver: driver}
		_, err := session.BuildEstablishmentPlan(&message.SessionEstablishmentRequest{
			CreatePDR: ruleIEs(),
		})
		if !errors.Is(err, ErrRuleCreationModificationFailed) {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("UpdateQER", func(t *testing.T) {
		driver := &recordingPlanDriver{failOn: "UpdateQER"}
		session := &Session{LocalID: 42, driver: driver}
		_, err := session.BuildModificationPlan(&message.SessionModificationRequest{
			UpdateQER: ruleIEs(),
		})
		if !errors.Is(err, ErrMissingMandatoryIE) {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestBuildRequestPlanRejectsNilRequest(t *testing.T) {
	session := &Session{}
	if _, err := session.BuildEstablishmentPlan(nil); !errors.Is(err, ErrMissingMandatoryIE) {
		t.Fatalf("unexpected establishment error: %v", err)
	}
	if _, err := session.BuildModificationPlan(nil); !errors.Is(err, ErrMissingMandatoryIE) {
		t.Fatalf("unexpected modification error: %v", err)
	}
}
