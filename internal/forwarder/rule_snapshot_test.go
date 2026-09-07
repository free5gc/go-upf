package forwarder

import (
	"errors"
	"github.com/free5gc/go-gtp5gnl"
	"github.com/khirono/go-nl"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestAppliedRuleAttrMergeKeepsRuleNamespacesSeparate(t *testing.T) {
	t.Run("PDR PDI is replaced as a complete field", func(t *testing.T) {
		current := &PDRPlan{Attrs: []nl.Attr{{
			Type: gtp5gnl.PDR_PDI,
			Value: nl.AttrList{
				{Type: gtp5gnl.PDI_SRC_INTF, Value: nl.AttrU8(1)},
				{Type: gtp5gnl.PDI_UE_ADDR_IPV4, Value: nl.AttrBytes{10, 0, 0, 1}},
			},
		}}}
		patch := &PDRPlan{Attrs: []nl.Attr{{
			Type: gtp5gnl.PDR_PDI,
			Value: nl.AttrList{
				{Type: gtp5gnl.PDI_SRC_INTF, Value: nl.AttrU8(2)},
			},
		}}}

		merged := ruleConfig{Attrs: mergeRuleAttrs(current.Attrs, patch.Attrs)}
		pdi, ok := merged.Attrs[0].Value.(nl.AttrList)
		if !ok || len(pdi) != 1 || pdi[0].Type != gtp5gnl.PDI_SRC_INTF {
			t.Fatalf("PDI was recursively merged across rule namespaces: %+v", merged.Attrs)
		}
	})

	t.Run("FAR forwarding parameters preserve omitted nested fields", func(t *testing.T) {
		current := &FARPlan{Attrs: []nl.Attr{{
			Type: gtp5gnl.FAR_FORWARDING_PARAMETER,
			Value: nl.AttrList{
				{Type: gtp5gnl.FORWARDING_PARAMETER_OUTER_HEADER_CREATION, Value: nl.AttrList{}},
				{Type: gtp5gnl.FORWARDING_PARAMETER_FORWARDING_POLICY, Value: nl.AttrString("1")},
			},
		}}}
		patch := &FARPlan{Attrs: []nl.Attr{{
			Type: gtp5gnl.FAR_FORWARDING_PARAMETER,
			Value: nl.AttrList{
				{Type: gtp5gnl.FORWARDING_PARAMETER_FORWARDING_POLICY, Value: nl.AttrString("2")},
			},
		}}}

		info := ruleConfig{Attrs: mergeFARRuleAttrs(current.Attrs, patch.Attrs)}
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

// Observe snapshots at the backend boundary without exposing them to PFCP.
type snapshotDriver struct {
	Empty
	seen          *ModificationPlan
	failure       error
	cleanupResult *ExecutionResult
}

func (d *snapshotDriver) ExecuteEstablishmentPlan(p *ModificationPlan) (*ExecutionResult, error) {
	return d.ExecuteModificationPlan(p)
}
func (d *snapshotDriver) ExecuteModificationPlan(p *ModificationPlan) (*ExecutionResult, error) {
	d.seen = p
	if d.cleanupResult != nil {
		return d.cleanupResult, d.failure
	}
	if d.failure != nil {
		return NewExecutionResult(p.SEID), d.failure
	}
	return NewSuccessfulExecutionResult(p), nil
}

func TestSnapshotsTrackSuccessfulUpdatesAndSurviveFailure(t *testing.T) {
	d := &snapshotDriver{}
	s := NewSessionDatapath(d, 10)
	create := &ModificationPlan{SEID: 10, CreateQERs: []*QERPlan{{QERID: 7,
		OID: gtp5gnl.OID{10, 7}, Attrs: []nl.Attr{{Type: gtp5gnl.QER_GATE, Value: nl.AttrU8(1)}},
	}}}
	_, err := s.ExecuteEstablishmentPlan(create)
	require.NoError(t, err)
	// Mutation of both the request and the backend result must not mutate stored data.
	create.CreateQERs[0].OID[0] = 99
	create.CreateQERs[0].Attrs[0].Value = nl.AttrU8(99)
	update := &ModificationPlan{SEID: 10, UpdateQERs: []*QERPlan{{QERID: 7,
		Attrs: []nl.Attr{{Type: gtp5gnl.QER_QFI, Value: nl.AttrU8(9)}},
	}}}
	_, err = s.ExecuteModificationPlan(update)
	require.NoError(t, err)
	require.Nil(t, update.Rollback)
	before := d.seen.Rollback.QERs[7]
	require.Equal(t, gtp5gnl.OID{10, 7}, before.OID)
	require.Equal(t, nl.AttrU8(1), before.Attrs[0].Value)
	before.OID[0] = 88
	before.Attrs[0].Value = nl.AttrU8(88)

	d.failure = errors.New("kernel failed; configuration rollback completed")
	failed := &ModificationPlan{SEID: 10, UpdateQERs: []*QERPlan{{QERID: 7,
		Attrs: []nl.Attr{{Type: gtp5gnl.QER_GATE, Value: nl.AttrU8(2)}},
	}}}
	_, err = s.ExecuteModificationPlan(failed)
	require.ErrorIs(t, err, d.failure)
	require.Len(t, d.seen.Rollback.QERs[7].Attrs, 2)
	require.Equal(t, nl.AttrU8(1), d.seen.Rollback.QERs[7].Attrs[0].Value)
	d.failure = nil
	remove := &ModificationPlan{SEID: 10, RemoveQERs: []*QERPlan{{QERID: 7}}}
	_, err = s.ExecuteModificationPlan(remove)
	require.NoError(t, err)
	require.Equal(t, gtp5gnl.OID{10, 7}, d.seen.Rollback.QERs[7].OID)
	require.Equal(t, nl.AttrU8(1), d.seen.Rollback.QERs[7].Attrs[0].Value)
	_, err = s.ExecuteModificationPlan(remove)
	require.ErrorContains(t, err, "missing applied snapshot")
}

func TestSnapshotsOwnNestedBytes(t *testing.T) {
	d := &snapshotDriver{}
	s := NewSessionDatapath(d, 10)
	bytes := nl.AttrBytes{10, 0, 0, 1}
	nested := nl.AttrList{{Type: gtp5gnl.PDI_UE_ADDR_IPV4, Value: bytes}}
	_, err := s.ExecuteEstablishmentPlan(&ModificationPlan{SEID: 10, CreatePDRs: []*PDRPlan{{PDRID: 1,
		Attrs: []nl.Attr{{Type: gtp5gnl.PDR_PDI, Value: nested}},
	}}})
	require.NoError(t, err)
	bytes[0] = 99
	nested[0].Type = 99
	remove := &ModificationPlan{SEID: 10, RemovePDRs: []*PDRPlan{{PDRID: 1}}}
	d.failure = errors.New("rollback completed")
	_, _ = s.ExecuteModificationPlan(remove)
	old := d.seen.Rollback.PDRs[1].Attrs[0].Value.(nl.AttrList)
	require.Equal(t, uint16(gtp5gnl.PDI_UE_ADDR_IPV4), old[0].Type)
	require.Equal(t, nl.AttrBytes{10, 0, 0, 1}, old[0].Value)
	old[0].Value.(nl.AttrBytes)[0] = 88
	_, _ = s.ExecuteModificationPlan(remove)
	old = d.seen.Rollback.PDRs[1].Attrs[0].Value.(nl.AttrList)
	require.Equal(t, nl.AttrBytes{10, 0, 0, 1}, old[0].Value)
}

func TestSnapshotNamespacesAndSessionIsolation(t *testing.T) {
	d := &snapshotDriver{}
	first, second := NewSessionDatapath(d, 10), NewSessionDatapath(d, 11)
	cfg := []nl.Attr{{Type: 1, Value: nl.AttrU8(1)}}
	_, err := first.ExecuteEstablishmentPlan(&ModificationPlan{SEID: 10,
		CreatePDRs: []*PDRPlan{{PDRID: 1, Attrs: cfg}},
		CreateFARs: []*FARPlan{{FARID: 1, Attrs: cfg}},
		CreateQERs: []*QERPlan{{QERID: 1, Attrs: cfg}},
		CreateURRs: []*URRPlan{{URRID: 1, Attrs: cfg}},
		CreateBARs: []*BARPlan{{BARID: 1, Attrs: cfg}},
	})
	require.NoError(t, err)
	_, err = second.ExecuteModificationPlan(&ModificationPlan{SEID: 11, RemoveQERs: []*QERPlan{{QERID: 1}}})
	require.ErrorContains(t, err, "missing applied snapshot")
	_, err = first.ExecuteModificationPlan(&ModificationPlan{SEID: 10,
		UpdatePDRs: []*PDRPlan{{PDRID: 1}}, UpdateFARs: []*FARPlan{{FARID: 1}},
		UpdateQERs: []*QERPlan{{QERID: 1}}, UpdateURRs: []*URRPlan{{URRID: 1}}, UpdateBARs: []*BARPlan{{BARID: 1}},
	})
	require.NoError(t, err)
	require.Len(t, d.seen.Rollback.PDRs, 1)
	require.Len(t, d.seen.Rollback.FARs, 1)
	require.Len(t, d.seen.Rollback.QERs, 1)
	require.Len(t, d.seen.Rollback.URRs, 1)
	require.Len(t, d.seen.Rollback.BARs, 1)
}

func TestCleanupPublishesOnlyConfirmedRemovals(t *testing.T) {
	d := &snapshotDriver{}
	s := NewSessionDatapath(d, 10)
	_, err := s.ExecuteEstablishmentPlan(&ModificationPlan{SEID: 10, CreateQERs: []*QERPlan{{QERID: 1}, {QERID: 2}}})
	require.NoError(t, err)
	d.failure = errors.New("remove 2 failed")
	d.cleanupResult = NewSuccessfulExecutionResult(&ModificationPlan{SEID: 10, RemoveQERs: []*QERPlan{{QERID: 1}}})
	_, err = s.ExecuteDeletionPlan(&ModificationPlan{SEID: 10, RemoveQERs: []*QERPlan{{QERID: 1}, {QERID: 2}}})
	require.ErrorIs(t, err, d.failure)
	require.Nil(t, d.seen.Rollback)
	d.failure, d.cleanupResult = nil, nil
	_, err = s.ExecuteModificationPlan(&ModificationPlan{SEID: 10, UpdateQERs: []*QERPlan{{QERID: 1}}})
	require.ErrorContains(t, err, "missing applied snapshot")
	_, err = s.ExecuteModificationPlan(&ModificationPlan{SEID: 10, UpdateQERs: []*QERPlan{{QERID: 2}}})
	require.NoError(t, err)
}

func TestFailedEstablishmentDoesNotPublishSnapshots(t *testing.T) {
	d := &snapshotDriver{failure: errors.New("establishment rolled back")}
	s := NewSessionDatapath(d, 10)
	create := &ModificationPlan{SEID: 10, CreateQERs: []*QERPlan{{QERID: 1}}}
	_, err := s.ExecuteEstablishmentPlan(create)
	require.ErrorIs(t, err, d.failure)
	require.Nil(t, create.Rollback)
	seen := d.seen
	_, err = s.ExecuteModificationPlan(&ModificationPlan{SEID: 10, UpdateQERs: []*QERPlan{{QERID: 1}}})
	require.ErrorContains(t, err, "missing applied snapshot")
	require.Same(t, seen, d.seen, "missing snapshot must fail before backend execution")
}

func TestCleanupRejectsNonRemovalOperations(t *testing.T) {
	d := &snapshotDriver{}
	s := NewSessionDatapath(d, 10)
	_, err := s.ExecuteDeletionPlan(&ModificationPlan{SEID: 10, UpdateQERs: []*QERPlan{{QERID: 1}}})
	require.ErrorContains(t, err, "removal-only")
	require.Nil(t, d.seen)
}
