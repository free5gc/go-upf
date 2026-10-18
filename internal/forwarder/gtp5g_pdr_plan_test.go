package forwarder

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/wmnsk/go-pfcp/ie"
)

// BuildCreatePDRPlan and BuildUpdatePDRPlan only parse IEs and never touch the
// netlink handles, so a zero-value Gtp5g is enough to exercise IE parsing
// without the privileges OpenGtp5g needs.
var pdrPlanTestG = &Gtp5g{}

func validPDR_PDI() *ie.IE {
	return ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess))
}

// TestBuildCreatePDRPlan_TracksFARAndQERReferences verifies that FAR ID and
// QER ID IEs parsed out of a Create PDR are recorded on the resulting PDRPlan
// (HasFARID/FARID/QERIDs), mirroring how URRID references are already tracked
// in URRIDs. Before this change these IEs were parsed into netlink attrs but
// silently dropped on the floor, which is what let issue #63's dangling FAR ID
// reference slip past validation and only fail later at the gtp5g kernel
// module.
func TestBuildCreatePDRPlan_TracksFARAndQERReferences(t *testing.T) {
	req := ie.NewCreatePDR(
		ie.NewPDRID(1010),
		ie.NewPrecedence(255),
		validPDR_PDI(),
		ie.NewFARID(10),
		ie.NewQERID(1010),
		ie.NewURRID(5),
	)

	plan, err := pdrPlanTestG.BuildCreatePDRPlan(1, req)
	require.NoError(t, err)
	assert.True(t, plan.HasFARID)
	assert.Equal(t, uint32(10), plan.FARID)
	assert.Equal(t, []uint32{1010}, plan.QERIDs)
	assert.Equal(t, []uint32{5}, plan.URRIDs)
}

// A Create PDR with no FAR ID IE at all must not be reported as referencing
// FAR 0: HasFARID distinguishes "absent" from "FAR ID 0 referenced".
func TestBuildCreatePDRPlan_NoFARIDReferenced(t *testing.T) {
	req := ie.NewCreatePDR(
		ie.NewPDRID(1),
		ie.NewPrecedence(255),
		validPDR_PDI(),
	)

	plan, err := pdrPlanTestG.BuildCreatePDRPlan(1, req)
	require.NoError(t, err)
	assert.False(t, plan.HasFARID)
	assert.Empty(t, plan.QERIDs)
}

// QER ID may appear more than once in a single PDR; all occurrences must be
// tracked, not just the first/last.
func TestBuildCreatePDRPlan_MultipleQERIDs(t *testing.T) {
	req := ie.NewCreatePDR(
		ie.NewPDRID(1),
		ie.NewPrecedence(255),
		validPDR_PDI(),
		ie.NewFARID(2),
		ie.NewQERID(10),
		ie.NewQERID(11),
	)

	plan, err := pdrPlanTestG.BuildCreatePDRPlan(1, req)
	require.NoError(t, err)
	assert.Equal(t, []uint32{10, 11}, plan.QERIDs)
}

// TestBuildUpdatePDRPlan_TracksFARAndQERReferences is the Update PDR analogue:
// an Update PDR can also repoint a PDR at a FAR ID / QER ID that was never
// created, and the same tracking gap existed there.
func TestBuildUpdatePDRPlan_TracksFARAndQERReferences(t *testing.T) {
	req := ie.NewUpdatePDR(
		ie.NewPDRID(1),
		ie.NewFARID(4),
		ie.NewQERID(7),
	)

	plan, err := pdrPlanTestG.BuildUpdatePDRPlan(1, req)
	require.NoError(t, err)
	assert.True(t, plan.HasFARID)
	assert.Equal(t, uint32(4), plan.FARID)
	assert.Equal(t, []uint32{7}, plan.QERIDs)
}

func TestBuildUpdatePDRPlan_NoFARIDReferenced(t *testing.T) {
	req := ie.NewUpdatePDR(
		ie.NewPDRID(1),
	)

	plan, err := pdrPlanTestG.BuildUpdatePDRPlan(1, req)
	require.NoError(t, err)
	assert.False(t, plan.HasFARID)
	assert.Empty(t, plan.QERIDs)
}
