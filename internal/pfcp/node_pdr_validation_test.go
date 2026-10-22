package pfcp

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/wmnsk/go-pfcp/ie"

	"github.com/free5gc/go-upf/internal/forwarder"
	"github.com/free5gc/go-upf/internal/logger"
	logger_util "github.com/free5gc/util/logger"
)

// newPDRValidationTestSess builds a Sess backed by a real (zero-value) driver
// so that ValidateCreatePDR/ValidateUpdatePDR exercise genuine IE parsing
// (forwarder.Gtp5g.BuildCreatePDRPlan/BuildUpdatePDRPlan) rather than the
// forwarder.Empty{} stub, which ignores its request entirely and would make
// these tests meaningless. The zero-value Gtp5g never touches its netlink
// fields on this path, so no kernel/gtp5g module privileges are required.
func newPDRValidationTestSess(t *testing.T) *Sess {
	t.Helper()
	lnode := &LocalNode{}
	rnode := NewRemoteNode(
		"smf1",
		nil,
		lnode,
		&forwarder.Gtp5g{},
		logger.PfcpLog.WithField(logger_util.FieldControlPlaneNodeID, "smf1"),
	)
	return rnode.NewSess(1)
}

// validPDI builds a minimal but spec-valid PDI (Source Interface is PDI's
// only mandatory IE).
func validPDI() *ie.IE {
	return ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess))
}

// TestValidateCreatePDR_DanglingFARIDRejected reproduces the free5gc/go-upf
// issue #63 packet trace: a Create PDR references "FAR ID: Dynamic by CP 10",
// which is not created anywhere in this request (nor does it pre-exist in the
// session). Per TS 29.244 6.3.2.3, the UPF must reject the whole request with
// a non-success cause instead of silently dropping the dangling reference and
// responding with Cause "Request accepted". Before this fix, ValidateCreatePDR
// had no FAR-existence check at all, so this request passed validation and the
// dangling reference only surfaced later when gtp5g netlink rejected it.
func TestValidateCreatePDR_DanglingFARIDRejected(t *testing.T) {
	sess := newPDRValidationTestSess(t)
	modPlan := forwarder.NewModificationPlan(sess.LocalID)

	req := ie.NewCreatePDR(
		ie.NewPDRID(1010),
		ie.NewPrecedence(255),
		validPDI(),
		ie.NewFARID(10), // never created in this request or session state
		ie.NewQERID(1010),
	)

	plan, err := sess.ValidateCreatePDR(req, modPlan)
	require.Error(t, err)
	assert.Nil(t, plan)
	assert.Equal(t, ie.CauseRuleCreationModificationFailure, pfcpCauseFromError(err))
}

// TestValidateCreatePDR_DanglingQERIDRejected is the QER ID analogue of the
// same issue #63 gap: a Create PDR referencing a QER ID that was never created
// must also be rejected, not silently accepted.
func TestValidateCreatePDR_DanglingQERIDRejected(t *testing.T) {
	sess := newPDRValidationTestSess(t)
	modPlan := forwarder.NewModificationPlan(sess.LocalID)

	// FAR 2 is created earlier in the same request, so the FAR reference is
	// valid; only the QER reference is dangling.
	modPlan.CreateFARs = append(modPlan.CreateFARs, &forwarder.FARPlan{FARID: 2})

	req := ie.NewCreatePDR(
		ie.NewPDRID(1),
		ie.NewPrecedence(255),
		validPDI(),
		ie.NewFARID(2),
		ie.NewQERID(999), // never created in this request or session state
	)

	plan, err := sess.ValidateCreatePDR(req, modPlan)
	require.Error(t, err)
	assert.Nil(t, plan)
	assert.Equal(t, ie.CauseRuleCreationModificationFailure, pfcpCauseFromError(err))
}

// TestValidateCreatePDR_ValidReferencesAccepted is the companion success case:
// a FAR created earlier in the same request and a QER that already exists in
// session state are both legitimate references and must not be rejected.
func TestValidateCreatePDR_ValidReferencesAccepted(t *testing.T) {
	sess := newPDRValidationTestSess(t)
	sess.QERIDs[5] = struct{}{} // pre-existing from a prior session modification
	modPlan := forwarder.NewModificationPlan(sess.LocalID)
	modPlan.CreateFARs = append(modPlan.CreateFARs, &forwarder.FARPlan{FARID: 2})

	req := ie.NewCreatePDR(
		ie.NewPDRID(1),
		ie.NewPrecedence(255),
		validPDI(),
		ie.NewFARID(2),
		ie.NewQERID(5),
	)

	plan, err := sess.ValidateCreatePDR(req, modPlan)
	require.NoError(t, err)
	require.NotNil(t, plan)
	assert.Equal(t, uint16(1), plan.PDRID)
}

// TestValidateUpdatePDR_DanglingFARIDRejected: the same dangling-reference gap
// exists on the Update PDR path (an Update PDR can repoint a PDR at a FAR ID
// that was never created), and must be rejected the same way.
func TestValidateUpdatePDR_DanglingFARIDRejected(t *testing.T) {
	sess := newPDRValidationTestSess(t)
	sess.PDRIDs[1] = &PDRInfo{RelatedURRIDs: map[uint32]struct{}{}}
	modPlan := forwarder.NewModificationPlan(sess.LocalID)

	req := ie.NewUpdatePDR(
		ie.NewPDRID(1),
		ie.NewFARID(10), // never created
	)

	plan, err := sess.ValidateUpdatePDR(req, modPlan)
	require.Error(t, err)
	assert.Nil(t, plan)
	assert.Equal(t, ie.CauseRuleCreationModificationFailure, pfcpCauseFromError(err))
}

// TestValidateUpdatePDR_DanglingQERIDRejected is the QER ID analogue for
// Update PDR.
func TestValidateUpdatePDR_DanglingQERIDRejected(t *testing.T) {
	sess := newPDRValidationTestSess(t)
	sess.PDRIDs[1] = &PDRInfo{RelatedURRIDs: map[uint32]struct{}{}}
	sess.FARIDs[2] = struct{}{}
	modPlan := forwarder.NewModificationPlan(sess.LocalID)

	req := ie.NewUpdatePDR(
		ie.NewPDRID(1),
		ie.NewFARID(2),
		ie.NewQERID(999), // never created
	)

	plan, err := sess.ValidateUpdatePDR(req, modPlan)
	require.Error(t, err)
	assert.Nil(t, plan)
	assert.Equal(t, ie.CauseRuleCreationModificationFailure, pfcpCauseFromError(err))
}

// TestValidateUpdatePDR_ValidReferencesAccepted is the Update PDR success
// companion case.
func TestValidateUpdatePDR_ValidReferencesAccepted(t *testing.T) {
	sess := newPDRValidationTestSess(t)
	sess.PDRIDs[1] = &PDRInfo{RelatedURRIDs: map[uint32]struct{}{}}
	sess.FARIDs[2] = struct{}{}
	sess.QERIDs[5] = struct{}{}
	modPlan := forwarder.NewModificationPlan(sess.LocalID)

	req := ie.NewUpdatePDR(
		ie.NewPDRID(1),
		ie.NewFARID(2),
		ie.NewQERID(5),
	)

	plan, err := sess.ValidateUpdatePDR(req, modPlan)
	require.NoError(t, err)
	require.NotNil(t, plan)
	assert.Equal(t, uint16(1), plan.PDRID)
}
