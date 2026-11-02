package forwarder

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/wmnsk/go-pfcp/ie"

	"github.com/free5gc/go-gtp5gnl"
)

// BuildCreatePDRPlan and BuildUpdatePDRPlan only parse IEs and never touch the
// netlink handles, so a zero-value Gtp5g is enough to exercise every validation
// path without the privileges OpenGtp5g needs.
var planTestG = &Gtp5g{}

func validPDI() *ie.IE {
	return ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess))
}

// malformedPDI carries a valid Source Interface plus an SDF Filter whose payload
// is shorter than the 3 bytes TS 29.244 8.2.5 requires. newPdi therefore fails
// with an error that is neither ErrMandatoryIEMissing nor ErrConditionalIEMissing,
// which lets a test tell a parse failure apart from a presence failure.
func malformedPDI() *ie.IE {
	return ie.NewPDI(
		ie.NewSourceInterface(ie.SrcInterfaceAccess),
		ie.New(ie.SDFFilter, []byte{0x01}),
	)
}

func TestBuildCreatePDRPlan_IEValidation(t *testing.T) {
	tests := []struct {
		name    string
		req     *ie.IE
		wantErr error
	}{
		{
			name: "all mandatory IEs present",
			req: ie.NewCreatePDR(
				ie.NewPDRID(1), ie.NewPrecedence(255), validPDI(), ie.NewFARID(2),
			),
		},
		{
			name: "MAR ID waives the FAR ID condition",
			req: ie.NewCreatePDR(
				ie.NewPDRID(1), ie.NewPrecedence(255), validPDI(), ie.NewMARID(3),
			),
		},
		{
			name:    "missing PDR ID",
			req:     ie.NewCreatePDR(ie.NewPrecedence(255), validPDI(), ie.NewFARID(2)),
			wantErr: ErrMandatoryIEMissing,
		},
		{
			name:    "missing Precedence",
			req:     ie.NewCreatePDR(ie.NewPDRID(1), validPDI(), ie.NewFARID(2)),
			wantErr: ErrMandatoryIEMissing,
		},
		{
			name:    "missing PDI",
			req:     ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(255), ie.NewFARID(2)),
			wantErr: ErrMandatoryIEMissing,
		},
		{
			name:    "neither FAR ID nor MAR ID",
			req:     ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(255), validPDI()),
			wantErr: ErrConditionalIEMissing,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := planTestG.BuildCreatePDRPlan(1, tt.req)
			if tt.wantErr == nil {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Truef(t, errors.Is(err, tt.wantErr), "got %v, want %v", err, tt.wantErr)
		})
	}
}

// A missing mandatory IE must win over a malformed one even when the malformed
// IE comes first on the wire, so the Cause reported to the CP function does not
// depend on the order the SMF happened to encode the IEs in.
func TestBuildCreatePDRPlan_MissingIEReportedBeforeMalformedIE(t *testing.T) {
	req := ie.NewCreatePDR(
		malformedPDI(), // malformed, and encoded ahead of everything else
		ie.NewPDRID(1),
		ie.NewFARID(2),
		// Precedence deliberately absent
	)

	_, err := planTestG.BuildCreatePDRPlan(1, req)
	require.Error(t, err)
	assert.Truef(t, errors.Is(err, ErrMandatoryIEMissing), "got %v", err)
}

// With every mandatory IE present, a malformed PDI must still fail the request
// rather than silently building a PDR with no packet detection information.
func TestBuildCreatePDRPlan_MalformedPDIFails(t *testing.T) {
	req := ie.NewCreatePDR(
		ie.NewPDRID(1), ie.NewPrecedence(255), malformedPDI(), ie.NewFARID(2),
	)

	_, err := planTestG.BuildCreatePDRPlan(1, req)
	require.Error(t, err)
	assert.Falsef(t, errors.Is(err, ErrMandatoryIEMissing), "got %v", err)
}

// QER ID and URR ID may appear more than once in a single PDR; none may be lost
// when the IEs are grouped by type.
func TestBuildCreatePDRPlan_RepeatedQERAndURRIDs(t *testing.T) {
	req := ie.NewCreatePDR(
		ie.NewPDRID(1), ie.NewPrecedence(255), validPDI(), ie.NewFARID(2),
		ie.NewQERID(10), ie.NewQERID(11),
		ie.NewURRID(20), ie.NewURRID(21),
	)

	plan, err := planTestG.BuildCreatePDRPlan(1, req)
	require.NoError(t, err)
	assert.Equal(t, []uint32{20, 21}, plan.URRIDs)

	var qerAttrs, urrAttrs int
	for _, a := range plan.Attrs {
		switch a.Type {
		case gtp5gnl.PDR_QER_ID:
			qerAttrs++
		case gtp5gnl.PDR_URR_ID:
			urrAttrs++
		}
	}
	assert.Equal(t, 2, qerAttrs)
	assert.Equal(t, 2, urrAttrs)
}

func TestBuildUpdatePDRPlan_IEValidation(t *testing.T) {
	t.Run("PDR ID alone is enough", func(t *testing.T) {
		_, err := planTestG.BuildUpdatePDRPlan(1, ie.NewUpdatePDR(ie.NewPDRID(1)))
		require.NoError(t, err)
	})

	t.Run("missing PDR ID", func(t *testing.T) {
		_, err := planTestG.BuildUpdatePDRPlan(1, ie.NewUpdatePDR(ie.NewPrecedence(255)))
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrMandatoryIEMissing))
	})

	t.Run("malformed PDI fails the update", func(t *testing.T) {
		_, err := planTestG.BuildUpdatePDRPlan(1, ie.NewUpdatePDR(ie.NewPDRID(1), malformedPDI()))
		require.Error(t, err)
		assert.False(t, errors.Is(err, ErrMandatoryIEMissing))
	})
}

// Source Interface is mandatory in the PDI, and an omitted IE must be rejected
// just like a malformed one -- otherwise the caller marks the PDR as carrying a
// valid PDI that structurally lacks a mandatory field.
func TestNewPdi_MissingSourceInterface(t *testing.T) {
	_, err := planTestG.newPdi(ie.NewPDI(ie.NewNetworkInstance("internet")))
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrMandatoryIEMissing))
}
