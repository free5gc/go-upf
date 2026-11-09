package pfcp

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

// TS 29.244 7.5.3.1: a rejection due to a mandatory IE missing or faulty
// names the IE in the Offending IE.
func TestSessionEstablishmentOffendingIE(t *testing.T) {
	nodeID := ie.NewNodeID("127.0.0.2", "", "")
	fseid := ie.NewFSEID(0x4321, net.ParseIP("127.0.0.2"), nil)
	emptyFQDN := ie.New(ie.NodeID, []byte{ie.NodeIDFQDN, 0})
	for _, tc := range []struct {
		name         string
		ies          []*ie.IE
		wantCause    uint8
		wantOffender uint16
	}{
		{"missing Node ID", []*ie.IE{fseid}, ie.CauseMandatoryIEMissing, ie.NodeID},
		{"faulty Node ID", []*ie.IE{ie.New(ie.NodeID, nil), fseid}, ie.CauseMandatoryIEIncorrect, ie.NodeID},
		{"empty FQDN Node ID", []*ie.IE{emptyFQDN, fseid}, ie.CauseMandatoryIEIncorrect, ie.NodeID},
		{"missing CP F-SEID", []*ie.IE{nodeID}, ie.CauseMandatoryIEMissing, ie.FSEID},
		{"faulty CP F-SEID", []*ie.IE{nodeID, ie.New(ie.FSEID, nil)}, ie.CauseMandatoryIEIncorrect, ie.FSEID},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _, _, peer := newPeerGuardFixture(t, "127.0.0.2")
			req := message.NewSessionEstablishmentRequest(0, 0, 0, 1, 0, tc.ies...)
			rsp, ok := exchangePeerGuardRequest(t, s, peer, req).(*message.SessionEstablishmentResponse)
			require.True(t, ok)
			require.NotNil(t, rsp.NodeID)
			cause, err := rsp.Cause.Cause()
			require.NoError(t, err)
			require.Equal(t, tc.wantCause, cause)
			require.NotNil(t, rsp.OffendingIE)
			offender, err := rsp.OffendingIE.OffendingIE()
			require.NoError(t, err)
			require.Equal(t, tc.wantOffender, offender)
		})
	}
}
