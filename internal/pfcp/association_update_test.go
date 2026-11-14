package pfcp

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

// TS 29.244 6.2.7.2.2: the UP function answers a PFCP Association Update Request with a successful cause, or with an
// error cause if the Node ID is not known; a peer updates its own association only.
func TestAssociationUpdate(t *testing.T) {
	for _, tc := range []struct {
		name      string
		peerIP    string
		nodeID    *ie.IE
		wantCause uint8
		offending bool
	}{
		{"owner", "127.0.0.2", ie.NewNodeID("127.0.0.2", "", ""), ie.CauseRequestAccepted, false},
		{
			"node without an association", "127.0.0.5", ie.NewNodeID("127.0.0.5", "", ""),
			ie.CauseNoEstablishedPFCPAssociation, false,
		},
		{
			"associated peer claims other Node ID", "127.0.0.3", ie.NewNodeID("127.0.0.2", "", ""),
			ie.CauseRequestRejected, false,
		},
		{"missing Node ID", "127.0.0.2", nil, ie.CauseMandatoryIEMissing, true},
		{
			"undecodable Node ID", "127.0.0.2", ie.New(ie.NodeID, []byte{7, 1, 2, 3, 4}),
			ie.CauseMandatoryIEIncorrect, true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _, owner, peer := newPeerGuardFixture(t, tc.peerIP)
			existing := owner.NewSess(0x1234)
			req := message.NewAssociationUpdateRequest(1)
			req.NodeID = tc.nodeID
			msg := exchangePeerGuardRequest(t, s, peer, req)
			rsp, ok := msg.(*message.AssociationUpdateResponse)
			require.True(t, ok, "answered %T", msg)
			require.NotNil(t, rsp.Cause)
			cause, err := rsp.Cause.Cause()
			require.NoError(t, err)
			require.Equal(t, tc.wantCause, cause)
			require.NotNil(t, rsp.NodeID)
			if tc.offending {
				require.Len(t, rsp.IEs, 1)
				require.Equal(t, ie.OffendingIE, rsp.IEs[0].Type)
				offending, err := rsp.IEs[0].OffendingIE()
				require.NoError(t, err)
				require.Equal(t, ie.NodeID, offending)
			} else {
				require.Empty(t, rsp.IEs)
			}

			// The association and its sessions stay, whatever the answer.
			_, associated := s.rnodes[owner.ID]
			require.True(t, associated, "the association was deleted")
			_, sessErr := s.lnode.Sess(existing.LocalID)
			require.NoError(t, sessErr)
		})
	}
}
