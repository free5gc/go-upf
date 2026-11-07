package pfcp

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

// TS 29.244 6.2.8.3: the UP function deletes the PFCP sessions of the association and the association, and answers
// with a successful cause; a peer releases its own association only.
func TestAssociationRelease(t *testing.T) {
	for _, tc := range []struct {
		name      string
		peerIP    string
		nodeID    *ie.IE
		wantCause uint8
		offending bool
		released  bool
	}{
		{"owner", "127.0.0.2", ie.NewNodeID("127.0.0.2", "", ""), ie.CauseRequestAccepted, false, true},
		{
			"node without an association", "127.0.0.2", ie.NewNodeID("127.0.0.5", "", ""),
			ie.CauseRequestAccepted, false, false,
		},
		{
			"associated peer claims other Node ID", "127.0.0.3", ie.NewNodeID("127.0.0.2", "", ""),
			ie.CauseRequestRejected, false, false,
		},
		{"missing Node ID", "127.0.0.2", nil, ie.CauseMandatoryIEMissing, true, false},
		{
			"undecodable Node ID", "127.0.0.2", ie.New(ie.NodeID, []byte{7, 1, 2, 3, 4}),
			ie.CauseMandatoryIEIncorrect, true, false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _, owner, peer := newPeerGuardFixture(t, tc.peerIP)
			existing := owner.NewSess(0x1234)
			req := message.NewAssociationReleaseRequest(1, tc.nodeID)
			msg := exchangePeerGuardRequest(t, s, peer, req)
			rsp, ok := msg.(*message.AssociationReleaseResponse)
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

			_, associated := s.rnodes[owner.ID]
			_, sessErr := s.lnode.Sess(existing.LocalID)
			if tc.released {
				require.False(t, associated, "the association is still there")
				require.Error(t, sessErr, "the session of the association is still there")
			} else {
				require.True(t, associated, "the association was deleted")
				require.NoError(t, sessErr)
			}
		})
	}
}
