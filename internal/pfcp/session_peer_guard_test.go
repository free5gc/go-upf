package pfcp

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"

	"github.com/free5gc/go-upf/internal/forwarder"
	"github.com/free5gc/go-upf/internal/rules"
	"github.com/free5gc/go-upf/pkg/factory"
)

type peerGuardDriver struct {
	forwarder.SessionDatapath
	establishments int
	deletions      int
}

func (d *peerGuardDriver) Establish(*rules.RuleChangeSet) (*forwarder.ApplyResult, error) {
	d.establishments++
	return &forwarder.ApplyResult{}, nil
}

func (d *peerGuardDriver) Cleanup(changes *rules.RuleChangeSet) (*forwarder.ApplyResult, error) {
	d.deletions++
	return removedRules(changes), nil
}

func newPeerGuardFixture(t *testing.T, peerIP string) (*PfcpServer, *peerGuardDriver, *PFCPAssociation, *net.UDPConn) {
	t.Helper()
	d := &peerGuardDriver{}
	s := NewPfcpServer(&factory.Config{Pfcp: &factory.Pfcp{
		Addr: "127.0.0.1", NodeID: "127.0.0.1", RetransTimeout: time.Minute,
	}}, forwarder.Empty{})
	s.dispatcher.node.newDatapath = func(uint64) forwarder.SessionDatapath { return d }
	var err error
	s.conn, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.conn.Close()) })
	t.Cleanup(s.stopTrTimers)
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(peerIP)})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, peer.Close()) })
	owner := s.dispatcher.node.EstablishAssociation("127.0.0.2", &net.UDPAddr{IP: net.ParseIP("127.0.0.2"), Port: 8805})
	s.dispatcher.node.EstablishAssociation("127.0.0.3", &net.UDPAddr{IP: net.ParseIP("127.0.0.3"), Port: 8805})
	return s, d, owner, peer
}

func exchangePeerGuardRequest(t *testing.T, s *PfcpServer, peer *net.UDPConn, req message.Message) message.Message {
	t.Helper()
	addr := peer.LocalAddr()
	rx := NewRxTransaction(s, addr, req.Sequence())
	s.rxTrans[rx.id] = rx
	requestBytes := make([]byte, req.MarshalLen())
	require.NoError(t, req.MarshalTo(requestBytes))
	parsed, err := message.Parse(requestBytes)
	require.NoError(t, err)
	require.NoError(t, s.dispatcher.HandleRequest(parsed, addr))
	require.NoError(t, peer.SetReadDeadline(time.Now().Add(time.Second)))
	buf := make([]byte, 4096)
	n, _, err := peer.ReadFromUDP(buf)
	require.NoError(t, err)
	rsp, err := message.Parse(buf[:n])
	require.NoError(t, err)
	return rsp
}

func TestSessionEstablishmentPeerGuard(t *testing.T) {
	for _, tc := range []struct {
		name         string
		peerIP       string
		nodeID       string
		omitFSEID    bool
		invalidFSEID bool
		wantCause    uint8
	}{
		{"owner with another source port", "127.0.0.2", "127.0.0.2", false, false, ie.CauseRequestAccepted},
		{"second association creates own session", "127.0.0.3", "127.0.0.3", false, false, ie.CauseRequestAccepted},
		{"associated peer claims other Node ID", "127.0.0.3", "127.0.0.2", false, false, ie.CauseRequestRejected},
		{
			"unassociated peer claims owner Node ID", "127.0.0.4", "127.0.0.2",
			false, false, ie.CauseNoEstablishedPFCPAssociation,
		},
		{
			"associated peer claims unknown Node ID", "127.0.0.2", "127.0.0.5",
			false, false, ie.CauseNoEstablishedPFCPAssociation,
		},
		{"unassociated peer missing CP F-SEID", "127.0.0.4", "127.0.0.2", true, false, ie.CauseNoEstablishedPFCPAssociation},
		{"unassociated peer invalid CP F-SEID", "127.0.0.4", "127.0.0.2", false, true, ie.CauseNoEstablishedPFCPAssociation},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, d, owner, peer := newPeerGuardFixture(t, tc.peerIP)
			existing := s.dispatcher.node.CreateSession(owner, 0x1234)
			ies := []*ie.IE{ie.NewNodeID(tc.nodeID, "", "")}
			if tc.invalidFSEID {
				ies = append(ies, ie.New(ie.FSEID, nil))
			} else if !tc.omitFSEID {
				ies = append(ies, ie.NewFSEID(0x4321, net.ParseIP(tc.peerIP), nil))
			}
			req := message.NewSessionEstablishmentRequest(0, 0, 0, 1, 0, ies...)
			msg := exchangePeerGuardRequest(t, s, peer, req)
			rsp, ok := msg.(*message.SessionEstablishmentResponse)
			require.True(t, ok)
			require.NotNil(t, rsp.Cause)
			cause, err := rsp.Cause.Cause()
			require.NoError(t, err)
			t.Logf("cause=%d session_count=%d establishment_calls=%d",
				cause, len(s.dispatcher.node.sessions.sessions), d.establishments)
			require.Equal(t, tc.wantCause, cause)
			// Node ID is mandatory in all Establishment Responses (TS 29.244 Table 7.5.3.1-1).
			require.NotNil(t, rsp.NodeID)
			nodeID, err := rsp.NodeID.NodeID()
			require.NoError(t, err)
			require.Equal(t, "127.0.0.1", nodeID)
			require.Nil(t, rsp.OffendingIE)
			require.Empty(t, rsp.IEs)
			if tc.omitFSEID || tc.invalidFSEID {
				require.Zero(t, rsp.SEID())
			} else {
				require.Equal(t, uint64(0x4321), rsp.SEID())
			}
			if tc.wantCause == ie.CauseRequestAccepted {
				require.Equal(t, 1, d.establishments)
				require.Len(t, s.dispatcher.node.sessions.sessions, 2)
				require.NotNil(t, rsp.UPFSEID)
			} else {
				require.Zero(t, d.establishments)
				require.Len(t, s.dispatcher.node.sessions.sessions, 1)
				require.Nil(t, rsp.UPFSEID)
			}
			got, err := s.dispatcher.node.Session(existing.LocalID)
			require.NoError(t, err)
			require.Same(t, existing, got)
		})
	}
}

func TestSessionDeletionPeerGuard(t *testing.T) {
	for _, tc := range []struct {
		name       string
		peerIP     string
		unknown    bool
		staleOwner bool
		wantCause  uint8
	}{
		{"owner with another source port", "127.0.0.2", false, false, ie.CauseRequestAccepted},
		{"other associated peer", "127.0.0.3", false, false, ie.CauseRequestRejected},
		{"unassociated peer", "127.0.0.4", false, false, ie.CauseNoEstablishedPFCPAssociation},
		{"unassociated peer with unknown session", "127.0.0.4", true, false, ie.CauseNoEstablishedPFCPAssociation},
		{"associated peer with unknown session", "127.0.0.2", true, false, ie.CauseSessionContextNotFound},
		{"stale association", "127.0.0.2", false, true, ie.CauseRequestRejected},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, d, owner, peer := newPeerGuardFixture(t, tc.peerIP)
			sess := s.dispatcher.node.CreateSession(owner, 0x1234)
			sibling := s.dispatcher.node.CreateSession(owner, 0x5678)
			sess.FARIDs[7] = &rules.FARConfig{FARID: 7}
			if tc.staleOwner {
				s.dispatcher.node.associations[owner.PeerNodeID] = newPFCPAssociation(owner.PeerNodeID, owner.peerAddr, owner.log)
			}
			target := sess.LocalID
			if tc.unknown {
				target += 1000
			}
			req := message.NewSessionDeletionRequest(0, 0, target, 1, 0)
			msg := exchangePeerGuardRequest(t, s, peer, req)
			rsp, ok := msg.(*message.SessionDeletionResponse)
			require.True(t, ok)
			require.NotNil(t, rsp.Cause)
			cause, err := rsp.Cause.Cause()
			require.NoError(t, err)
			_, sessionErr := s.dispatcher.node.Session(sess.LocalID)
			t.Logf("cause=%d session_exists=%t deletion_calls=%d", cause, sessionErr == nil, d.deletions)
			require.Equal(t, tc.wantCause, cause)
			require.Nil(t, rsp.OffendingIE)
			require.Empty(t, rsp.IEs)
			if tc.wantCause == ie.CauseRequestAccepted {
				require.Equal(t, 1, d.deletions)
				_, lookupErr := s.dispatcher.node.Session(sess.LocalID)
				require.Error(t, lookupErr)
				require.Len(t, owner.sessionIDs, 1)
				require.Equal(t, sess.RemoteID, rsp.SEID())
			} else {
				require.Zero(t, d.deletions)
				got, lookupErr := s.dispatcher.node.Session(sess.LocalID)
				require.NoError(t, lookupErr)
				require.Same(t, sess, got)
				require.Contains(t, sess.FARIDs, uint32(7))
				require.Len(t, owner.sessionIDs, 2)
				require.Zero(t, rsp.SEID())
			}
			got, err := s.dispatcher.node.Session(sibling.LocalID)
			require.NoError(t, err)
			require.Same(t, sibling, got)
		})
	}
}
