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

type authorizationDriver struct {
	forwarder.SessionDatapath
	modifications []*rules.RuleChangeSet
}

func (d *authorizationDriver) Modify(c *rules.RuleChangeSet) (*forwarder.ApplyResult, error) {
	d.modifications = append(d.modifications, c)
	return &forwarder.ApplyResult{}, nil
}

func TestSessionModificationAuthorization(t *testing.T) {
	for _, tc := range []struct {
		name           string
		peerIP         string
		nodeID         *ie.IE
		staleOwner     bool
		unknownSession bool
		wantCause      uint8
	}{
		{name: "owner", peerIP: "127.0.0.2", wantCause: ie.CauseRequestAccepted},
		{
			name: "owner with matching Node ID", peerIP: "127.0.0.2",
			nodeID: ie.NewNodeID("127.0.0.2", "", ""), wantCause: ie.CauseRequestAccepted,
		},
		{name: "other associated peer", peerIP: "127.0.0.3", wantCause: ie.CauseRequestRejected},
		{name: "unassociated peer", peerIP: "127.0.0.4", wantCause: ie.CauseNoEstablishedPFCPAssociation},
		{
			name: "unassociated peer claiming owner Node ID", peerIP: "127.0.0.4",
			nodeID: ie.NewNodeID("127.0.0.2", "", ""), wantCause: ie.CauseNoEstablishedPFCPAssociation,
		},
		{
			name: "unassociated peer with unknown session", peerIP: "127.0.0.4", unknownSession: true,
			wantCause: ie.CauseNoEstablishedPFCPAssociation,
		},
		{
			name: "associated peer with unknown session", peerIP: "127.0.0.2", unknownSession: true,
			wantCause: ie.CauseSessionContextNotFound,
		},
		{
			name: "other peer claiming owner Node ID", peerIP: "127.0.0.3",
			nodeID: ie.NewNodeID("127.0.0.2", "", ""), wantCause: ie.CauseRequestRejected,
		},
		{
			name: "unverified takeover", peerIP: "127.0.0.3",
			nodeID: ie.NewNodeID("127.0.0.3", "", ""), wantCause: ie.CauseRequestRejected,
		},
		{
			name: "owner cannot overwrite another association", peerIP: "127.0.0.2",
			nodeID: ie.NewNodeID("127.0.0.3", "", ""), wantCause: ie.CauseRequestRejected,
		},
		{
			name: "malformed Node ID", peerIP: "127.0.0.2",
			nodeID: ie.New(ie.NodeID, nil), wantCause: ie.CauseMandatoryIEIncorrect,
		},
		{
			name: "empty FQDN Node ID", peerIP: "127.0.0.2",
			nodeID: ie.New(ie.NodeID, []byte{ie.NodeIDFQDN, 0}), wantCause: ie.CauseMandatoryIEIncorrect,
		},
		{
			name: "stale association", peerIP: "127.0.0.2", staleOwner: true,
			wantCause: ie.CauseRequestRejected,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			driver := &authorizationDriver{}
			cfg := &factory.Config{Pfcp: &factory.Pfcp{RetransTimeout: time.Minute}}
			s := NewPfcpServer(cfg, forwarder.Empty{})
			s.dispatcher.node.newDatapath = func(uint64) forwarder.SessionDatapath { return driver }
			var err error
			s.conn, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, s.conn.Close()) })
			t.Cleanup(s.stopTrTimers)
			peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(tc.peerIP)})
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, peer.Close()) })
			addr := peer.LocalAddr()
			// Association signalling and session requests may use different
			// source ports on the same peer IP (TS 29.244 clause 4.2.2).
			ownerAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.2"), Port: 8805}
			owner := s.dispatcher.node.EstablishAssociation("127.0.0.2", ownerAddr)
			other := s.dispatcher.node.EstablishAssociation("127.0.0.3", &net.UDPAddr{IP: net.ParseIP("127.0.0.3"), Port: 8805})
			sess := s.dispatcher.node.CreateSession(owner, 0x1234)
			sibling := s.dispatcher.node.CreateSession(owner, 0x5678)
			sess.FARIDs[7] = &rules.FARConfig{FARID: 7}
			if tc.staleOwner {
				s.dispatcher.node.associations[owner.PeerNodeID] = newPFCPAssociation(owner.PeerNodeID, ownerAddr, owner.log)
			}
			registeredOwner := s.dispatcher.node.associations[owner.PeerNodeID]
			req := message.NewSessionModificationRequest(0, 0, sess.LocalID, 1, 0,
				ie.NewUpdateFAR(ie.NewFARID(7), ie.NewApplyAction(2)))
			if tc.unknownSession {
				req.Header.SEID += 1000
			}
			if tc.nodeID != nil {
				req.NodeID = tc.nodeID
			}
			rx := NewRxTransaction(s, addr, req.Sequence())
			s.rxTrans[rx.id] = rx
			require.NoError(t, s.dispatcher.HandleRequest(req, addr))
			require.NoError(t, peer.SetReadDeadline(time.Now().Add(time.Second)))
			buf := make([]byte, 4096)
			n, _, err := peer.ReadFromUDP(buf)
			require.NoError(t, err)
			msg, err := message.Parse(buf[:n])
			require.NoError(t, err)
			rsp, ok := msg.(*message.SessionModificationResponse)
			require.True(t, ok)
			require.NotNil(t, rsp.Cause)
			cause, err := rsp.Cause.Cause()
			require.NoError(t, err)
			require.Equal(t, tc.wantCause, cause)
			if tc.wantCause == ie.CauseMandatoryIEIncorrect {
				require.NotNil(t, rsp.OffendingIE, "TS 29.244 Table 7.5.5.1-1 requires the faulty IE type")
				offending, err := rsp.OffendingIE.OffendingIE()
				require.NoError(t, err)
				require.Equal(t, ie.NodeID, offending)
			} else {
				require.Nil(t, rsp.OffendingIE)
			}
			if tc.peerIP != "127.0.0.2" || tc.staleOwner || tc.unknownSession {
				require.Zero(t, rsp.SEID(), "do not disclose the owner's remote SEID to another peer")
			} else {
				require.Equal(t, sess.RemoteID, rsp.SEID())
			}
			if tc.wantCause == ie.CauseRequestAccepted {
				require.Len(t, driver.modifications, 1)
				require.Len(t, driver.modifications[0].UpdateFARs, 1)
				require.Equal(t, uint32(7), driver.modifications[0].UpdateFARs[0].FARID)
			} else {
				require.Empty(t, driver.modifications)
			}
			// A rejected request must not rename a shared owner, overwrite
			// another association, or change any session's ownership.
			require.Equal(t, "127.0.0.2", owner.PeerNodeID)
			require.Same(t, registeredOwner, s.dispatcher.node.associations["127.0.0.2"])
			require.Same(t, other, s.dispatcher.node.associations["127.0.0.3"])
			require.Len(t, s.dispatcher.node.associations, 2)
			require.Same(t, owner, sess.association)
			require.Same(t, owner, sibling.association)
			require.Equal(t, uint64(0x1234), sess.RemoteID)
			require.Len(t, owner.sessionIDs, 2)
		})
	}
}
