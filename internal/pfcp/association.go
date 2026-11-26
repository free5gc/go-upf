package pfcp

import (
	"net"

	"github.com/sirupsen/logrus"
)

// PFCPAssociation stores remote PFCP peer state and the Local SEIDs
// established through that association. Kernel-applied rule state remains owned by Session.
type PFCPAssociation struct {
	PeerNodeID string
	peerAddr   net.Addr
	sessionIDs map[uint64]struct{} // key: Local SEID
	log        *logrus.Entry
}

func newPFCPAssociation(
	peerNodeID string,
	peerAddr net.Addr,
	log *logrus.Entry,
) *PFCPAssociation {
	return &PFCPAssociation{
		PeerNodeID: peerNodeID,
		peerAddr:   peerAddr,
		sessionIDs: make(map[uint64]struct{}),
		log:        log,
	}
}

func (n *PFCPAssociation) matchesPeer(addr net.Addr) bool {
	if n == nil {
		return false
	}
	peer, ok := addr.(*net.UDPAddr)
	if !ok || peer == nil || len(peer.IP) == 0 {
		return false
	}
	bound, ok := n.peerAddr.(*net.UDPAddr)
	return ok && bound != nil && len(bound.IP) != 0 && bound.IP.Equal(peer.IP) && bound.Zone == peer.Zone
}
