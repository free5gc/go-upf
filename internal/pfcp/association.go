package pfcp

import (
	"net"

	"github.com/sirupsen/logrus"
)

// PFCPAssociation stores remote PFCP peer state and the Local SEIDs
// established through that association. Rule desired state remains owned by Session.
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
