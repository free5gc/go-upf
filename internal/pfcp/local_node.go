package pfcp

import (
	"net"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/free5gc/go-upf/internal/forwarder"
	logger_util "github.com/free5gc/util/logger"
)

// LocalNode owns state and local dependencies that belong to this UP function,
// rather than to the PFCP transport or a single remote association.
type LocalNode struct {
	NodeID       string
	RecoveryTime time.Time

	associations map[string]*PFCPAssociation // key: peer Node ID
	sessions     *SessionStore

	datapath forwarder.Driver
	log      *logrus.Entry
}

func NewLocalNode(
	nodeID string,
	recoveryTime time.Time,
	datapath forwarder.Driver,
	log *logrus.Entry,
) *LocalNode {
	return &LocalNode{
		NodeID:       nodeID,
		RecoveryTime: recoveryTime,
		associations: make(map[string]*PFCPAssociation),
		sessions:     &SessionStore{},
		datapath:     datapath,
		log:          log,
	}
}

// Association returns the established association for a peer Node ID.
func (n *LocalNode) Association(peerNodeID string) (*PFCPAssociation, bool) {
	association, ok := n.associations[peerNodeID]
	return association, ok
}

// EstablishAssociation replaces any existing association for the peer.
// Replacing an association also removes every PFCP session owned by the old one.
func (n *LocalNode) EstablishAssociation(
	peerNodeID string,
	peerAddr net.Addr,
) *PFCPAssociation {
	n.DeleteAssociation(peerNodeID)

	association := NewPFCPAssociation(
		peerNodeID,
		peerAddr,
		n.sessions,
		n.log.WithField(logger_util.FieldControlPlaneNodeID, peerNodeID),
	)
	n.associations[peerNodeID] = association
	association.log.Infoln("New PFCP association")
	return association
}

// DeleteAssociation removes an association and all sessions established through it.
func (n *LocalNode) DeleteAssociation(peerNodeID string) {
	association, ok := n.associations[peerNodeID]
	if !ok {
		return
	}

	n.log.Infof("delete association: %#+v\n", association)
	association.DeleteAllSessions()
	delete(n.associations, peerNodeID)
}

// UpdateAssociationPeerNodeID rekeys an association after an SMF takeover.
func (n *LocalNode) UpdateAssociationPeerNodeID(
	association *PFCPAssociation,
	newPeerNodeID string,
) {
	n.log.Infof(
		"Update peer Node ID %q to %q",
		association.PeerNodeID,
		newPeerNodeID,
	)
	delete(n.associations, association.PeerNodeID)
	association.PeerNodeID = newPeerNodeID
	association.log = n.log.WithField(
		logger_util.FieldControlPlaneNodeID,
		newPeerNodeID,
	)
	n.associations[newPeerNodeID] = association
}
