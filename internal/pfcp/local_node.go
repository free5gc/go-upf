package pfcp

import (
	"fmt"
	"net"
	"time"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/free5gc/go-upf/internal/forwarder"
	"github.com/free5gc/go-upf/internal/report"
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

	association := newPFCPAssociation(
		peerNodeID,
		peerAddr,
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
	n.deleteAssociationSessions(association)
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

// Session returns a session from the UPF-wide Local SEID namespace.
func (n *LocalNode) Session(localSEID uint64) (*Session, error) {
	return n.sessions.Get(localSEID)
}

// SessionForAssociation returns a session only when it belongs to the association.
func (n *LocalNode) SessionForAssociation(
	association *PFCPAssociation,
	localSEID uint64,
) (*Session, error) {
	if association == nil {
		return nil, errors.New("LocalNode.SessionForAssociation: nil association")
	}
	if _, ok := association.sessionIDs[localSEID]; !ok {
		return nil, errors.Errorf(
			"LocalNode.SessionForAssociation: session not found (localSEID:%#x)",
			localSEID,
		)
	}
	return n.Session(localSEID)
}

// FindSessionByRemoteSEID finds a session using the peer address and CP-side SEID.
func (n *LocalNode) FindSessionByRemoteSEID(
	remoteSEID uint64,
	peerAddr net.Addr,
) (*Session, error) {
	return n.sessions.FindByRemoteSEID(remoteSEID, peerAddr)
}

// CreateSession allocates a Local SEID and associates the session with its PFCP peer.
func (n *LocalNode) CreateSession(
	association *PFCPAssociation,
	remoteSEID uint64,
) *Session {
	sess := n.sessions.Create(remoteSEID, BUFFQ_LEN, n.datapath)
	association.sessionIDs[sess.LocalID] = struct{}{}
	sess.association = association
	sess.log = association.log.WithFields(
		logrus.Fields{
			logger_util.FieldUserPlaneSEID:    fmt.Sprintf("%#x", sess.LocalID),
			logger_util.FieldControlPlaneSEID: fmt.Sprintf("%#x", remoteSEID),
		})
	sess.log.Infoln("New session")
	return sess
}

// DeleteSession removes a session from both its association and the Local SEID store.
// Deleting an unknown Local SEID is an idempotent no-op.
func (n *LocalNode) DeleteSession(localSEID uint64) []report.USAReport {
	sess, err := n.sessions.Get(localSEID)
	if err != nil {
		return nil
	}

	reports, err := n.sessions.Delete(localSEID)
	if err != nil {
		n.log.Warnln(err)
		return nil
	}
	if sess.association != nil {
		delete(sess.association.sessionIDs, localSEID)
	}
	return reports
}

func (n *LocalNode) deleteAssociationSessions(association *PFCPAssociation) {
	for localSEID := range association.sessionIDs {
		n.DeleteSession(localSEID)
	}
	association.sessionIDs = make(map[uint64]struct{})
}
