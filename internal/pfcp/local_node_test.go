package pfcp

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/free5gc/go-upf/internal/forwarder"
	"github.com/free5gc/go-upf/internal/logger"
)

func TestNewLocalNode(t *testing.T) {
	recoveryTime := time.Unix(1_700_000_000, 0)
	datapath := forwarder.Empty{}
	log := logger.PfcpLog.WithField("test", t.Name())

	node := NewLocalNode("upf.example.com", recoveryTime, datapath, log)

	assert.Equal(t, "upf.example.com", node.NodeID)
	assert.Equal(t, recoveryTime, node.RecoveryTime)
	assert.NotNil(t, node.associations)
	assert.Empty(t, node.associations)
	assert.NotNil(t, node.sessions)
	assert.Equal(t, datapath, node.datapath)
	assert.Same(t, log, node.log)
}

func TestNewLocalNodeOwnsIndependentState(t *testing.T) {
	log := logger.PfcpLog.WithField("test", t.Name())

	first := NewLocalNode("upf-1.example.com", time.Time{}, forwarder.Empty{}, log)
	second := NewLocalNode("upf-2.example.com", time.Time{}, forwarder.Empty{}, log)

	first.associations["smf.example.com"] = &PFCPAssociation{}
	first.sessions.sessions = append(first.sessions.sessions, &Session{})

	assert.Empty(t, second.associations)
	assert.Empty(t, second.sessions.sessions)
}

func TestLocalNodeAssociationLifecycle(t *testing.T) {
	log := logger.PfcpLog.WithField("test", t.Name())
	node := NewLocalNode("upf.example.com", time.Time{}, forwarder.Empty{}, log)
	peerNodeID := "smf.example.com"
	peerAddr := &net.UDPAddr{IP: net.IPv4(10, 100, 200, 5), Port: 8805}

	_, ok := node.Association(peerNodeID)
	assert.False(t, ok)

	association := node.EstablishAssociation(peerNodeID, peerAddr)
	got, ok := node.Association(peerNodeID)
	assert.True(t, ok)
	assert.Same(t, association, got)
	assert.Equal(t, peerAddr, association.peerAddr)

	session := node.CreateSession(association, 0x10)
	replacement := node.EstablishAssociation(peerNodeID, peerAddr)

	assert.NotSame(t, association, replacement)
	assert.Empty(t, association.sessionIDs)
	_, err := node.Session(session.LocalID)
	assert.Error(t, err)

	got, ok = node.Association(peerNodeID)
	assert.True(t, ok)
	assert.Same(t, replacement, got)

	node.DeleteAssociation(peerNodeID)
	_, ok = node.Association(peerNodeID)
	assert.False(t, ok)

	// Deleting an association that is already absent is intentionally idempotent.
	node.DeleteAssociation(peerNodeID)
}

func TestLocalNodeUpdateAssociationPeerNodeID(t *testing.T) {
	log := logger.PfcpLog.WithField("test", t.Name())
	node := NewLocalNode("upf.example.com", time.Time{}, forwarder.Empty{}, log)
	association := node.EstablishAssociation("smf-old.example.com", nil)

	node.UpdateAssociationPeerNodeID(association, "smf-new.example.com")

	_, ok := node.Association("smf-old.example.com")
	assert.False(t, ok)

	got, ok := node.Association("smf-new.example.com")
	assert.True(t, ok)
	assert.Same(t, association, got)
	assert.Equal(t, "smf-new.example.com", association.PeerNodeID)
}
