package pfcp

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/free5gc/go-upf/internal/forwarder"
	"github.com/free5gc/go-upf/internal/logger"
)

func newLocalNodeForTest(t *testing.T) *LocalNode {
	t.Helper()
	return NewLocalNode(
		"upf.example.com",
		time.Time{},
		forwarder.Empty{},
		logger.PfcpLog.WithField("test", t.Name()),
	)
}

func TestLocalNodeSessions(t *testing.T) {
	t.Run("session is not found before create", func(t *testing.T) {
		node := newLocalNodeForTest(t)
		association := node.EstablishAssociation("smf1", nil)

		for i := 0; i < 3; i++ {
			_, err := node.SessionForAssociation(association, uint64(i))
			assert.Error(t, err)
		}
	})

	t.Run("create multiple sessions", func(t *testing.T) {
		node := newLocalNodeForTest(t)
		association := node.EstablishAssociation("smf1", nil)
		testcases := []struct {
			localID  uint64
			remoteID uint64
		}{
			{1, 10}, {2, 20}, {3, 30},
		}

		for _, tc := range testcases {
			sess := node.CreateSession(association, tc.remoteID)
			assert.Equal(t, tc.localID, sess.LocalID)
			assert.Equal(t, tc.remoteID, sess.RemoteID)
		}

		for _, tc := range testcases {
			sess, err := node.SessionForAssociation(association, tc.localID)
			assert.NoError(t, err)
			assert.Equal(t, tc.localID, sess.LocalID)
			assert.Equal(t, tc.remoteID, sess.RemoteID)
		}
	})

	t.Run("delete absent session has no effect", func(t *testing.T) {
		node := newLocalNodeForTest(t)
		assert.Nil(t, node.DeleteSession(0))
	})

	t.Run("delete removes store and association membership", func(t *testing.T) {
		node := newLocalNodeForTest(t)
		association := node.EstablishAssociation("smf1", nil)
		testcases := []struct {
			localID  uint64
			remoteID uint64
		}{
			{1, 10}, {2, 20}, {3, 30},
		}

		for _, tc := range testcases {
			node.CreateSession(association, tc.remoteID)
		}
		for _, tc := range testcases {
			node.DeleteSession(tc.localID)
		}

		assert.Empty(t, association.sessionIDs)
		for _, tc := range testcases {
			_, err := node.Session(tc.localID)
			assert.Error(t, err)
			_, err = node.SessionForAssociation(association, tc.localID)
			assert.Error(t, err)
			assert.Nil(t, node.DeleteSession(tc.localID))
		}
	})
}

func TestLocalNodeSessionsAcrossAssociations(t *testing.T) {
	node := newLocalNodeForTest(t)
	smf1 := node.EstablishAssociation("smf1", nil)
	smf2 := node.EstablishAssociation("smf2", nil)

	smf1Session := node.CreateSession(smf1, 10)
	smf2Session := node.CreateSession(smf2, 10)
	assert.Equal(t, uint64(1), smf1Session.LocalID)
	assert.Equal(t, uint64(2), smf2Session.LocalID)

	got, err := node.SessionForAssociation(smf1, smf1Session.LocalID)
	assert.NoError(t, err)
	assert.Same(t, smf1Session, got)

	got, err = node.SessionForAssociation(smf2, smf2Session.LocalID)
	assert.NoError(t, err)
	assert.Same(t, smf2Session, got)

	_, err = node.SessionForAssociation(smf1, smf2Session.LocalID)
	assert.Error(t, err)
	_, err = node.SessionForAssociation(smf2, smf1Session.LocalID)
	assert.Error(t, err)

	smf1SecondSession := node.CreateSession(smf1, 20)
	assert.Equal(t, uint64(3), smf1SecondSession.LocalID)
	_, err = node.SessionForAssociation(smf2, smf1SecondSession.LocalID)
	assert.Error(t, err)

	node.DeleteAssociation("smf1")

	_, ok := node.Association("smf1")
	assert.False(t, ok)
	_, err = node.Session(smf1Session.LocalID)
	assert.Error(t, err)
	_, err = node.Session(smf1SecondSession.LocalID)
	assert.Error(t, err)

	got, err = node.SessionForAssociation(smf2, smf2Session.LocalID)
	assert.NoError(t, err)
	assert.Same(t, smf2Session, got)
}

func TestLocalNodeFindSessionByRemoteSEID(t *testing.T) {
	addr := &net.UDPAddr{IP: net.IPv4(10, 100, 200, 5), Port: 8805}
	node := newLocalNodeForTest(t)
	association := node.EstablishAssociation("smf1", addr)
	deletedSess := node.CreateSession(association, 0x1efcd)
	activeSess := node.CreateSession(association, 0x1efce)
	node.DeleteSession(deletedSess.LocalID)

	sess, err := node.FindSessionByRemoteSEID(activeSess.RemoteID, addr)
	assert.NoError(t, err)
	assert.Equal(t, activeSess.LocalID, sess.LocalID)

	_, err = node.FindSessionByRemoteSEID(deletedSess.RemoteID, addr)
	assert.Error(t, err)
}
