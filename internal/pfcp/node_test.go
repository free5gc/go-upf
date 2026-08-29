package pfcp

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/free5gc/go-upf/internal/forwarder"
	"github.com/free5gc/go-upf/internal/logger"
	logger_util "github.com/free5gc/util/logger"
)

func TestPFCPAssociation(t *testing.T) {
	t.Run("sess is not found before create", func(t *testing.T) {
		n := NewPFCPAssociation(
			"smf1",
			nil,
			&LocalNode{},
			logger.PfcpLog.WithField(logger_util.FieldControlPlaneNodeID, "smf1"),
		)
		for i := 0; i < 3; i++ {
			_, err := n.Session(uint64(i))
			assert.NotNil(t, err)
		}
	})

	t.Run("new multiple session", func(t *testing.T) {
		n := NewPFCPAssociation(
			"smf1",
			nil,
			&LocalNode{},
			logger.PfcpLog.WithField(logger_util.FieldControlPlaneNodeID, "smf1"),
		)

		testcases := []struct {
			localID  uint64
			remoteID uint64
		}{
			{1, 10}, {2, 20}, {3, 30},
		}

		for _, tc := range testcases {
			sess := n.NewSession(tc.remoteID, forwarder.Empty{})
			assert.Equal(t, tc.localID, sess.LocalID)
			assert.Equal(t, tc.remoteID, sess.RemoteID)
		}

		// assure the session is registered with the association
		for _, tc := range testcases {
			sess, err := n.Session(tc.localID)
			assert.Nil(t, err)
			assert.Equal(t, tc.localID, sess.LocalID)
			assert.Equal(t, tc.remoteID, sess.RemoteID)
		}
	})

	t.Run("delete 0 no effect before create", func(t *testing.T) {
		n := NewPFCPAssociation(
			"smf1",
			nil,
			&LocalNode{},
			logger.PfcpLog.WithField(logger_util.FieldControlPlaneNodeID, "smf1"),
		)
		report := n.DeleteSession(0)
		assert.Nil(t, report)
	})
	t.Run("delete should success after create", func(t *testing.T) {
		n := NewPFCPAssociation(
			"smf1",
			nil,
			&LocalNode{},
			logger.PfcpLog.WithField(logger_util.FieldControlPlaneNodeID, "smf1"),
		)

		testcases := []struct {
			localID  uint64
			remoteID uint64
		}{
			{1, 10}, {2, 20}, {3, 30},
		}

		for _, tc := range testcases {
			n.NewSession(tc.remoteID, forwarder.Empty{})
		}

		for _, tc := range testcases {
			n.DeleteSession(tc.localID)
		}

		// assure the session is deleted
		for _, tc := range testcases {
			_, err := n.Session(tc.localID)
			assert.NotNil(t, err)
		}

		// delete again should have no effect
		for _, tc := range testcases {
			report := n.DeleteSession(tc.localID)
			assert.Nil(t, report)
		}
	})
}

func TestPFCPAssociationMultipleSMFs(t *testing.T) {
	var lnode LocalNode
	n1 := NewPFCPAssociation(
		"smf1",
		nil,
		&lnode,
		logger.PfcpLog.WithField(logger_util.FieldControlPlaneNodeID, "smf1"),
	)
	n2 := NewPFCPAssociation(
		"smf2",
		nil,
		&lnode,
		logger.PfcpLog.WithField(logger_util.FieldControlPlaneNodeID, "smf2"),
	)
	t.Run("new smf1 r-SEID=10", func(t *testing.T) {
		sess := n1.NewSession(10, forwarder.Empty{})
		if sess.LocalID != 1 {
			t.Errorf("want 1; but got %v\n", sess.LocalID)
		}
		if sess.RemoteID != 10 {
			t.Errorf("want 10; but got %v\n", sess.RemoteID)
		}
	})
	t.Run("new smf2 r-SEID=10", func(t *testing.T) {
		sess := n2.NewSession(10, forwarder.Empty{})
		if sess.LocalID != 2 {
			t.Errorf("want 2; but got %v\n", sess.LocalID)
		}
		if sess.RemoteID != 10 {
			t.Errorf("want 10; but got %v\n", sess.RemoteID)
		}
	})
	t.Run("get smf1 l-SEID=1", func(t *testing.T) {
		sess, err := n1.Session(1)
		if err != nil {
			t.Fatal(err)
		}
		if sess.LocalID != 1 {
			t.Errorf("want 1; but got %v\n", sess.LocalID)
		}
		if sess.RemoteID != 10 {
			t.Errorf("want 10; but got %v\n", sess.RemoteID)
		}
	})
	t.Run("get smf2 l-SEID=2", func(t *testing.T) {
		sess, err := n2.Session(2)
		if err != nil {
			t.Fatal(err)
		}
		if sess.LocalID != 2 {
			t.Errorf("want 2; but got %v\n", sess.LocalID)
		}
		if sess.RemoteID != 10 {
			t.Errorf("want 10; but got %v\n", sess.RemoteID)
		}
	})
	t.Run("get smf1 l-SEID=2", func(t *testing.T) {
		_, err := n1.Session(2)
		if err == nil {
			t.Errorf("want error; but not error")
		}
	})
	t.Run("get smf2 l-SEID=1", func(t *testing.T) {
		_, err := n2.Session(1)
		if err == nil {
			t.Errorf("want error; but not error")
		}
	})
	t.Run("new smf1:20", func(t *testing.T) {
		sess := n1.NewSession(20, forwarder.Empty{})
		if sess.LocalID != 3 {
			t.Errorf("want 3; but got %v\n", sess.LocalID)
		}
		if sess.RemoteID != 20 {
			t.Errorf("want 20; but got %v\n", sess.RemoteID)
		}
	})
	t.Run("get smf2 l-SEID=3", func(t *testing.T) {
		_, err := n2.Session(3)
		if err == nil {
			t.Errorf("want error; but not error")
		}
	})
	t.Run("delete all smf1 association sessions", func(t *testing.T) {
		n1.DeleteAllSessions()
	})
	t.Run("get smf1 l-SEID=1", func(t *testing.T) {
		_, err := n1.Session(1)
		if err == nil {
			t.Errorf("want error; but not error")
		}
	})
	t.Run("get smf1 l-SEID=3", func(t *testing.T) {
		_, err := n1.Session(3)
		if err == nil {
			t.Errorf("want error; but not error")
		}
	})
	t.Run("get smf2 l-SEID=2", func(t *testing.T) {
		sess, err := n2.Session(2)
		if err != nil {
			t.Fatal(err)
		}
		if sess.LocalID != 2 {
			t.Errorf("want 2; but got %v\n", sess.LocalID)
		}
		if sess.RemoteID != 10 {
			t.Errorf("want 10; but got %v\n", sess.RemoteID)
		}
	})
}

func TestLocalNode(t *testing.T) {
	t.Run("new session", func(t *testing.T) {
		lnode := LocalNode{}
		sess := lnode.NewSess(10, BUFFQ_LEN, forwarder.Empty{})
		assert.Equal(t, uint64(1), sess.LocalID)
		assert.Equal(t, uint64(10), sess.RemoteID)
	})

	t.Run("recycle LocalID", func(t *testing.T) {
		lnode := LocalNode{
			sess: []*Sess{},
			free: []uint64{},
		}
		sess := lnode.NewSess(10, BUFFQ_LEN, forwarder.Empty{})
		recycleLocalID := 1
		assert.Equal(t, uint64(recycleLocalID), sess.LocalID)
		assert.Equal(t, uint64(10), sess.RemoteID)
	})

	t.Run("remote sess skips deleted local slots", func(t *testing.T) {
		addr := &net.UDPAddr{IP: net.IPv4(10, 100, 200, 5), Port: 8805}
		lnode := &LocalNode{}
		association := NewPFCPAssociation(
			"smf1",
			addr,
			lnode,
			logger.PfcpLog.WithField(logger_util.FieldControlPlaneNodeID, "smf1"),
		)

		deletedSess := association.NewSession(0x1efcd, forwarder.Empty{})
		activeSess := association.NewSession(0x1efce, forwarder.Empty{})
		association.DeleteSession(deletedSess.LocalID)

		sess, err := lnode.RemoteSess(activeSess.RemoteID, addr)
		assert.NoError(t, err)
		assert.Equal(t, activeSess.LocalID, sess.LocalID)

		_, err = lnode.RemoteSess(deletedSess.RemoteID, addr)
		assert.Error(t, err)
	})
}
