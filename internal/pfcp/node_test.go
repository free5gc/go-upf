package pfcp

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/free5gc/go-upf/internal/forwarder"
	"github.com/free5gc/go-upf/internal/logger"
	logger_util "github.com/free5gc/util/logger"
)

func TestRemoteNode(t *testing.T) {
	t.Run("sess is not found before create", func(t *testing.T) {
		n := NewRemoteNode(
			"smf1",
			nil,
			&LocalNode{},
			forwarder.Empty{},
			logger.PfcpLog.WithField(logger_util.FieldControlPlaneNodeID, "smf1"),
		)
		for i := 0; i < 3; i++ {
			_, err := n.Sess(uint64(i))
			assert.NotNil(t, err)
		}
	})

	t.Run("new multiple session", func(t *testing.T) {
		n := NewRemoteNode(
			"smf1",
			nil,
			&LocalNode{},
			forwarder.Empty{},
			logger.PfcpLog.WithField(logger_util.FieldControlPlaneNodeID, "smf1"),
		)

		testcases := []struct {
			localID  uint64
			remoteID uint64
		}{
			{1, 10}, {2, 20}, {3, 30},
		}

		for _, tc := range testcases {
			sess := n.NewSess(tc.remoteID)
			assert.Equal(t, tc.localID, sess.LocalID)
			assert.Equal(t, tc.remoteID, sess.RemoteID)
		}

		// assure the session stored in the node
		for _, tc := range testcases {
			sess, err := n.Sess(tc.localID)
			assert.Nil(t, err)
			assert.Equal(t, tc.localID, sess.LocalID)
			assert.Equal(t, tc.remoteID, sess.RemoteID)
		}
	})

	t.Run("delete 0 no effect before create", func(t *testing.T) {
		n := NewRemoteNode(
			"smf1",
			nil,
			&LocalNode{},
			forwarder.Empty{},
			logger.PfcpLog.WithField(logger_util.FieldControlPlaneNodeID, "smf1"),
		)
		report := n.DeleteSess(0)
		assert.Nil(t, report)
	})
	t.Run("delete should success after create", func(t *testing.T) {
		n := NewRemoteNode(
			"smf1",
			nil,
			&LocalNode{},
			forwarder.Empty{},
			logger.PfcpLog.WithField(logger_util.FieldControlPlaneNodeID, "smf1"),
		)

		testcases := []struct {
			localID  uint64
			remoteID uint64
		}{
			{1, 10}, {2, 20}, {3, 30},
		}

		for _, tc := range testcases {
			n.NewSess(tc.remoteID)
		}

		for _, tc := range testcases {
			n.DeleteSess(tc.localID)
		}

		// assure the session is deleted
		for _, tc := range testcases {
			_, err := n.Sess(tc.localID)
			assert.NotNil(t, err)
		}

		// delete again should have no effect
		for _, tc := range testcases {
			report := n.DeleteSess(tc.localID)
			assert.Nil(t, report)
		}
	})
}

func TestRemoteNodeMatchesPeer(t *testing.T) {
	udp := func(ip string, port int, zone string) *net.UDPAddr {
		return &net.UDPAddr{IP: net.ParseIP(ip), Port: port, Zone: zone}
	}
	for _, tc := range []struct {
		name  string
		bound net.Addr
		peer  net.Addr
		want  bool
	}{
		{"same IPv4 different port", udp("192.0.2.1", 8805, ""), udp("192.0.2.1", 12345, ""), true},
		{"different IPv4", udp("192.0.2.1", 8805, ""), udp("192.0.2.2", 8805, ""), false},
		{"mapped IPv4", udp("192.0.2.1", 8805, ""), udp("::ffff:192.0.2.1", 8805, ""), true},
		{"same IPv6", udp("2001:db8::1", 8805, ""), udp("2001:db8::1", 12345, ""), true},
		{"different IPv6", udp("2001:db8::1", 8805, ""), udp("2001:db8::2", 8805, ""), false},
		{"same zone", udp("fe80::1", 8805, "eth0"), udp("fe80::1", 12345, "eth0"), true},
		{"different zone", udp("fe80::1", 8805, "eth0"), udp("fe80::1", 8805, "eth1"), false},
		{"nil bound", nil, udp("192.0.2.1", 8805, ""), false},
		{"typed nil bound", (*net.UDPAddr)(nil), udp("192.0.2.1", 8805, ""), false},
		{"nil peer", udp("192.0.2.1", 8805, ""), nil, false},
		{"typed nil peer", udp("192.0.2.1", 8805, ""), (*net.UDPAddr)(nil), false},
		{"missing IP", &net.UDPAddr{}, &net.UDPAddr{}, false},
		{"wrong transport", udp("192.0.2.1", 8805, ""), &net.TCPAddr{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n := &RemoteNode{addr: tc.bound}
			assert.Equal(t, tc.want, n.matchesPeer(tc.peer))
		})
	}
	var n *RemoteNode
	assert.False(t, n.matchesPeer(udp("192.0.2.1", 8805, "")))
}

func TestRemoteNode_multipleSMF(t *testing.T) {
	var lnode LocalNode
	n1 := NewRemoteNode(
		"smf1",
		nil,
		&lnode,
		forwarder.Empty{},
		logger.PfcpLog.WithField(logger_util.FieldControlPlaneNodeID, "smf1"),
	)
	n2 := NewRemoteNode(
		"smf2",
		nil,
		&lnode,
		forwarder.Empty{},
		logger.PfcpLog.WithField(logger_util.FieldControlPlaneNodeID, "smf2"),
	)
	t.Run("new smf1 r-SEID=10", func(t *testing.T) {
		sess := n1.NewSess(10)
		if sess.LocalID != 1 {
			t.Errorf("want 1; but got %v\n", sess.LocalID)
		}
		if sess.RemoteID != 10 {
			t.Errorf("want 10; but got %v\n", sess.RemoteID)
		}
	})
	t.Run("new smf2 r-SEID=10", func(t *testing.T) {
		sess := n2.NewSess(10)
		if sess.LocalID != 2 {
			t.Errorf("want 2; but got %v\n", sess.LocalID)
		}
		if sess.RemoteID != 10 {
			t.Errorf("want 10; but got %v\n", sess.RemoteID)
		}
	})
	t.Run("get smf1 l-SEID=1", func(t *testing.T) {
		sess, err := n1.Sess(1)
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
		sess, err := n2.Sess(2)
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
		_, err := n1.Sess(2)
		if err == nil {
			t.Errorf("want error; but not error")
		}
	})
	t.Run("get smf2 l-SEID=1", func(t *testing.T) {
		_, err := n2.Sess(1)
		if err == nil {
			t.Errorf("want error; but not error")
		}
	})
	t.Run("new smf1:20", func(t *testing.T) {
		sess := n1.NewSess(20)
		if sess.LocalID != 3 {
			t.Errorf("want 3; but got %v\n", sess.LocalID)
		}
		if sess.RemoteID != 20 {
			t.Errorf("want 20; but got %v\n", sess.RemoteID)
		}
	})
	t.Run("get smf2 l-SEID=3", func(t *testing.T) {
		_, err := n2.Sess(3)
		if err == nil {
			t.Errorf("want error; but not error")
		}
	})
	t.Run("reset smf1", func(t *testing.T) {
		n1.Reset()
	})
	t.Run("get smf1 l-SEID=1", func(t *testing.T) {
		_, err := n1.Sess(1)
		if err == nil {
			t.Errorf("want error; but not error")
		}
	})
	t.Run("get smf1 l-SEID=3", func(t *testing.T) {
		_, err := n1.Sess(3)
		if err == nil {
			t.Errorf("want error; but not error")
		}
	})
	t.Run("get smf2 l-SEID=2", func(t *testing.T) {
		sess, err := n2.Sess(2)
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
		sess := lnode.NewSess(10, BUFFQ_LEN)
		assert.Equal(t, uint64(1), sess.LocalID)
		assert.Equal(t, uint64(10), sess.RemoteID)
	})

	t.Run("recycle LocalID", func(t *testing.T) {
		lnode := LocalNode{
			sess: []*Sess{},
			free: []uint64{},
		}
		sess := lnode.NewSess(10, BUFFQ_LEN)
		recycleLocalID := 1
		assert.Equal(t, uint64(recycleLocalID), sess.LocalID)
		assert.Equal(t, uint64(10), sess.RemoteID)
	})

	t.Run("remote sess skips deleted local slots", func(t *testing.T) {
		addr := &net.UDPAddr{IP: net.IPv4(10, 100, 200, 5), Port: 8805}
		lnode := &LocalNode{}
		rnode := NewRemoteNode(
			"smf1",
			addr,
			lnode,
			forwarder.Empty{},
			logger.PfcpLog.WithField(logger_util.FieldControlPlaneNodeID, "smf1"),
		)

		deletedSess := rnode.NewSess(0x1efcd)
		activeSess := rnode.NewSess(0x1efce)
		rnode.DeleteSess(deletedSess.LocalID)

		sess, err := lnode.RemoteSess(activeSess.RemoteID, addr)
		assert.NoError(t, err)
		assert.Equal(t, activeSess.LocalID, sess.LocalID)

		_, err = lnode.RemoteSess(deletedSess.RemoteID, addr)
		assert.Error(t, err)
	})
}
