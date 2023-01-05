package pfcp

import (
	"testing"

	"github.com/free5gc/go-upf/internal/forwarder"
	"github.com/free5gc/go-upf/internal/logger"
	logger_util "github.com/free5gc/util/logger"
)

func TestNode(t *testing.T) {
	n := NewRemoteNode(
		"smf1",
		nil,
		&LocalNode{},
		forwarder.Empty{},
		logger.PfcpLog.WithField(logger_util.FieldControlPlaneNodeID, "smf1"),
	)
	t.Run("delete 0 no effect", func(t *testing.T) {
		n.DeleteSess(0)
	})
	t.Run("sess 0 is not found", func(t *testing.T) {
		_, err := n.Sess(0)
		if err == nil {
			t.Errorf("want false; but got %v\n", err)
		}
	})
	t.Run("sess 1 is not found", func(t *testing.T) {
		_, err := n.Sess(1)
		if err == nil {
			t.Errorf("want false; but got %v\n", err)
		}
	})
	t.Run("sess 2 is not found", func(t *testing.T) {
		_, err := n.Sess(2)
		if err == nil {
			t.Errorf("want false; but got %v\n", err)
		}
	})
	t.Run("new 1", func(t *testing.T) {
		sess := n.NewSess(10)
		if sess.LocalID != 1 {
			t.Errorf("want 1; but got %v\n", sess.LocalID)
		}
		if sess.RemoteID != 10 {
			t.Errorf("want 10; but got %v\n", sess.RemoteID)
		}
	})
	t.Run("new 2", func(t *testing.T) {
		sess := n.NewSess(20)
		if sess.LocalID != 2 {
			t.Errorf("want 2; but got %v\n", sess.LocalID)
		}
		if sess.RemoteID != 20 {
			t.Errorf("want 20; but got %v\n", sess.RemoteID)
		}
	})
	t.Run("new 3", func(t *testing.T) {
		sess := n.NewSess(30)
		if sess.LocalID != 3 {
			t.Errorf("want 3; but got %v\n", sess.LocalID)
		}
		if sess.RemoteID != 30 {
			t.Errorf("want 30; but got %v\n", sess.RemoteID)
		}
	})
	t.Run("sess 1", func(t *testing.T) {
		sess, err := n.Sess(1)
		if err != nil {
			t.Fatalf("want true; but got %v\n", err)
		}
		if sess.LocalID != 1 {
			t.Errorf("want 1; but got %v\n", sess.LocalID)
		}
		if sess.RemoteID != 10 {
			t.Errorf("want 10; but got %v\n", sess.RemoteID)
		}
	})
	t.Run("sess 2", func(t *testing.T) {
		sess, err := n.Sess(2)
		if err != nil {
			t.Fatalf("want true; but got %v\n", err)
		}
		if sess.LocalID != 2 {
			t.Errorf("want 2; but got %v\n", sess.LocalID)
		}
		if sess.RemoteID != 20 {
			t.Errorf("want 20; but got %v\n", sess.RemoteID)
		}
	})
	t.Run("sess 3", func(t *testing.T) {
		sess, err := n.Sess(3)
		if err != nil {
			t.Fatalf("want true; but got %v\n", err)
		}
		if sess.LocalID != 3 {
			t.Errorf("want 3; but got %v\n", sess.LocalID)
		}
		if sess.RemoteID != 30 {
			t.Errorf("want 30; but got %v\n", sess.RemoteID)
		}
	})
	t.Run("sess 4 is not found", func(t *testing.T) {
		_, err := n.Sess(4)
		if err == nil {
			t.Errorf("want false; but got %v\n", err)
		}
	})
	t.Run("delete 2", func(t *testing.T) {
		n.DeleteSess(2)
	})
	t.Run("sess 2 is not found", func(t *testing.T) {
		_, err := n.Sess(2)
		if err == nil {
			t.Errorf("want false; but got %v\n", err)
		}
	})
	t.Run("delete 1", func(t *testing.T) {
		n.DeleteSess(1)
	})
	t.Run("sess 1 is not found", func(t *testing.T) {
		_, err := n.Sess(1)
		if err == nil {
			t.Errorf("want false; but got %v\n", err)
		}
	})
	t.Run("delete 1 no effect", func(t *testing.T) {
		n.DeleteSess(1)
	})
	t.Run("delete 4 no effect", func(t *testing.T) {
		n.DeleteSess(4)
	})
	t.Run("new 4", func(t *testing.T) {
		sess := n.NewSess(40)
		if sess.LocalID != 1 {
			t.Errorf("want 1; but got %v\n", sess.LocalID)
		}
		if sess.RemoteID != 40 {
			t.Errorf("want 40; but got %v\n", sess.RemoteID)
		}
	})
}

func TestNode_multipleSMF(t *testing.T) {
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
