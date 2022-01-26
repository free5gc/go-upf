package pfcp

import (
	"testing"
)

func TestNode(t *testing.T) {
	n := NewNode("", nil)
	t.Run("delete 0 no effect", func(t *testing.T) {
		n.Delete(0)
	})
	t.Run("sess 0 is not found", func(t *testing.T) {
		_, ok := n.Sess(0)
		if ok {
			t.Errorf("want false; but got %v\n", ok)
		}
	})
	t.Run("sess 1 is not found", func(t *testing.T) {
		_, ok := n.Sess(1)
		if ok {
			t.Errorf("want false; but got %v\n", ok)
		}
	})
	t.Run("sess 2 is not found", func(t *testing.T) {
		_, ok := n.Sess(2)
		if ok {
			t.Errorf("want false; but got %v\n", ok)
		}
	})
	t.Run("new 1", func(t *testing.T) {
		sess := n.New(10)
		if sess.LocalID != 1 {
			t.Errorf("want 1; but got %v\n", sess.LocalID)
		}
		if sess.RemoteID != 10 {
			t.Errorf("want 10; but got %v\n", sess.RemoteID)
		}
	})
	t.Run("new 2", func(t *testing.T) {
		sess := n.New(20)
		if sess.LocalID != 2 {
			t.Errorf("want 2; but got %v\n", sess.LocalID)
		}
		if sess.RemoteID != 20 {
			t.Errorf("want 20; but got %v\n", sess.RemoteID)
		}
	})
	t.Run("new 3", func(t *testing.T) {
		sess := n.New(30)
		if sess.LocalID != 3 {
			t.Errorf("want 3; but got %v\n", sess.LocalID)
		}
		if sess.RemoteID != 30 {
			t.Errorf("want 30; but got %v\n", sess.RemoteID)
		}
	})
	t.Run("sess 1", func(t *testing.T) {
		sess, ok := n.Sess(1)
		if !ok {
			t.Fatalf("want true; but got %v\n", ok)
		}
		if sess.LocalID != 1 {
			t.Errorf("want 1; but got %v\n", sess.LocalID)
		}
		if sess.RemoteID != 10 {
			t.Errorf("want 10; but got %v\n", sess.RemoteID)
		}
	})
	t.Run("sess 2", func(t *testing.T) {
		sess, ok := n.Sess(2)
		if !ok {
			t.Fatalf("want true; but got %v\n", ok)
		}
		if sess.LocalID != 2 {
			t.Errorf("want 2; but got %v\n", sess.LocalID)
		}
		if sess.RemoteID != 20 {
			t.Errorf("want 20; but got %v\n", sess.RemoteID)
		}
	})
	t.Run("sess 3", func(t *testing.T) {
		sess, ok := n.Sess(3)
		if !ok {
			t.Fatalf("want true; but got %v\n", ok)
		}
		if sess.LocalID != 3 {
			t.Errorf("want 3; but got %v\n", sess.LocalID)
		}
		if sess.RemoteID != 30 {
			t.Errorf("want 30; but got %v\n", sess.RemoteID)
		}
	})
	t.Run("sess 4 is not found", func(t *testing.T) {
		_, ok := n.Sess(4)
		if ok {
			t.Errorf("want false; but got %v\n", ok)
		}
	})
	t.Run("delete 2", func(t *testing.T) {
		n.Delete(2)
	})
	t.Run("sess 2 is not found", func(t *testing.T) {
		_, ok := n.Sess(2)
		if ok {
			t.Errorf("want false; but got %v\n", ok)
		}
	})
	t.Run("delete 1", func(t *testing.T) {
		n.Delete(1)
	})
	t.Run("sess 1 is not found", func(t *testing.T) {
		_, ok := n.Sess(1)
		if ok {
			t.Errorf("want false; but got %v\n", ok)
		}
	})
	t.Run("delete 1 no effect", func(t *testing.T) {
		n.Delete(1)
	})
	t.Run("delete 4 no effect", func(t *testing.T) {
		n.Delete(4)
	})
	t.Run("new 4", func(t *testing.T) {
		sess := n.New(40)
		if sess.LocalID != 1 {
			t.Errorf("want 1; but got %v\n", sess.LocalID)
		}
		if sess.RemoteID != 40 {
			t.Errorf("want 40; but got %v\n", sess.RemoteID)
		}
	})
}
