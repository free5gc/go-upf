package pfcp

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/free5gc/go-upf/internal/forwarder"
	"github.com/free5gc/go-upf/internal/logger"
)

func TestSessionStore(t *testing.T) {
	t.Run("new session", func(t *testing.T) {
		sessions := SessionStore{}
		sess := sessions.Create(10, BUFFQ_LEN, forwarder.Empty{})
		assert.Equal(t, uint64(1), sess.LocalID)
		assert.Equal(t, uint64(10), sess.RemoteID)
	})

	t.Run("recycle local SEID", func(t *testing.T) {
		sessions := SessionStore{}
		first := sessions.Create(10, BUFFQ_LEN, forwarder.Empty{})
		first.log = logger.PfcpLog.WithField("test", t.Name())

		_, err := sessions.Delete(first.LocalID)
		assert.NoError(t, err)

		second := sessions.Create(20, BUFFQ_LEN, forwarder.Empty{})
		assert.Equal(t, first.LocalID, second.LocalID)
		assert.Equal(t, uint64(20), second.RemoteID)
	})
}
