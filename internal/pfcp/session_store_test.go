package pfcp

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/free5gc/go-upf/internal/forwarder"
	"github.com/free5gc/go-upf/internal/logger"
	"github.com/free5gc/go-upf/internal/report"
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

// Embedding Empty must not bypass the concrete driver's overrides when a
// SessionStore creates its datapath handle.
type sessionStoreDriver struct {
	forwarder.Empty
	queriedSEID  uint64
	cleanedSEIDs []uint64
	closed       bool
}

func (d *sessionStoreDriver) QueryURR(seid uint64, _ uint32) ([]report.USAReport, error) {
	d.queriedSEID = seid
	return nil, nil
}

func (d *sessionStoreDriver) ExecuteModificationPlan(plan *forwarder.ModificationPlan) (*forwarder.ExecutionResult, error) {
	d.cleanedSEIDs = append(d.cleanedSEIDs, plan.SEID)
	return forwarder.NewSuccessfulExecutionResult(plan), nil
}

func (d *sessionStoreDriver) Close() { d.closed = true }

func TestSessionStoreOwnsDatapathHandles(t *testing.T) {
	store := SessionStore{}
	driver := &sessionStoreDriver{}
	first := store.Create(10, BUFFQ_LEN, driver)
	first.log = logger.PfcpLog.WithField("test", t.Name())
	second := store.Create(20, BUFFQ_LEN, driver)

	_, err := first.datapath.QueryURR(7)
	assert.NoError(t, err)
	assert.Equal(t, first.LocalID, driver.queriedSEID)
	_, err = store.Delete(first.LocalID)
	assert.NoError(t, err)
	assert.Equal(t, []uint64{first.LocalID}, driver.cleanedSEIDs)
	assert.False(t, driver.closed)

	_, err = second.datapath.QueryURR(7)
	assert.NoError(t, err)
	assert.Equal(t, second.LocalID, driver.queriedSEID)

	recycled := store.Create(30, BUFFQ_LEN, driver)
	assert.Equal(t, first.LocalID, recycled.LocalID)
	assert.NotSame(t, first.datapath, recycled.datapath)
	_, err = recycled.datapath.QueryURR(7)
	assert.NoError(t, err)
	assert.Equal(t, recycled.LocalID, driver.queriedSEID)
}
