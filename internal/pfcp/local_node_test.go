package pfcp

import (
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
	first.sessions.sessions = append(first.sessions.sessions, &Sess{})

	assert.Empty(t, second.associations)
	assert.Empty(t, second.sessions.sessions)
}
