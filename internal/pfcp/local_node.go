package pfcp

import (
	"time"

	"github.com/sirupsen/logrus"

	"github.com/free5gc/go-upf/internal/forwarder"
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
