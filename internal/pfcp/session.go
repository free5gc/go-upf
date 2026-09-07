package pfcp

import (
	"github.com/sirupsen/logrus"

	"github.com/free5gc/go-upf/internal/forwarder"
	"github.com/free5gc/go-upf/internal/rules"
)

const (
	BUFFQ_LEN = 512
)

// URRInfo separates shared rule configuration from PFCP reporting runtime.
type URRInfo struct {
	Config    rules.URRConfig
	removed   bool
	SEQN      uint32
	refPdrNum uint16
}

type Session struct {
	association *PFCPAssociation          // remote PFCP association that owns this session
	driver      forwarder.Driver          // legacy plan builders; shared driver is owned by LocalNode
	datapath    forwarder.SessionDatapath // execution handle owned by this session
	LocalID     uint64
	RemoteID    uint64
	PDRIDs      map[uint16]*rules.PDRConfig // key: PDR_ID
	FARIDs      map[uint32]*rules.FARConfig // key: FAR_ID
	QERIDs      map[uint32]*rules.QERConfig // key: QER_ID
	URRIDs      map[uint32]*URRInfo         // key: URR_ID
	BARIDs      map[uint8]*rules.BARConfig  // key: BAR_ID
	q           map[uint16]chan []byte
	qlen        int
	log         *logrus.Entry
}

func (s *Session) Push(pdrid uint16, p []byte) {
	pkt := make([]byte, len(p))
	copy(pkt, p)
	q, ok := s.q[pdrid]
	if !ok {
		s.q[pdrid] = make(chan []byte, s.qlen)
		q = s.q[pdrid]
	}

	select {
	case q <- pkt:
		s.log.Debugf("Push bufPkt to q[%d](len:%d)", pdrid, len(q))
	default:
		s.log.Debugf("q[%d](len:%d) is full, drop it", pdrid, len(q))
	}
}

func (s *Session) Len(pdrid uint16) int {
	q, ok := s.q[pdrid]
	if !ok {
		return 0
	}
	return len(q)
}

func (s *Session) Pop(pdrid uint16) ([]byte, bool) {
	q, ok := s.q[pdrid]
	if !ok {
		return nil, ok
	}
	select {
	case pkt := <-q:
		s.log.Debugf("Pop bufPkt from q[%d](len:%d)", pdrid, len(q))
		return pkt, true
	default:
		return nil, false
	}
}

func (s *Session) URRSeq(urrid uint32) uint32 {
	info, ok := s.URRIDs[urrid]
	if !ok {
		return 0
	}
	seq := info.SEQN
	info.SEQN++
	return seq
}
