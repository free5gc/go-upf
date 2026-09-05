package pfcp

import (
	"time"

	"github.com/khirono/go-nl"
	"github.com/sirupsen/logrus"

	"github.com/free5gc/go-gtp5gnl"
	"github.com/free5gc/go-upf/internal/forwarder"
	"github.com/free5gc/go-upf/internal/report"
)

const (
	BUFFQ_LEN = 512
)

// ruleConfig is the complete rule configuration last confirmed by the datapath.
// It is embedded in each rule Info so Session has one canonical state per rule.
type ruleConfig struct {
	OID   gtp5gnl.OID
	Attrs []nl.Attr
}

type PDRInfo struct {
	ruleConfig

	FARID              uint32
	HasFARID           bool
	RelatedURRIDs      map[uint32]struct{}
	RelatedQERIDs      map[uint32]struct{}
	SourceInterface    uint8
	HasSourceInterface bool
}

type FARInfo struct {
	ruleConfig
}

// QERInfo is the last kernel-applied PFCP state used by the FlowQoS resolver.
// Rate values are stored in bits per second, not PFCP's wire-level kbps.
type QERInfo struct {
	ruleConfig

	QFI    uint8
	HasQFI bool

	GateUL  uint8
	GateDL  uint8
	HasGate bool

	GBRULBps uint64
	GBRDLBps uint64
	MBRULBps uint64
	MBRDLBps uint64
	HasGBR   bool
	HasMBR   bool
}

type URRInfo struct {
	ruleConfig

	// Applied reporting configuration.
	report.MeasureMethod
	report.MeasureInformation
	ReportingTrigger report.ReportingTrigger
	MeasurePeriod    time.Duration

	// Runtime state is intentionally preserved by UpdateURR patches.
	removed   bool
	SEQN      uint32
	refPdrNum uint16
}

type BARInfo struct {
	ruleConfig
}

type Session struct {
	association *PFCPAssociation // remote PFCP association that owns this session
	driver      forwarder.Driver // local UPF datapath dependency
	LocalID     uint64
	RemoteID    uint64
	PDRIDs      map[uint16]*PDRInfo // key: PDR_ID
	FARIDs      map[uint32]*FARInfo // key: FAR_ID
	QERIDs      map[uint32]*QERInfo // key: QER_ID
	URRIDs      map[uint32]*URRInfo // key: URR_ID
	BARIDs      map[uint8]*BARInfo  // key: BAR_ID
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
