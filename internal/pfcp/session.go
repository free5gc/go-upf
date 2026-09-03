package pfcp

import (
	"github.com/sirupsen/logrus"

	"github.com/free5gc/go-upf/internal/forwarder"
	"github.com/free5gc/go-upf/internal/report"
)

const (
	BUFFQ_LEN = 512
)

type PDRInfo struct {
	FARID              uint32
	HasFARID           bool
	RelatedURRIDs      map[uint32]struct{}
	RelatedQERIDs      map[uint32]struct{}
	SourceInterface    uint8
	HasSourceInterface bool
}

// QERInfo is the last kernel-applied PFCP state used by the FlowQoS resolver.
// Rate values are stored in bits per second, not PFCP's wire-level kbps.
type QERInfo struct {
	QFI uint8

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
	removed bool
	SEQN    uint32
	report.MeasureMethod
	report.MeasureInformation
	refPdrNum uint16
}

// appliedRulePlans keeps the complete create-form plans for the rules currently
// applied in the kernel. The PFCP-facing Info maps remain optimized for runtime
// lookups, while these plans provide before-images for request rollback.
type appliedRulePlans struct {
	pdrs map[uint16]*forwarder.PDRPlan
	fars map[uint32]*forwarder.FARPlan
	qers map[uint32]*forwarder.QERPlan
	urrs map[uint32]*forwarder.URRPlan
	bars map[uint8]*forwarder.BARPlan
}

func newAppliedRulePlans() *appliedRulePlans {
	return &appliedRulePlans{
		pdrs: make(map[uint16]*forwarder.PDRPlan),
		fars: make(map[uint32]*forwarder.FARPlan),
		qers: make(map[uint32]*forwarder.QERPlan),
		urrs: make(map[uint32]*forwarder.URRPlan),
		bars: make(map[uint8]*forwarder.BARPlan),
	}
}

func (s *Session) ensureAppliedRulePlans() *appliedRulePlans {
	if s.appliedRules == nil {
		s.appliedRules = newAppliedRulePlans()
	}
	return s.appliedRules
}

type Session struct {
	association  *PFCPAssociation // remote PFCP association that owns this session
	driver       forwarder.Driver // local UPF datapath dependency
	LocalID      uint64
	RemoteID     uint64
	PDRIDs       map[uint16]*PDRInfo    // key: PDR_ID
	FARIDs       map[uint32]struct{}    // key: FAR_ID
	QERIDs       map[uint32]*QERInfo    // key: QER_ID
	URRIDs       map[uint32]*URRInfo    // key: URR_ID
	BARIDs       map[uint8]struct{}     // key: BAR_ID
	appliedRules *appliedRulePlans      // complete kernel-applied rule before-images
	q            map[uint16]chan []byte // key: PDR_ID
	qlen         int
	log          *logrus.Entry
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
