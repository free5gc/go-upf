package buff

import (
	"github.com/free5gc/go-upf/internal/report"
)

type Sess struct {
	handler report.Handler
	q       map[uint16]chan []byte
	qlen    int
}

func OpenSess(handler report.Handler, qlen int) *Sess {
	s := new(Sess)
	s.handler = handler
	s.q = make(map[uint16]chan []byte)
	s.qlen = qlen
	return s
}

func (s *Sess) Close() {
	for _, q := range s.q {
		close(q)
	}
}

func (s *Sess) Push(pdrid uint16, p []byte) {
	pkt := make([]byte, len(p))
	copy(pkt, p)
	q, ok := s.q[pdrid]
	if !ok {
		s.q[pdrid] = make(chan []byte, s.qlen)
		q = s.q[pdrid]
	}
	q <- pkt
}

func (s *Sess) Len(pdrid uint16) int {
	q, ok := s.q[pdrid]
	if !ok {
		return 0
	}
	return len(q)
}

func (s *Sess) Pop(pdrid uint16) ([]byte, bool) {
	q, ok := s.q[pdrid]
	if !ok {
		return nil, ok
	}
	select {
	case pkt := <-q:
		return pkt, true
	default:
		return nil, false
	}
}
