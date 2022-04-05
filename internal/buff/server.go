package buff

import (
	"net"
	"os"
	"sync"
	"unsafe"

	"github.com/free5gc/go-upf/internal/logger"
	"github.com/free5gc/go-upf/internal/report"
)

const (
	BUFF = 1 << 2
	NOCP = 1 << 3
)

type Server struct {
	conn    *net.UnixConn
	q       map[uint16]chan []byte
	qlen    int
	handler report.Handler
}

func OpenServer(wg *sync.WaitGroup, addr string, qlen int) (*Server, error) {
	s := new(Server)

	err := os.Remove(addr)
	if err != nil {
		logger.BuffLog.Traceln(err)
	}
	laddr, err := net.ResolveUnixAddr("unixgram", addr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUnixgram("unixgram", laddr)
	if err != nil {
		return nil, err
	}
	s.conn = conn

	s.q = make(map[uint16]chan []byte)
	s.qlen = qlen

	wg.Add(1)
	go s.Serve(wg)
	logger.BuffLog.Infof("buff server started")

	return s, nil
}

func (s *Server) Close() {
	err := s.conn.Close()
	if err != nil {
		logger.BuffLog.Warnf("Server close err: %+v", err)
	}
}

func (s *Server) Handle(handler report.Handler) {
	s.handler = handler
}

func (s *Server) HandleFunc(f func(report.Report)) {
	s.handler = report.HandlerFunc(f)
}

func (s *Server) Serve(wg *sync.WaitGroup) {
	defer func() {
		logger.BuffLog.Infof("buff server stopped")
		wg.Done()
	}()

	b := make([]byte, 96*1024)
	for {
		n, _, err := s.conn.ReadFrom(b)
		if err != nil {
			break
		}
		if n < 4 {
			continue
		}
		pdrid := *(*uint16)(unsafe.Pointer(&b[0]))
		action := *(*uint16)(unsafe.Pointer(&b[2]))
		if action&BUFF == 0 {
			continue
		}
		pkt := make([]byte, n-4)
		copy(pkt, b[4:n])
		q, ok := s.q[pdrid]
		if !ok {
			s.q[pdrid] = make(chan []byte, s.qlen)
			q = s.q[pdrid]
		}
		q <- pkt
		if action&NOCP != 0 && len(q) == 1 {
			if s.handler != nil {
				s.handler.ServeReport(report.DLDReport{PDRID: pdrid})
			}
		}
	}
	for _, q := range s.q {
		close(q)
	}
}

func (s *Server) Pop(pdrid uint16) ([]byte, bool) {
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
