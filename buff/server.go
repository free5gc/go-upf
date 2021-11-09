package buff

import (
	"net"
	"os"
	"unsafe"

	"github.com/m-asama/upf/report"
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

func OpenServer(addr string, qlen int) (*Server, error) {
	s := new(Server)

	os.Remove(addr)
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

	go s.Serve()

	return s, nil
}

func (s *Server) Close() {
	s.conn.Close()
}

func (s *Server) Handle(handler report.Handler) {
	s.handler = handler
}

func (s *Server) HandleFunc(f func(report.Report)) {
	s.handler = report.HandlerFunc(f)
}

func (s *Server) Serve() {
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
		if action&NOCP != 0 {
			if s.handler != nil {
				s.handler.ServeReport(report.DLDReport{pdrid})
			}
		}
		pkt := make([]byte, n-4)
		copy(pkt, b[4:n])
		q, ok := s.q[pdrid]
		if !ok {
			s.q[pdrid] = make(chan []byte, s.qlen)
			q = s.q[pdrid]
		}
		q <- pkt
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
