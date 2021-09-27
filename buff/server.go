package buff

import (
	"net"
	"os"
	"unsafe"
)

const (
	BUFF = 1 << 2
	NOCP = 1 << 3
)

type Server struct {
	conn   *net.UnixConn
	f      *os.File
	q      map[uint16]chan []byte
	qlen   int
	notify func(uint16)
}

func OpenServer(addr string, qlen int, notify func(uint16)) (*Server, error) {
	s := new(Server)

	laddr, err := net.ResolveUnixAddr("unixgram", addr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUnixgram("unixgram", laddr)
	if err != nil {
		return nil, err
	}
	s.conn = conn

	f, err := conn.File()
	if err != nil {
		s.Close()
		return nil, err
	}
	s.f = f

	s.q = make(map[uint16]chan []byte)
	s.qlen = qlen

	s.notify = notify

	go s.Serve()

	return s, nil
}

func (s *Server) Close() {
	if s.conn != nil {
		s.conn.Close()
	}
	if s.f != nil {
		s.f.Close()
	}
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
			s.notify(pdrid)
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
