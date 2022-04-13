package buff

import (
	"io"
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
	conn *net.UnixConn
	sess sync.Map
	qlen int
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

func (s *Server) Handle(seid uint64, handler report.Handler) {
	sess := OpenSess(handler, s.qlen)
	s.sess.Store(seid, sess)
}

func (s *Server) HandleFunc(seid uint64, f func(report.Report)) {
	sess := OpenSess(report.HandlerFunc(f), s.qlen)
	s.sess.Store(seid, sess)
}

func (s *Server) Drop(seid uint64) {
	v, ok := s.sess.Load(seid)
	if ok {
		s.sess.Delete(seid)
		sess := v.(*Sess)
		sess.Close()
	}
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
		seid, pdrid, action, pkt, err := s.decode(b[:n])
		if err != nil {
			continue
		}
		if action&BUFF == 0 {
			continue
		}
		v, ok := s.sess.Load(seid)
		if !ok {
			continue
		}
		sess := v.(*Sess)
		sess.Push(pdrid, pkt)
		if action&NOCP != 0 && sess.Len(pdrid) == 1 {
			rep := report.DLDReport{
				PDRID: pdrid,
			}
			sess.handler.ServeReport(rep)
		}
	}
	s.sess.Range(func(k, v interface{}) bool {
		sess := v.(*Sess)
		sess.Close()
		return true
	})
}

func (s *Server) decode(b []byte) (uint64, uint16, uint16, []byte, error) {
	n := len(b)
	if n < 12 {
		return 0, 0, 0, nil, io.ErrUnexpectedEOF
	}
	var off int
	seid := *(*uint64)(unsafe.Pointer(&b[off]))
	off += 8
	pdrid := *(*uint16)(unsafe.Pointer(&b[off]))
	off += 2
	action := *(*uint16)(unsafe.Pointer(&b[off]))
	off += 2
	return seid, pdrid, action, b[off:], nil
}

func (s *Server) Pop(seid uint64, pdrid uint16) ([]byte, bool) {
	v, ok := s.sess.Load(seid)
	if !ok {
		return nil, ok
	}
	sess := v.(*Sess)
	return sess.Pop(pdrid)
}
