package report

import (
	"io"
	"net"
	"os"
	"sync"
	"unsafe"

	"github.com/free5gc/go-upf/internal/logger"
	"github.com/free5gc/go-upf/internal/report"
)

type Server struct {
	conn    *net.UnixConn
	handler report.Handler
}

func OpenServer(wg *sync.WaitGroup, addr string) (*Server, error) {
	s := new(Server)

	err := os.Remove(addr)
	if err != nil {
		logger.ReportLog.Traceln(err)
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

	wg.Add(1)
	go s.Serve(wg)
	logger.ReportLog.Infof("buff server started")

	return s, nil
}

func (s *Server) Close() {
	err := s.conn.Close()
	if err != nil {
		logger.ReportLog.Warnf("Server close err: %+v", err)
	}
}

func (s *Server) Handle(handler report.Handler) {
	s.handler = handler
}

func (s *Server) Serve(wg *sync.WaitGroup) {
	defer func() {
		logger.ReportLog.Infof("report server stopped")
		wg.Done()
	}()

	b := make([]byte, 96*1024)
	for {
		n, _, err := s.conn.ReadFrom(b)
		if err != nil {
			break
		}
		seid, action, usar, pkt, err := s.decode(b[:n])
		if err != nil {
			continue
		}

		if s.handler == nil {
			continue
		}
		s.handler.NotifySessReport(
			report.SessReport{
				SEID:   seid,
				Report: usar,
				Action: action,
				BufPkt: pkt,
			},
		)
	}
}

func (s *Server) decode(b []byte) (uint64, uint16, report.USAReport, []byte, error) {
	n := len(b)
	if n < 12 {
		return 0, 0, report.USAReport{}, nil, io.ErrUnexpectedEOF
	}
	var off int
	seid := *(*uint64)(unsafe.Pointer(&b[off]))
	off += 8
	action := *(*uint16)(unsafe.Pointer(&b[off]))
	off += 2
	usar := *(*report.USAReport)(unsafe.Pointer(&b[off]))
	off += 82
	return seid, action, usar, b[off:], nil
}

func (s *Server) Pop(seid uint64, pdrid uint16) ([]byte, bool) {
	return s.handler.PopBufPkt(seid, pdrid)
}
