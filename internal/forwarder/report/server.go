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
	logger.ReportLog.Infof("report server started")

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
	usar := report.USAReport{}
	var off int
	seid := *(*uint64)(unsafe.Pointer(&b[off]))
	off += 8
	action := *(*uint16)(unsafe.Pointer(&b[off]))
	off += 2
	usar.URRID = (*(*uint32)(unsafe.Pointer(&b[off])))
	off += 4
	usar.URSEQN = (*(*uint32)(unsafe.Pointer(&b[off])))
	off += 4

	trigger := (*(*uint64)(unsafe.Pointer(&b[off])))

	usar.USARTrigger = report.UsageReportTrigger{
		PERIO: uint8(trigger & 1),
		VOLTH: uint8((trigger >> 1) & 1),
		TIMTH: uint8((trigger >> 2) & 1),
		QUHTI: uint8((trigger >> 3) & 1),
		START: uint8((trigger >> 4) & 1),
		STOPT: uint8((trigger >> 5) & 1),
		DROTH: uint8((trigger >> 6) & 1),
		IMMER: uint8((trigger >> 7) & 1),
		VOLQU: uint8((trigger >> 8) & 1),
		TIMQU: uint8((trigger >> 9) & 1),
		LIUSA: uint8((trigger >> 10) & 1),
		TERMR: uint8((trigger >> 11) & 1),
		MONIT: uint8((trigger >> 12) & 1),
		ENVCL: uint8((trigger >> 13) & 1),
		MACAR: uint8((trigger >> 14) & 1),
		EVETH: uint8((trigger >> 15) & 1),
		EVEQU: uint8((trigger >> 16) & 1),
		TEBUR: uint8((trigger >> 17) & 1),
		IPMJL: uint8((trigger >> 18) & 1),
		QUVTI: uint8((trigger >> 19) & 1),
		EMRRE: uint8((trigger >> 20) & 1),
	}
	off += 8
	usar.VolMeasurement.Flag = (uint8)(*(*uint64)(unsafe.Pointer(&b[off])))
	off += 1
	usar.VolMeasurement.TotalVolume = (*(*uint64)(unsafe.Pointer(&b[off])))
	off += 8
	usar.VolMeasurement.UplinkVolume = (*(*uint64)(unsafe.Pointer(&b[off])))
	off += 8
	usar.VolMeasurement.DownlinkVolume = (*(*uint64)(unsafe.Pointer(&b[off])))
	off += 8
	usar.VolMeasurement.TotalPktNum = (*(*uint64)(unsafe.Pointer(&b[off])))
	off += 8
	usar.VolMeasurement.UplinkPktNum = (*(*uint64)(unsafe.Pointer(&b[off])))
	off += 8
	usar.VolMeasurement.DownlinkPktNum = (*(*uint64)(unsafe.Pointer(&b[off])))
	off += 8
	usar.QueryUrrRef = (*(*uint32)(unsafe.Pointer(&b[off])))
	off += 4
	logger.PfcpLog.Info(usar)
	return seid, action, usar, b[off:], nil
}

func (s *Server) Pop(seid uint64, pdrid uint16) ([]byte, bool) {
	return s.handler.PopBufPkt(seid, pdrid)
}
