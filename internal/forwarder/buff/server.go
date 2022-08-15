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

type Server struct {
	conn    *net.UnixConn
	handler report.Handler
}

func OpenServer(wg *sync.WaitGroup, addr string) (*Server, error) {
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

func (s *Server) SendReport(sp report.SessReport) {
	s.handler.NotifySessReport(
		sp,
	)
}

func (s *Server) Handle(handler report.Handler) {
	s.handler = handler
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
		msgtype, seid, pdrid, action, pkt, reports, err := s.decode(b[:n])
		if err != nil {
			continue
		}
		if s.handler == nil {
			continue
		}
		if msgtype == 1 {
			dldr := report.DLDReport{
				PDRID:  pdrid,
				Action: action,
				BufPkt: pkt,
			}
			s.handler.NotifySessReport(
				report.SessReport{
					SEID:    seid,
					Reports: []report.Report{dldr},
				},
			)
		} else if msgtype == 2 {

			var usars []report.Report
			for _, usar := range reports {
				usars = append(usars, usar)
			}

			s.handler.NotifySessReport(
				report.SessReport{
					SEID:    seid,
					Reports: usars,
				},
			)
		} else {
			logger.BuffLog.Warn("Unknow Report Type")
		}

	}
}

func (s *Server) decode(b []byte) (uint8, uint64, uint16, uint16, []byte, []report.USAReport, error) {
	n := len(b)
	if n < 12 {
		return 0, 0, 0, 0, nil, nil, io.ErrUnexpectedEOF
	}
	var off int
	msgtype := *(*uint8)(unsafe.Pointer(&b[off]))
	off += 1
	seid := *(*uint64)(unsafe.Pointer(&b[off]))
	off += 8

	if msgtype == 2 {
		report_num := int(*(*uint16)(unsafe.Pointer(&b[off])))
		off += 2
		multiusar := []report.USAReport{}

		for i := 0; i < report_num; i++ {
			usar := report.USAReport{}

			usar.URRID = (*(*uint32)(unsafe.Pointer(&b[off])))
			off += 4
			usar.URSEQN = (*(*uint32)(unsafe.Pointer(&b[off])))
			off += 4

			trigger := (*(*uint64)(unsafe.Pointer(&b[off])))

			usar.USARTrigger = report.UsageReportTrigger{
				PERIO: uint8((trigger >> 16) & 1),
				VOLTH: uint8((trigger >> 17) & 1),
				TIMTH: uint8((trigger >> 18) & 1),
				QUHTI: uint8((trigger >> 19) & 1),
				START: uint8((trigger >> 20) & 1),
				STOPT: uint8((trigger >> 21) & 1),
				DROTH: uint8((trigger >> 22) & 1),
				IMMER: uint8((trigger >> 23) & 1),
				VOLQU: uint8((trigger >> 8) & 1),
				TIMQU: uint8((trigger >> 9) & 1),
				LIUSA: uint8((trigger >> 10) & 1),
				TERMR: uint8((trigger >> 11) & 1),
				MONIT: uint8((trigger >> 12) & 1),
				ENVCL: uint8((trigger >> 13) & 1),
				MACAR: uint8((trigger >> 14) & 1),
				EVETH: uint8((trigger >> 15) & 1),
				EVEQU: uint8((trigger) & 1),
				TEBUR: uint8((trigger >> 1) & 1),
				IPMJL: uint8((trigger >> 2) & 1),
				QUVTI: uint8((trigger >> 3) & 1),
				EMRRE: uint8((trigger >> 4) & 1),
			}
			off += 8
			usar.VolMeasurement.Flag = (*(*uint8)(unsafe.Pointer(&b[off])))
			off += 1
			usar.VolMeasurement.TotalVolume = uint64((*(*uint64)(unsafe.Pointer(&b[off]))) / 8192.0)
			off += 8
			usar.VolMeasurement.UplinkVolume = uint64((*(*uint64)(unsafe.Pointer(&b[off]))) / 8192.0)
			off += 8
			usar.VolMeasurement.DownlinkVolume = uint64((*(*uint64)(unsafe.Pointer(&b[off]))) / 8192.0)
			off += 8
			usar.VolMeasurement.TotalPktNum = (*(*uint64)(unsafe.Pointer(&b[off])))
			off += 8
			usar.VolMeasurement.UplinkPktNum = (*(*uint64)(unsafe.Pointer(&b[off])))
			off += 8
			usar.VolMeasurement.DownlinkPktNum = (*(*uint64)(unsafe.Pointer(&b[off])))
			off += 8
			usar.QueryUrrRef = (*(*uint32)(unsafe.Pointer(&b[off])))
			off += 4

			multiusar = append(multiusar, usar)
		}
		return msgtype, seid, 0, 0, nil, multiusar, nil
	} else if msgtype == 1 {
		pdrid := *(*uint16)(unsafe.Pointer(&b[off]))
		off += 2
		action := *(*uint16)(unsafe.Pointer(&b[off]))
		off += 2
		return msgtype, seid, pdrid, action, b[off:], nil, nil
	} else {
		return msgtype, seid, 0, 0, b[off:], nil, nil
	}
}

func (s *Server) Pop(seid uint64, pdrid uint16) ([]byte, bool) {
	return s.handler.PopBufPkt(seid, pdrid)
}
