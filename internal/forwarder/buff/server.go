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

const (
	TYPE_BUFFER     uint8 = 1
	TYPE_URR_REPORT uint8 = 2
)

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
		if msgtype == TYPE_BUFFER {
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
		} else if msgtype == TYPE_URR_REPORT {

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

	if msgtype == TYPE_URR_REPORT {
		report_num := int(*(*uint16)(unsafe.Pointer(&b[off])))
		off += 2
		multiusar := []report.USAReport{}

		for i := 0; i < report_num; i++ {
			usar := report.USAReport{}

			usar.URRID = (*(*uint32)(unsafe.Pointer(&b[off])))
			off += 4
			usar.URSEQN = (*(*uint32)(unsafe.Pointer(&b[off])))
			off += 4
			r := (*(*uint64)(unsafe.Pointer(&b[off])))

			usar.USARTrigger = report.UsageReportTrigger{
				EVEQU: uint8((r) & 1),
				TEBUR: uint8((r >> 1) & 1),
				IPMJL: uint8((r >> 2) & 1),
				QUVTI: uint8((r >> 3) & 1),
				EMRRE: uint8((r >> 4) & 1),
				VOLQU: uint8((r >> 8) & 1),
				TIMQU: uint8((r >> 9) & 1),
				LIUSA: uint8((r >> 10) & 1),
				TERMR: uint8((r >> 11) & 1),
				MONIT: uint8((r >> 12) & 1),
				ENVCL: uint8((r >> 13) & 1),
				MACAR: uint8((r >> 14) & 1),
				EVETH: uint8((r >> 15) & 1),
				PERIO: uint8((r >> 16) & 1),
				VOLTH: uint8((r >> 17) & 1),
				TIMTH: uint8((r >> 18) & 1),
				QUHTI: uint8((r >> 19) & 1),
				START: uint8((r >> 20) & 1),
				STOPT: uint8((r >> 21) & 1),
				DROTH: uint8((r >> 22) & 1),
				IMMER: uint8((r >> 23) & 1),
			}
			off += 8

			// For flag in report struct
			// v := (*(*uint8)(unsafe.Pointer(&b[off])))
			off += 1
			usar.VolMeasure.TotalVolume = uint64((*(*uint64)(unsafe.Pointer(&b[off]))) / 1024.0)
			if usar.VolMeasure.TotalVolume > 0 {
				usar.VolMeasure.TOVOL = 1
			}
			off += 8
			usar.VolMeasure.UplinkVolume = uint64((*(*uint64)(unsafe.Pointer(&b[off]))) / 1024.0)
			if usar.VolMeasure.UplinkVolume > 0 {
				usar.VolMeasure.ULVOL = 1
			}
			off += 8
			usar.VolMeasure.DownlinkVolume = uint64((*(*uint64)(unsafe.Pointer(&b[off]))) / 1024.0)
			if usar.VolMeasure.DownlinkVolume > 0 {
				usar.VolMeasure.DLVOL = 1
			}
			off += 8
			usar.VolMeasure.TotalPktNum = (*(*uint64)(unsafe.Pointer(&b[off])))
			if usar.VolMeasure.TotalPktNum > 0 {
				usar.VolMeasure.TOVOL = 1
			}
			off += 8
			usar.VolMeasure.UplinkPktNum = (*(*uint64)(unsafe.Pointer(&b[off])))

			if usar.VolMeasure.UplinkPktNum > 0 {
				usar.VolMeasure.ULNOP = 1
			}
			off += 8
			usar.VolMeasure.DownlinkPktNum = (*(*uint64)(unsafe.Pointer(&b[off])))
			if usar.VolMeasure.DownlinkPktNum > 0 {
				usar.VolMeasure.DLNOP = 1
			}
			off += 8
			usar.QueryUrrRef = (*(*uint32)(unsafe.Pointer(&b[off])))
			off += 4

			multiusar = append(multiusar, usar)
		}
		return msgtype, seid, 0, 0, nil, multiusar, nil
	} else if msgtype == TYPE_BUFFER {
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
