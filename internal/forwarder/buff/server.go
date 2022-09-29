package buff

import (
	"io"
	"net"
	"os"
	"sync"
	"time"
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

		switch msgtype {
		case TYPE_BUFFER:
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
		case TYPE_URR_REPORT:
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
		default:
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
		usars := []report.USAReport{}

		for i := 0; i < report_num; i++ {
			usar := report.USAReport{}

			usar.URRID = (*(*uint32)(unsafe.Pointer(&b[off])))
			off += 4
			r := (*(*uint64)(unsafe.Pointer(&b[off])))

			usar.USARTrigger.Unmarshal(uint32(r))
			off += 8

			usar.VolumMeasure.TotalVolume = (*(*uint64)(unsafe.Pointer(&b[off])))
			off += 8
			usar.VolumMeasure.UplinkVolume = (*(*uint64)(unsafe.Pointer(&b[off])))
			off += 8
			usar.VolumMeasure.DownlinkVolume = (*(*uint64)(unsafe.Pointer(&b[off])))
			off += 8
			usar.VolumMeasure.TotalPktNum = (*(*uint64)(unsafe.Pointer(&b[off])))
			off += 8
			usar.VolumMeasure.UplinkPktNum = (*(*uint64)(unsafe.Pointer(&b[off])))
			off += 8
			usar.VolumMeasure.DownlinkPktNum = (*(*uint64)(unsafe.Pointer(&b[off])))
			off += 8

			usar.QueryUrrRef = (*(*uint32)(unsafe.Pointer(&b[off])))
			off += 4

			v := (*(*uint64)(unsafe.Pointer(&b[off])))
			usar.StartTime = time.Unix(0, int64(v))
			off += 8

			v = (*(*uint64)(unsafe.Pointer(&b[off])))
			usar.EndTime = time.Unix(0, int64(v))
			off += 8

			usars = append(usars, usar)
		}
		return msgtype, seid, 0, 0, nil, usars, nil
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
