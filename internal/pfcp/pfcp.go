package pfcp

import (
	"encoding/hex"
	"fmt"
	"net"
	"runtime/debug"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/wmnsk/go-pfcp/message"

	"github.com/free5gc/go-upf/internal/forwarder"
	"github.com/free5gc/go-upf/internal/logger"
	"github.com/free5gc/go-upf/internal/report"
	"github.com/free5gc/go-upf/pkg/factory"
)

const (
	RECEIVE_CHANNEL_LEN       = 512
	REPORT_CHANNEL_LEN        = 64
	TRANS_TIMEOUT_CHANNEL_LEN = 64
	MAX_PFCP_MSG_LEN          = 1500
)

type ReceivePacket struct {
	RemoteAddr net.Addr
	Buf        []byte
}

type TransType int

const (
	TX TransType = iota
	RX
)

type TransactionTimeout struct {
	TransType TransType
	TransID   string
	Seq       uint32
}

type Response struct {
	RemoteAddr net.Addr
	Msg        message.Message
}

type PfcpServer struct {
	cfg          *factory.Config
	listen       string
	nodeID       string
	rcvCh        chan ReceivePacket
	srCh         chan report.SessReport
	trToCh       chan TransactionTimeout
	conn         *net.UDPConn
	recoveryTime time.Time
	driver       forwarder.Driver
	lnode        LocalNode
	rnodes       map[string]*RemoteNode
	trans        map[string]*Transaction // key: RemoteAddr
	log          *logrus.Entry
}

func NewPfcpServer(cfg *factory.Config, driver forwarder.Driver) *PfcpServer {
	listen := fmt.Sprintf("%s:%d", cfg.Pfcp.Addr, factory.UpfPfcpDefaultPort)
	return &PfcpServer{
		cfg:          cfg,
		listen:       listen,
		nodeID:       cfg.Pfcp.NodeID,
		rcvCh:        make(chan ReceivePacket, RECEIVE_CHANNEL_LEN),
		srCh:         make(chan report.SessReport, REPORT_CHANNEL_LEN),
		trToCh:       make(chan TransactionTimeout, TRANS_TIMEOUT_CHANNEL_LEN),
		recoveryTime: time.Now(),
		driver:       driver,
		rnodes:       make(map[string]*RemoteNode),
		trans:        make(map[string]*Transaction),
		log:          logger.PfcpLog.WithField(logger.FieldListenAddr, listen),
	}
}

func (s *PfcpServer) main(wg *sync.WaitGroup) {
	defer func() {
		if p := recover(); p != nil {
			// Print stack for panic to log. Fatalf() will let program exit.
			s.log.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
		}

		s.log.Infoln("pfcp server stopped")
		for _, tr := range s.trans {
			tr.stopAllTimers()
		}
		close(s.rcvCh)
		close(s.srCh)
		close(s.trToCh)
		wg.Done()
	}()

	var err error
	laddr, err := net.ResolveUDPAddr("udp", s.listen)
	if err != nil {
		s.log.Errorf("Resolve err: %+v", err)
		return
	}

	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		s.log.Errorf("Listen err: %+v", err)
		return
	}
	s.conn = conn

	wg.Add(1)
	go s.receiver(wg)

	for {
		select {
		case sr := <-s.srCh:
			s.ServeReport(&sr)
		case rcvPkt := <-s.rcvCh:
			if len(rcvPkt.Buf) == 0 {
				// receiver closed
				return
			}
			msg, err := message.Parse(rcvPkt.Buf)
			if err != nil {
				s.log.Errorln(err)
				s.log.Tracef("ignored undecodable message:\n%+v", hex.Dump(rcvPkt.Buf))
				continue
			}

			// find transaction
			addrStr := rcvPkt.RemoteAddr.String()
			tr, ok := s.trans[addrStr]
			if !ok {
				tr = NewTransaction(s, rcvPkt.RemoteAddr)
				s.trans[addrStr] = tr
			}

			if isRequest(msg) {
				needDispatch, err1 := tr.rxRecv(msg)
				if err1 != nil {
					s.log.Warnf("rcvCh: tr[%s]: %v", tr.raddr, err1)
					continue
				} else if !needDispatch {
					s.log.Debugf("rcvCh: no need to dispatch")
					continue
				}
			} else if isResponse(msg) {
				err1 := tr.txRecv(msg)
				if err1 != nil {
					s.log.Warnf("rcvCh: tr[%s]: %v", tr.raddr, err1)
					continue
				}
			}

			err = s.dispacher(msg, rcvPkt.RemoteAddr)
			if err != nil {
				s.log.Errorln(err)
				s.log.Tracef("ignored undecodable message:\n%+v", hex.Dump(rcvPkt.Buf))
			}
		case trTo := <-s.trToCh:
			// find transaction
			tr, ok := s.trans[trTo.TransID]
			if !ok {
				s.log.Warnf("trToCh: tr[%s] not found", trTo.TransID)
				continue
			}

			if trTo.TransType == TX {
				tr.handleTxTimeout(trTo.Seq)
			} else { // RX
				tr.handleRxTimeout(trTo.Seq)
			}
		}
	}
}

func (s *PfcpServer) receiver(wg *sync.WaitGroup) {
	defer func() {
		if p := recover(); p != nil {
			// Print stack for panic to log. Fatalf() will let program exit.
			s.log.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
		}

		s.log.Infoln("pfcp reciver stopped")
		wg.Done()
	}()

	buf := make([]byte, MAX_PFCP_MSG_LEN)
	for {
		n, addr, err := s.conn.ReadFrom(buf)
		if err != nil {
			s.log.Errorf("%+v", err)
			s.rcvCh <- ReceivePacket{}
			break
		}
		s.rcvCh <- ReceivePacket{
			RemoteAddr: addr,
			Buf:        buf[:n],
		}
	}
}

func (s *PfcpServer) Start(wg *sync.WaitGroup) {
	s.log.Infoln("starting pfcp server")
	wg.Add(1)
	go s.main(wg)
	s.log.Infoln("pfcp server started")
}

func (s *PfcpServer) Stop() {
	s.log.Infoln("Stopping pfcp server")
	if s.conn != nil {
		err := s.conn.Close()
		if err != nil {
			s.log.Errorf("Stop pfcp server err: %+v", err)
		}
	}
}

func (s *PfcpServer) NewNode(id string, driver forwarder.Driver) *RemoteNode {
	n := NewRemoteNode(
		id,
		&s.lnode,
		driver,
		s.log.WithField(logger.FieldRemoteNodeID, "rNodeID:"+id),
	)
	n.log.Infoln("New node")
	return n
}

func (s *PfcpServer) UpdateNodeID(n *RemoteNode, newId string) {
	s.log.Infof("Update nodeId %q to %q", n.ID, newId)
	delete(s.rnodes, n.ID)
	n.ID = newId
	n.log = s.log.WithField(logger.FieldRemoteNodeID, "rNodeID:"+newId)
	s.rnodes[newId] = n
}

func (s *PfcpServer) NotifySessReport(sr report.SessReport) {
	s.srCh <- sr
}

func (s *PfcpServer) NotifyTransTimeout(transType TransType, transID string, seq uint32) {
	s.trToCh <- TransactionTimeout{TransType: transType, TransID: transID, Seq: seq}
}

func (s *PfcpServer) PopBufPkt(seid uint64, pdrid uint16) ([]byte, bool) {
	sess, err := s.lnode.Sess(seid)
	if err != nil {
		s.log.Errorln(err)
		return nil, false
	}
	return sess.Pop(pdrid)
}

func (s *PfcpServer) sendReqTo(msg message.Message, addr net.Addr, rspCh chan<- Response) error {
	if !isRequest(msg) {
		return errors.Errorf("sendReqTo: invalid req type(%d)", msg.MessageType())
	}

	// find transaction
	addrStr := addr.String()
	tr, ok := s.trans[addrStr]
	if !ok {
		tr = NewTransaction(s, addr)
		s.trans[addrStr] = tr
	}

	return tr.txSend(msg, rspCh)
}

func (s *PfcpServer) sendRspTo(msg message.Message, addr net.Addr) error {
	if !isResponse(msg) {
		return errors.Errorf("sendRspTo: invalid rsp type(%d)", msg.MessageType())
	}

	// find transaction
	addrStr := addr.String()
	tr, ok := s.trans[addrStr]
	if !ok {
		return errors.Errorf("sendRspTo: tr(%s) not found", addrStr)
	}

	return tr.rxSend(msg)
}

func isRequest(msg message.Message) bool {
	switch msg.MessageType() {
	case message.MsgTypeHeartbeatRequest:
		return true
	case message.MsgTypePFDManagementRequest:
		return true
	case message.MsgTypeAssociationSetupRequest:
		return true
	case message.MsgTypeAssociationUpdateRequest:
		return true
	case message.MsgTypeAssociationReleaseRequest:
		return true
	case message.MsgTypeNodeReportRequest:
		return true
	case message.MsgTypeSessionSetDeletionRequest:
		return true
	case message.MsgTypeSessionEstablishmentRequest:
		return true
	case message.MsgTypeSessionModificationRequest:
		return true
	case message.MsgTypeSessionDeletionRequest:
		return true
	case message.MsgTypeSessionReportRequest:
		return true
	default:
	}
	return false
}

func isResponse(msg message.Message) bool {
	switch msg.MessageType() {
	case message.MsgTypeHeartbeatResponse:
		return true
	case message.MsgTypePFDManagementResponse:
		return true
	case message.MsgTypeAssociationSetupResponse:
		return true
	case message.MsgTypeAssociationUpdateResponse:
		return true
	case message.MsgTypeAssociationReleaseResponse:
		return true
	case message.MsgTypeNodeReportResponse:
		return true
	case message.MsgTypeSessionSetDeletionResponse:
		return true
	case message.MsgTypeSessionEstablishmentResponse:
		return true
	case message.MsgTypeSessionModificationResponse:
		return true
	case message.MsgTypeSessionDeletionResponse:
		return true
	case message.MsgTypeSessionReportResponse:
		return true
	default:
	}
	return false
}
