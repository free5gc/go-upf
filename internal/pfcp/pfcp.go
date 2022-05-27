package pfcp

import (
	"encoding/hex"
	"fmt"
	"net"
	"runtime/debug"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/wmnsk/go-pfcp/message"

	"github.com/free5gc/go-upf/internal/forwarder"
	"github.com/free5gc/go-upf/internal/logger"
	"github.com/free5gc/go-upf/internal/report"
	"github.com/free5gc/go-upf/pkg/factory"
)

const (
	RECEIVE_CHANNEL_LEN = 512
	REPORT_CHANNEL_LEN  = 64
	MAX_PFCP_MSG_LEN    = 1500
)

type ReceiveMessage struct {
	RemoteAddr net.Addr
	Msg        []byte
}

type PfcpServer struct {
	listen       string
	nodeID       string
	rcvCh        chan ReceiveMessage
	srCh         chan report.SessReport
	conn         *net.UDPConn
	recoveryTime time.Time
	driver       forwarder.Driver
	lnode        LocalNode
	rnodes       map[string]*RemoteNode
	log          *logrus.Entry
}

func NewPfcpServer(listen, nodeID string, driver forwarder.Driver) *PfcpServer {
	listen = fmt.Sprintf("%s:%d", listen, factory.UpfPfcpDefaultPort)
	return &PfcpServer{
		listen:       listen,
		nodeID:       nodeID,
		rcvCh:        make(chan ReceiveMessage, RECEIVE_CHANNEL_LEN),
		srCh:         make(chan report.SessReport, REPORT_CHANNEL_LEN),
		recoveryTime: time.Now(),
		driver:       driver,
		rnodes:       make(map[string]*RemoteNode),
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
		close(s.rcvCh)
		close(s.srCh)
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
		case rcvMsg := <-s.rcvCh:
			if len(rcvMsg.Msg) == 0 {
				// receiver closed
				return
			}
			msg, err := message.Parse(rcvMsg.Msg)
			if err != nil {
				s.log.Errorln(err)
				s.log.Tracef("ignored undecodable message:\n%+v", hex.Dump(rcvMsg.Msg))
				continue
			}

			// TODO: rx transaction

			err = s.dispacher(msg, rcvMsg.RemoteAddr)
			if err != nil {
				s.log.Errorln(err)
				s.log.Tracef("ignored undecodable message:\n%+v", hex.Dump(rcvMsg.Msg))
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
			s.rcvCh <- ReceiveMessage{}
			break
		}
		s.rcvCh <- ReceiveMessage{
			RemoteAddr: addr,
			Msg:        buf[:n],
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

func (s *PfcpServer) PopBufPkt(seid uint64, pdrid uint16) ([]byte, bool) {
	sess, err := s.lnode.Sess(seid)
	if err != nil {
		s.log.Errorln(err)
		return nil, false
	}
	return sess.Pop(pdrid)
}

func (s *PfcpServer) sendMsgTo(msg message.Message, addr net.Addr) error {
	// TODO: tx transaction

	b := make([]byte, msg.MarshalLen())
	err := msg.MarshalTo(b)
	if err != nil {
		return err
	}

	_, err = s.conn.WriteTo(b, addr)
	if err != nil {
		return err
	}

	return nil
}
