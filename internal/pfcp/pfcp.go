package pfcp

import (
	"encoding/hex"
	"fmt"
	"net"
	"runtime/debug"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/free5gc/go-upf/internal/forwarder"
	"github.com/free5gc/go-upf/internal/logger"
	"github.com/free5gc/go-upf/pkg/factory"
)

type PfcpServer struct {
	listen       string
	conn         *net.UDPConn
	recoveryTime time.Time
	driver       forwarder.Driver
	nodes        map[string]*Node
	log          *logrus.Entry
}

func NewPfcpServer(listen string, driver forwarder.Driver) *PfcpServer {
	listen = fmt.Sprintf("%s:%d", listen, factory.UpfPfcpDefaultPort)
	return &PfcpServer{
		listen:       listen,
		recoveryTime: time.Now(),
		driver:       driver,
		nodes:        make(map[string]*Node),
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

	buf := make([]byte, 1500)
	for {
		n, addr, err := s.conn.ReadFrom(buf)
		if err != nil {
			s.log.Errorf("%+v", err)
			break
		}
		err = s.dispacher(buf[:n], addr)
		if err != nil {
			s.log.Errorln(err)
			s.log.Tracef("ignored undecodable message:\n%+v", hex.Dump(buf))
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

func (s *PfcpServer) NewNode(id string, driver forwarder.Driver) *Node {
	n := &Node{
		ID:     id,
		driver: driver,
		log:    s.log.WithField(logger.FieldNodeID, "NodeID:"+id),
	}
	n.log.Infoln("New node")
	return n
}
