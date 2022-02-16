package pfcp

import (
	"encoding/hex"
	"fmt"
	"net"
	"runtime/debug"
	"sync"
	"time"

	"github.com/free5gc/go-upf/internal/forwarder"
	"github.com/free5gc/go-upf/internal/logger"
	"github.com/free5gc/go-upf/pkg/factory"
)

type upf interface {
	Config() *factory.Config
}

type PfcpServer struct {
	upf

	listen       string
	conn         *net.UDPConn
	recoveryTime time.Time
	driver       forwarder.Driver
	nodes        sync.Map
}

func NewPfcpServer(listen string, driver forwarder.Driver) *PfcpServer {
	return &PfcpServer{
		listen:       listen,
		recoveryTime: time.Now(),
		driver:       driver,
	}
}

func (s *PfcpServer) main(wg *sync.WaitGroup) {
	defer func() {
		if p := recover(); p != nil {
			// Print stack for panic to log. Fatalf() will let program exit.
			logger.PfcpLog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
		}

		logger.PfcpLog.Infoln(s.listen, "pfcp server stopped")
		wg.Done()
	}()

	listen := fmt.Sprintf("%s:%d", s.listen, factory.UpfPfcpDefaultPort)
	logger.PfcpLog.Infof("PFCP Address: %q", listen)
	laddr, err := net.ResolveUDPAddr("udp", listen)
	if err != nil {
		logger.PfcpLog.Errorf("Resolve err: %+v", err)
		return
	}

	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		logger.PfcpLog.Errorf("Listen err: %+v", err)
		return
	}
	s.conn = conn

	buf := make([]byte, 1500)
	for {
		n, addr, err1 := s.conn.ReadFrom(buf)
		if err1 != nil {
			logger.PfcpLog.Errorf("%+v", err1)
			break
		}
		err1 = s.dispacher(buf[:n], addr)
		if err1 != nil {
			logger.PfcpLog.Errorln(err1)
			logger.PfcpLog.Tracef("ignored undecodable message:\n%+v", hex.Dump(buf))
		}
	}
}

func (s *PfcpServer) Start(wg *sync.WaitGroup) {
	logger.PfcpLog.Infoln(s.listen, "starting")
	wg.Add(1)
	go s.main(wg)
	logger.PfcpLog.Infoln(s.listen, "started")
}

func (s *PfcpServer) Terminate() {
	logger.PfcpLog.Infoln(s.listen, "Stopping pfcp server")
	if s.conn != nil {
		err := s.conn.Close()
		if err != nil {
			logger.PfcpLog.Errorf("%s Stop pfcp server err: %+v", s.listen, err)
		}
	}
}
