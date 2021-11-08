package pfcp

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/m-asama/upf/factory"
	"github.com/m-asama/upf/forwarder"
	"github.com/m-asama/upf/logger"
)

type PfcpServer struct {
	listen       string
	conn         *net.UDPConn
	done         chan bool
	running      bool
	recoveryTime time.Time
	driver       forwarder.Driver
	nodes        sync.Map
}

func NewPfcpServer(listen string, driver forwarder.Driver) *PfcpServer {
	return &PfcpServer{
		listen:       listen,
		done:         make(chan bool),
		running:      false,
		recoveryTime: time.Now(),
		driver:       driver,
	}
}

func (s *PfcpServer) main(startDispacher chan bool) {
	listen := fmt.Sprintf("%s:%s", s.listen, factory.UPF_DEFAULT_PORT)
	laddr, err := net.ResolveUDPAddr("udp", listen)
	if err != nil {
		logger.PfcpLog.Errorf("%+v", err)
		startDispacher <- false
		return
	}

	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		logger.PfcpLog.Errorf("%+v", err)
		startDispacher <- false
		return
	}

	s.conn = conn

	startDispacher <- true
	s.running = true

	<-s.done
	logger.PfcpLog.Infoln(s.listen, "closing udp connection")
	s.conn.Close()
	logger.PfcpLog.Infoln(s.listen, "closed udp connection")
	logger.PfcpLog.Infoln(s.listen, "main exit")
}

func (s *PfcpServer) Start() {
	logger.PfcpLog.Infoln(s.listen, "starting")
	startDispacher := make(chan bool)
	go s.main(startDispacher)
	go s.dispacher(startDispacher)
	logger.PfcpLog.Infoln(s.listen, "started")
}

func (s *PfcpServer) Terminate() {
	logger.PfcpLog.Infoln(s.listen, "terminating")
	if s.running {
		s.done <- true
		s.running = false
		logger.PfcpLog.Infoln(s.listen, "terminated")
	} else {
		logger.PfcpLog.Infoln(s.listen, "terminate skipped")
	}
}
