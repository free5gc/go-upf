package pfcp

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	"github.com/free5gc/go-upf/internal/forwarder"
	"github.com/free5gc/go-upf/internal/report"
	"github.com/free5gc/go-upf/pkg/factory"
	logger_util "github.com/free5gc/util/logger"
)

func newTestPfcpServer() *PfcpServer {
	return NewPfcpServer(
		&factory.Config{
			Pfcp: &factory.Pfcp{
				Addr:   "127.0.0.1",
				NodeID: "127.0.0.1",
			},
		},
		forwarder.Empty{},
	)
}

func TestNewPfcpServerInitializesLocalNode(t *testing.T) {
	s := newTestPfcpServer()

	assert.NotNil(t, s.localNode)
	assert.Equal(t, "127.0.0.1", s.localNode.NodeID)
	assert.False(t, s.localNode.RecoveryTime.IsZero())
	assert.NotNil(t, s.localNode.associations)
	assert.NotNil(t, s.localNode.sessions)
	assert.Equal(t, forwarder.Empty{}, s.localNode.datapath)
	assert.Same(t, s.log, s.localNode.log)
}

func TestStart(t *testing.T) {
}

func TestStop(t *testing.T) {
	s := &PfcpServer{
		log: logrus.WithField(logger_util.FieldControlPlaneNodeID, "127.0.0.1"),
	}

	addr, err := net.ResolveUDPAddr("udp4", "127.0.0.1:0")
	if err != nil {
		t.Errorf("failed to resolve UDP address: %v", err)
		return
	}
	s.conn, err = net.ListenUDP("udp4", addr)
	if err != nil {
		t.Errorf("expected err to be nil, but got %v", err)
	}

	if s.conn == nil {
		t.Errorf("expected s.conn not to be nil")
		return
	}

	s.Stop()

	if !isConnClosed(s.conn) {
		t.Errorf("expected connection to be closed")
	}
}

func TestNotifySessReport(t *testing.T) {
	s := &PfcpServer{
		srCh: make(chan report.SessReport),
	}

	reports := []report.Report{}

	sr := report.SessReport{
		SEID:    1,
		Reports: reports,
	}

	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		receivedSr := <-s.srCh
		assert.EqualValues(t, sr, receivedSr)
	}()

	s.NotifySessReport(sr)

	wg.Wait()
}

func TestNotifyTransTimeout(t *testing.T) {
	s := &PfcpServer{
		trToCh: make(chan TransactionTimeout),
	}
	txId := "127.0.0.1-1"

	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		receivedSeid := <-s.trToCh
		assert.EqualValues(t, TransactionTimeout{TrType: TX, TrID: txId}, receivedSeid)
	}()

	s.NotifyTransTimeout(TX, txId)

	wg.Wait()
}

func isConnClosed(conn *net.UDPConn) bool {
	oneByte := make([]byte, 1)
	err := conn.SetReadDeadline(time.Now())
	if err != nil {
		return true
	}
	_, err = conn.Read(oneByte)
	if err != nil {
		netErr, ok := err.(net.Error)
		if ok && netErr.Timeout() {
			// The read timed out, which means the connection is still open
			return false
		}
		// Any other error means the connection is closed
		return true
	}

	// If we were able to read a byte, the connection is definitely open
	return false
}
