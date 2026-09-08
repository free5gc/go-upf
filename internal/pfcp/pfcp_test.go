package pfcp

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/wmnsk/go-pfcp/message"

	"github.com/free5gc/go-upf/internal/forwarder"
	"github.com/free5gc/go-upf/internal/report"
	"github.com/free5gc/go-upf/pkg/factory"
	logger_util "github.com/free5gc/util/logger"
)

type messageTransportMock struct {
	req     message.Message
	reqAddr net.Addr
	rsp     message.Message
	rspAddr net.Addr
}

func (m *messageTransportMock) sendReqTo(msg message.Message, addr net.Addr) error {
	m.req = msg
	m.reqAddr = addr
	return nil
}

func (m *messageTransportMock) sendRspTo(msg message.Message, addr net.Addr) error {
	m.rsp = msg
	m.rspAddr = addr
	return nil
}

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

func TestNewPfcpServerInitializesDispatcher(t *testing.T) {
	s := newTestPfcpServer()

	assert.NotNil(t, s.dispatcher)
	assert.Same(t, s, s.dispatcher.transport)
	assert.NotNil(t, s.dispatcher.node)
	assert.Equal(t, "127.0.0.1", s.dispatcher.node.NodeID)
	assert.False(t, s.dispatcher.node.RecoveryTime.IsZero())
	assert.NotNil(t, s.dispatcher.node.associations)
	assert.NotNil(t, s.dispatcher.node.sessions)
	assert.Equal(t, forwarder.Empty{}, s.dispatcher.node.datapath)
	assert.Same(t, s.log, s.dispatcher.log)
	assert.Same(t, s.log, s.dispatcher.node.log)
}

func TestDispatcherDispatchesHeartbeatRequest(t *testing.T) {
	recoveryTime := time.Unix(1_700_000_000, 0)
	log := logrus.WithField("test", t.Name())
	node := NewLocalNode("127.0.0.1", recoveryTime, forwarder.Empty{}, log)
	transport := &messageTransportMock{}
	dispatcher := newDispatcher(node, transport, log)
	addr := &net.UDPAddr{IP: net.IPv4(10, 100, 200, 5), Port: 8805}
	req := message.NewHeartbeatRequest(42, nil, nil)

	err := dispatcher.HandleRequest(req, addr)

	assert.NoError(t, err)
	assert.Equal(t, addr, transport.rspAddr)
	rsp, ok := transport.rsp.(*message.HeartbeatResponse)
	assert.True(t, ok)
	if !ok {
		return
	}
	assert.Equal(t, uint32(42), rsp.SequenceNumber)
	gotRecoveryTime, err := rsp.RecoveryTimeStamp.RecoveryTimeStamp()
	assert.NoError(t, err)
	assert.Equal(t, recoveryTime, gotRecoveryTime)
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
