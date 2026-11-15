package pfcp

import (
	"encoding/binary"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"

	"github.com/free5gc/go-upf/internal/forwarder"
	"github.com/free5gc/go-upf/internal/report"
	"github.com/free5gc/go-upf/pkg/factory"
	logger_util "github.com/free5gc/util/logger"
)

type PfcpServerMock struct {
	PfcpServer
}

func (p *PfcpServerMock) GetRNodes() map[string]*RemoteNode {
	return p.rnodes
}

func (p *PfcpServerMock) AddRNode(rnodeid string, node *RemoteNode) {
	p.rnodes[rnodeid] = node
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

func TestNewNode(t *testing.T) {
	s := &PfcpServer{
		log: logrus.WithField(logger_util.FieldControlPlaneNodeID, "127.0.0.1"),
	}

	id := "smf1"
	driver := forwarder.Empty{}
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:8805")
	if err != nil {
		t.Errorf("failed to resolve UDP address: %v", err)
		return
	}

	newNode := s.NewNode(id, addr, driver)

	assert.NotNil(t, newNode)
	assert.Equal(t, id, newNode.ID)
}

func TestUpdateNodeID(t *testing.T) {
	s := &PfcpServerMock{
		PfcpServer: PfcpServer{
			log:    logrus.WithField(logger_util.FieldControlPlaneNodeID, "127.0.0.1"),
			rnodes: make(map[string]*RemoteNode),
		},
	}

	origNodeId := "127.0.0.1"
	node := s.NewNode(origNodeId, nil, nil)
	s.AddRNode(origNodeId, node)

	newNodeId := "192.168.56.101"
	s.UpdateNodeID(node, newNodeId)

	assert.Nil(t, s.GetRNodes()[origNodeId])
	assert.NotNil(t, s.GetRNodes()[newNodeId])
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

// TS 29.244 7.6.2: a message of an unsupported PFCP version is answered with a PFCP Version Not Supported Response.
// TS 29.244 7.6.3: a request in a datagram whose length disagrees with the Message Length of its header is answered
// with the Response of Cause "Invalid length".
func TestVersionAndLengthErrors(t *testing.T) {
	marshal := func(m message.Message) []byte {
		b := make([]byte, m.MarshalLen())
		require.NoError(t, m.MarshalTo(b))
		return b
	}
	version2 := marshal(message.NewHeartbeatRequest(6, ie.NewRecoveryTimeStamp(time.Now()), nil))
	version2[0] = version2[0]&0x1f | 2<<5

	cfg := &factory.Config{Pfcp: &factory.Pfcp{Addr: "127.0.0.1", NodeID: "127.0.0.1", RetransTimeout: time.Minute}}
	s := NewPfcpServer(cfg, forwarder.Empty{})
	s.listen = freeUDPAddr(t).String()
	var wg sync.WaitGroup
	s.Start(&wg)
	t.Cleanup(func() {
		s.Stop()
		wg.Wait()
	})
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, peer.Close()) })
	upf, err := net.ResolveUDPAddr("udp4", s.listen)
	require.NoError(t, err)

	// The server starts asynchronously: send Heartbeat Requests until one is answered, then drop late answers.
	buf := make([]byte, MAX_PFCP_MSG_LEN)
	for seq := uint32(1); ; seq++ {
		require.Less(t, seq, uint32(50), "no answer")
		_, err = peer.WriteToUDP(marshal(message.NewHeartbeatRequest(seq, ie.NewRecoveryTimeStamp(time.Now()), nil)), upf)
		require.NoError(t, err)
		require.NoError(t, peer.SetReadDeadline(time.Now().Add(100*time.Millisecond)))
		if _, _, err = peer.ReadFromUDP(buf); err == nil {
			break
		}
	}
	for err == nil {
		require.NoError(t, peer.SetReadDeadline(time.Now().Add(100*time.Millisecond)))
		_, _, err = peer.ReadFromUDP(buf)
	}

	exchange := func(t *testing.T, req []byte) message.Message {
		_, werr := peer.WriteToUDP(req, upf)
		require.NoError(t, werr)
		require.NoError(t, peer.SetReadDeadline(time.Now().Add(time.Second)))
		n, _, rerr := peer.ReadFromUDP(buf)
		require.NoError(t, rerr, "no answer")
		rsp, perr := message.Parse(buf[:n])
		require.NoError(t, perr)
		return rsp
	}
	silence := func(t *testing.T) {
		require.NoError(t, peer.SetReadDeadline(time.Now().Add(200*time.Millisecond)))
		_, _, rerr := peer.ReadFromUDP(buf)
		require.ErrorIs(t, rerr, os.ErrDeadlineExceeded, "answered")
	}

	t.Run("unsupported version", func(t *testing.T) {
		msg := exchange(t, version2)
		rsp, ok := msg.(*message.VersionNotSupportedResponse)
		require.True(t, ok, "answered %T", msg)
		require.Equal(t, 1, rsp.Version())
	})
	t.Run("Version Not Supported Response of another version", func(t *testing.T) {
		rsp := marshal(message.NewVersionNotSupportedResponse(0))
		rsp[0] = rsp[0]&0x1f | 2<<5
		_, err = peer.WriteToUDP(rsp, upf)
		require.NoError(t, err)
		silence(t)
	})
	nodeID := ie.NewNodeID("127.0.0.2", "", "")
	fseid := ie.NewFSEID(0x1234, net.IPv4(127, 0, 0, 2), nil)
	recovery := ie.NewRecoveryTimeStamp(time.Now())
	far := ie.NewUpdateFAR(ie.NewFARID(1), ie.NewApplyAction(0x01))
	for _, tc := range []struct {
		name     string
		req      message.Message
		nodeID   bool
		trailing bool
	}{
		{"Association Setup", message.NewAssociationSetupRequest(7, nodeID, recovery), true, false},
		{"Association Update", message.NewAssociationUpdateRequest(8, nodeID), true, true},
		{"Association Release", message.NewAssociationReleaseRequest(9, nodeID), true, false},
		{"Session Establishment", message.NewSessionEstablishmentRequest(0, 0, 0, 10, 0, nodeID, fseid), true, true},
		{"Session Modification", message.NewSessionModificationRequest(0, 0, 0x1234, 11, 0, far), false, false},
		{"Session Deletion", message.NewSessionDeletionRequest(0, 0, 0x1234, 12, 0), false, true},
	} {
		t.Run(tc.name+" Request of an inconsistent length", func(t *testing.T) {
			req := marshal(tc.req)
			if tc.trailing {
				req = append(req, 0, 0)
			} else {
				binary.BigEndian.PutUint16(req[2:], uint16(len(req)-4+100))
			}
			msg := exchange(t, req)
			require.Equal(t, tc.req.MessageType()+1, msg.MessageType(), "answered %T", msg)
			require.Equal(t, tc.req.Sequence(), msg.Sequence())
			require.Equal(t, uint64(0), msg.SEID())
			var c, id *ie.IE
			switch rsp := msg.(type) {
			case *message.AssociationSetupResponse:
				c, id = rsp.Cause, rsp.NodeID
			case *message.AssociationUpdateResponse:
				c, id = rsp.Cause, rsp.NodeID
			case *message.AssociationReleaseResponse:
				c, id = rsp.Cause, rsp.NodeID
			case *message.SessionEstablishmentResponse:
				c, id = rsp.Cause, rsp.NodeID
			case *message.SessionModificationResponse:
				c = rsp.Cause
			case *message.SessionDeletionResponse:
				c = rsp.Cause
			}
			require.NotNil(t, c)
			v, err := c.Cause()
			require.NoError(t, err)
			require.Equal(t, ie.CauseInvalidLength, v)
			require.Equal(t, tc.nodeID, id != nil)
			silence(t)
		})
	}
}
