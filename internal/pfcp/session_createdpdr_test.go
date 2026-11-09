package pfcp

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"

	"github.com/free5gc/go-upf/internal/forwarder"
	"github.com/free5gc/go-upf/pkg/factory"
)

// createdPDRTestDriver mirrors the production gtp5g driver's behavior of
// populating PDRPlan.OriginalIE and PDRID; forwarder.Empty leaves both zero.
type createdPDRTestDriver struct {
	forwarder.Empty
}

func (createdPDRTestDriver) BuildCreatePDRPlan(lSeid uint64, req *ie.IE) (*forwarder.PDRPlan, error) {
	return &forwarder.PDRPlan{
		OriginalIE: req,
		PDRID:      getPDRIDFromPDR(req),
	}, nil
}

func newCreatedPDRFixture(t *testing.T) (*PfcpServer, *net.UDPConn) {
	t.Helper()
	d := &createdPDRTestDriver{}
	s := NewPfcpServer(&factory.Config{Pfcp: &factory.Pfcp{
		Addr: "127.0.0.1", NodeID: "127.0.0.1", RetransTimeout: time.Minute,
	}}, d)
	var err error
	s.conn, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.conn.Close()) })
	t.Cleanup(s.stopTrTimers)
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.2")})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, peer.Close()) })
	owner := s.NewNode("127.0.0.2", &net.UDPAddr{IP: net.ParseIP("127.0.0.2"), Port: 8805}, d)
	s.rnodes[owner.ID] = owner
	return s, peer
}

// TestSessionEstablishmentCreatedPDRUEIPAddress is a regression test for the
// Created PDR / UE IP Address IE conditional-inclusion bug (free5gc/go-upf
// issue #65, TS 29.244 7.5.3.2 / 5.21): the UP function must only echo the
// UE IP Address back in Created PDR when the CP delegated allocation to the
// UP via the CHV4/CHV6 flag, never when the CP already supplied an address.
func TestSessionEstablishmentCreatedPDRUEIPAddress(t *testing.T) {
	const (
		flagV4   uint8 = 1 << 1 // V4
		flagCHV4 uint8 = 1 << 4 // CHV4 ("Choose", CP delegates allocation to UP)
	)

	for _, tc := range []struct {
		name string
		pdi  []*ie.IE
	}{
		{
			name: "CP-allocated address must not be echoed back",
			pdi: []*ie.IE{
				ie.NewSourceInterface(ie.SrcInterfaceAccess),
				ie.NewUEIPAddress(flagV4, "10.60.0.1", "", 0, 0),
			},
		},
		{
			name: "CP-delegated allocation is skipped, not fabricated, when no allocator exists",
			pdi: []*ie.IE{
				ie.NewSourceInterface(ie.SrcInterfaceAccess),
				ie.NewUEIPAddress(flagCHV4, "", "", 0, 0),
			},
		},
		{
			name: "no UE IP Address IE at all",
			pdi: []*ie.IE{
				ie.NewSourceInterface(ie.SrcInterfaceAccess),
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, peer := newCreatedPDRFixture(t)
			req := message.NewSessionEstablishmentRequest(0, 0, 0, 1, 0,
				ie.NewNodeID("127.0.0.2", "", ""),
				ie.NewFSEID(0x4321, net.ParseIP("127.0.0.2"), nil),
				ie.NewCreatePDR(
					ie.NewPDRID(1),
					ie.NewPrecedence(100),
					ie.NewPDI(tc.pdi...),
				),
			)
			msg := exchangePeerGuardRequest(t, s, peer, req)
			rsp, ok := msg.(*message.SessionEstablishmentResponse)
			require.True(t, ok)
			require.NotNil(t, rsp.Cause)
			cause, err := rsp.Cause.Cause()
			require.NoError(t, err)
			require.Equal(t, ie.CauseRequestAccepted, cause)

			// None of these cases has a CP that delegated allocation to an
			// implemented allocator, so Created PDR must never appear.
			require.Empty(t, rsp.CreatedPDR)
		})
	}
}
