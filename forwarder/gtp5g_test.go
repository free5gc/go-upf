package forwarder

import (
	"net"
	"testing"
	"time"

	"github.com/wmnsk/go-pfcp/ie"
)

func TestGtp5g_CreateRules(t *testing.T) {
	g, err := OpenGtp5g()
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()

	far := ie.NewCreateFAR(
		ie.NewFARID(1),
		ie.NewApplyAction(0x2),
		ie.NewForwardingParameters(
			ie.NewDestinationInterface(ie.DstInterfaceAccess),
			ie.NewNetworkInstance("internet"),
			ie.NewOuterHeaderCreation(
				0x0500,    // OuterHeaderCreationDescription
				4,         // TEID
				"5.6.7.8", // IPv4
				"",        // IPv6
				9,         // port number
				0,         // C-TAG only N6
				0,         // S-TAG only N6
			),
			ie.NewForwardingPolicy("10"),
		),
	)

	err = g.CreateFAR(far)
	if err != nil {
		t.Fatal(err)
	}

	qer := ie.NewCreateQER(
		ie.NewQERID(1),
		ie.NewQERCorrelationID(0x11111111),
		ie.NewGateStatus(ie.GateStatusOpen, ie.GateStatusClosed),
		ie.NewMBR(0x1111111111, 0x2222222222),
		ie.NewGBR(0x3333333333, 0x4444444444),
		ie.NewQFI(0x0a),
		ie.NewRQI(0x02),
		ie.NewPagingPolicyIndicator(1),
		ie.NewAveragingWindow(0xffffffff),
	)

	err = g.CreateQER(qer)
	if err != nil {
		t.Fatal(err)
	}

	pdr := ie.NewCreatePDR(
		ie.NewPDRID(1),
		ie.NewPrecedence(0x11111111),
		ie.NewPDI(
			ie.NewSourceInterface(ie.SrcInterfaceAccess),
			ie.NewFTEID(
				0x01,
				0x11111111,
				net.ParseIP("20.20.0.1"),
				nil,
				0,
			),
			ie.NewNetworkInstance("internet"),
			ie.NewUEIPAddress(
				0x02,
				"127.0.0.1",
				"",
				0,
				0,
			),
			ie.NewApplicationID(""),
		),
		ie.NewOuterHeaderRemoval(0, 0),
		ie.NewFARID(1),
		ie.NewQERID(1),
	)

	err = g.CreatePDR(pdr)
	if err != nil {
		t.Fatal(err)
	}

	time.Sleep(10 * time.Second)
}
