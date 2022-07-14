package forwarder

import (
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/wmnsk/go-pfcp/ie"

	"github.com/free5gc/go-upf/pkg/factory"
)

func TestGtp5g_CreateRules(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping testing in short mode")
	}

	var wg sync.WaitGroup
	g, err := OpenGtp5g(&wg, ":"+strconv.Itoa(factory.UpfGtpDefaultPort))
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()

	lSeid := uint64(0)
	t.Run("create rules", func(t *testing.T) {
		far := ie.NewCreateFAR(
			ie.NewFARID(2),
			ie.NewApplyAction(0x2),
			ie.NewForwardingParameters(
				ie.NewDestinationInterface(ie.DstInterfaceSGiLANN6LAN),
				ie.NewNetworkInstance("internet"),
			),
		)

		err = g.CreateFAR(lSeid, far)
		if err != nil {
			t.Fatal(err)
		}

		far = ie.NewCreateFAR(
			ie.NewFARID(4),
			ie.NewApplyAction(0x2),
		)

		err = g.CreateFAR(lSeid, far)
		if err != nil {
			t.Fatal(err)
		}

		qer := ie.NewCreateQER(
			ie.NewQERID(1),
			ie.NewGateStatus(ie.GateStatusOpen, ie.GateStatusOpen),
			ie.NewMBR(200000, 100000),
			ie.NewQFI(10),
		)

		err = g.CreateQER(lSeid, qer)
		if err != nil {
			t.Fatal(err)
		}

		urr := ie.NewCreateURR(
			ie.NewURRID(1),
			ie.NewMeasurementPeriod(10),
			ie.NewMeasurementMethod(0, 1, 0),
			ie.NewMeasurementInformation(4),
			ie.NewVolumeThreshold(7, 10000, 20000, 30000),
			ie.NewVolumeQuota(7, 40000, 50000, 60000),
		)

		err = g.CreateURR(lSeid, urr)
		if err != nil {
			t.Fatal(err)
		}

		pdr := ie.NewCreatePDR(
			ie.NewPDRID(1),
			ie.NewPrecedence(255),
			ie.NewPDI(
				ie.NewSourceInterface(ie.SrcInterfaceAccess),
				ie.NewFTEID(
					0x01,
					1,
					net.ParseIP("30.30.30.2"),
					nil,
					0,
				),
				ie.NewNetworkInstance(""),
				ie.NewUEIPAddress(
					0x02,
					"60.60.0.1",
					"",
					0,
					0,
				),
			),
			ie.NewOuterHeaderRemoval(0, 0),
			ie.NewFARID(2),
			ie.NewQERID(1),
			ie.NewURRID(1),
		)

		err = g.CreatePDR(lSeid, pdr)
		if err != nil {
			t.Fatal(err)
		}

		pdr = ie.NewCreatePDR(
			ie.NewPDRID(3),
			ie.NewPrecedence(255),
			ie.NewPDI(
				ie.NewSourceInterface(ie.SrcInterfaceCore),
				ie.NewNetworkInstance("internet"),
				ie.NewUEIPAddress(
					0x02,
					"60.60.0.1",
					"",
					0,
					0,
				),
			),
			ie.NewFARID(4),
			ie.NewQERID(1),
			ie.NewURRID(1),
		)

		err = g.CreatePDR(lSeid, pdr)
		if err != nil {
			t.Fatal(err)
		}
	})

	t.Run("update rules", func(t *testing.T) {
		far := ie.NewUpdateFAR(
			ie.NewFARID(4),
			ie.NewApplyAction(0x2),
			ie.NewUpdateForwardingParameters(
				ie.NewDestinationInterface(ie.DstInterfaceAccess),
				ie.NewNetworkInstance("internet"),
				ie.NewOuterHeaderCreation(
					0x0100,
					1,
					"30.30.30.1",
					"",
					0,
					0,
					0,
				),
			),
		)

		err = g.UpdateFAR(lSeid, far)
		if err != nil {
			t.Fatal(err)
		}

		pdr := ie.NewUpdatePDR(
			ie.NewPDRID(3),
			ie.NewPrecedence(255),
			ie.NewPDI(
				ie.NewSourceInterface(ie.SrcInterfaceCore),
				ie.NewNetworkInstance("internet"),
				ie.NewUEIPAddress(
					0x02,
					"60.60.0.1",
					"",
					0,
					0,
				),
			),
			ie.NewFARID(4),
		)

		err = g.UpdatePDR(lSeid, pdr)
		if err != nil {
			t.Fatal(err)
		}
	})

	time.Sleep(10 * time.Second)
}
