package forwarder_test

import (
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"

	"github.com/free5gc/go-upf/internal/forwarder"
	"github.com/free5gc/go-upf/internal/pfcp"
	"github.com/free5gc/go-upf/internal/report"
	"github.com/free5gc/go-upf/pkg/factory"
)

type testHandler struct{}

var testSessRpts map[uint64]*report.SessReport // key: SEID

func (h *testHandler) NotifySessReport(sessRpt report.SessReport) {
	testSessRpts[sessRpt.SEID] = &sessRpt
}

func (h *testHandler) PopBufPkt(lSeid uint64, pdrid uint16) ([]byte, bool) {
	return nil, true
}

func TestGtp5g_CreateRules(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping testing in short mode")
	}

	var wg sync.WaitGroup
	g, err := forwarder.OpenGtp5g(&wg, ":"+strconv.Itoa(factory.UpfGtpDefaultPort), 1400)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()

	testSessRpts = make(map[uint64]*report.SessReport)
	g.HandleReport(&testHandler{})

	lSeid := uint64(1)
	handle := forwarder.NewSessionDatapath(g, lSeid)
	t.Run("create rules", func(t *testing.T) {
		req := &message.SessionModificationRequest{}

		far1 := ie.NewCreateFAR(
			ie.NewFARID(2),
			ie.NewApplyAction(0x2),
			ie.NewForwardingParameters(
				ie.NewDestinationInterface(ie.DstInterfaceSGiLANN6LAN),
				ie.NewNetworkInstance("internet"),
			),
		)
		req.CreateFAR = append(req.CreateFAR, far1)

		far2 := ie.NewCreateFAR(
			ie.NewFARID(4),
			ie.NewApplyAction(0x2),
		)
		req.CreateFAR = append(req.CreateFAR, far2)

		qer := ie.NewCreateQER(
			ie.NewQERID(1),
			ie.NewGateStatus(ie.GateStatusOpen, ie.GateStatusOpen),
			ie.NewMBR(200000, 100000),
			ie.NewQFI(10),
		)
		req.CreateQER = append(req.CreateQER, qer)

		rptTrig := report.ReportingTrigger{
			Flags: report.RPT_TRIG_PERIO,
		}
		urr1 := ie.NewCreateURR(
			ie.NewURRID(1),
			ie.NewMeasurementPeriod(1*time.Second),
			ie.NewMeasurementMethod(0, 1, 0),
			rptTrig.IE(),
			ie.NewMeasurementInformation(4),
		)
		req.CreateURR = append(req.CreateURR, urr1)

		rptTrig.Flags = report.RPT_TRIG_VOLTH | report.RPT_TRIG_VOLQU
		urr2 := ie.NewCreateURR(
			ie.NewURRID(2),
			ie.NewMeasurementMethod(0, 1, 0),
			rptTrig.IE(),
			ie.NewMeasurementInformation(4),
			ie.NewVolumeThreshold(7, 10000, 20000, 30000),
			ie.NewVolumeQuota(7, 40000, 50000, 60000),
		)
		req.CreateURR = append(req.CreateURR, urr2)

		pdr1 := ie.NewCreatePDR(
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
			ie.NewURRID(2),
		)
		req.CreatePDR = append(req.CreatePDR, pdr1)

		pdr2 := ie.NewCreatePDR(
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
		req.CreatePDR = append(req.CreatePDR, pdr2)

		changes, err := (&pfcp.Session{LocalID: lSeid}).ParseModificationChanges(req)
		require.NoError(t, err)
		_, err = handle.Establish(changes)
		if err != nil {
			t.Fatal(err)
		}

		time.Sleep(1100 * time.Millisecond)

		require.Contains(t, testSessRpts, lSeid)
		require.Equal(t, len(testSessRpts[lSeid].Reports), 1)
		require.Equal(t, testSessRpts[lSeid].Reports[0].(report.USAReport).URRID, uint32(1))
	})

	t.Run("update rules", func(t *testing.T) {
		req := &message.SessionModificationRequest{}

		rpt := report.ReportingTrigger{
			Flags: report.RPT_TRIG_PERIO,
		}
		urr := ie.NewUpdateURR(
			ie.NewURRID(1),
			ie.NewMeasurementPeriod(2*time.Second),
			rpt.IE(),
		)
		req.UpdateURR = append(req.UpdateURR, urr)

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
		req.UpdateFAR = append(req.UpdateFAR, far)

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
		req.UpdatePDR = append(req.UpdatePDR, pdr)

		changes, err := (&pfcp.Session{LocalID: lSeid}).ParseModificationChanges(req)
		require.NoError(t, err)
		result, err := handle.Modify(changes)
		if err != nil {
			t.Fatal(err)
		}

		// TODO: should apply PERIO updateURR and receive final report from old URR
		require.Empty(t, result.USAReports)
		// require.NotNil(t, r)
		// require.Equal(t, r.URRID, uint32(1))
	})

	t.Run("remove rules", func(t *testing.T) {
		req := &message.SessionModificationRequest{}

		urr1 := ie.NewRemoveURR(
			ie.NewURRID(1),
		)
		req.RemoveURR = append(req.RemoveURR, urr1)

		urr2 := ie.NewRemoveURR(
			ie.NewURRID(2),
		)
		req.RemoveURR = append(req.RemoveURR, urr2)

		changes, err := (&pfcp.Session{LocalID: lSeid}).ParseModificationChanges(req)
		require.NoError(t, err)
		result, err := handle.Modify(changes)
		if err != nil {
			t.Fatal(err)
		}

		require.NotNil(t, result.USAReports)
		require.Equal(t, 2, len(result.USAReports))
		t.Logf("Receive final report from URR(%d), rpts: %+v", result.USAReports[0].URRID, result.USAReports)
		t.Logf("Receive final report from URR(%d)", result.USAReports[1].URRID)
	})
}
