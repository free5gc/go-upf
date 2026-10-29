package pfcp

import (
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"

	"github.com/free5gc/go-upf/internal/ees"
	"github.com/free5gc/go-upf/internal/forwarder"
	"github.com/free5gc/go-upf/internal/logger"
	"github.com/free5gc/go-upf/internal/report"
)

func pdrPlan(id uint16, ip string, update bool) *forwarder.PDRPlan {
	children := []*ie.IE{ie.NewPDRID(id)}
	if ip != "" {
		children = append(children, ie.NewPDI(ie.NewUEIPAddress(2, ip, "", 0, 0)))
	}
	req := ie.NewCreatePDR(children...)
	if update {
		req = ie.NewUpdatePDR(children...)
	}
	return &forwarder.PDRPlan{PDRID: id, OriginalIE: req}
}

func TestEESIdentityLifecycleAndSnapshots(t *testing.T) {
	node := &LocalNode{}
	remote := NewRemoteNode("smf", nil, node, forwarder.Empty{}, logger.PfcpLog)
	s := remote.NewSess(99)
	s.ApplyCreatePDR(pdrPlan(1, "10.0.0.1", false))
	before := s.identitySnapshot()
	require.Equal(t, "10.0.0.1", before.UeIPv4Addr)
	s.ApplyUpdatePDR(pdrPlan(1, "", true))
	require.Equal(t, "10.0.0.1", s.identitySnapshot().UeIPv4Addr)
	s.ApplyUpdatePDR(pdrPlan(1, "10.0.0.2", true))
	require.Equal(t, "10.0.0.2", s.identitySnapshot().UeIPv4Addr)
	s.ApplyRemovePDR(&forwarder.PDRPlan{PDRID: 1})
	require.Empty(t, s.identitySnapshot().UeIPv4Addr)
	id := s.LocalID
	remote.DeleteSess(id)
	replacement := remote.NewSess(99)
	require.Equal(t, id, replacement.LocalID)
	require.NotEqual(t, before.Generation, replacement.identitySnapshot().Generation)
}

// Identity tracking must not change PFCP rule semantics: an UpdatePDR without
// URR ID IEs still clears the PDR's URR associations exactly as upstream does.
func TestEESIdentityTrackingKeepsUpstreamURRSemantics(t *testing.T) {
	node := &LocalNode{}
	remote := NewRemoteNode("smf", nil, node, forwarder.Empty{}, logger.PfcpLog)
	s := remote.NewSess(99)
	s.URRIDs[2] = &URRInfo{}
	create := pdrPlan(1, "10.0.0.1", false)
	create.URRIDs = []uint32{2}
	s.ApplyCreatePDR(create)
	require.Equal(t, uint16(1), s.URRIDs[2].refPdrNum)
	s.ApplyUpdatePDR(pdrPlan(1, "10.0.0.2", true))
	require.Empty(t, s.PDRIDs[1].RelatedURRIDs)
	require.Equal(t, uint16(0), s.URRIDs[2].refPdrNum)
	require.Equal(t, "10.0.0.2", s.identitySnapshot().UeIPv4Addr)
}

func TestEESConcurrentRuleSnapshots(t *testing.T) {
	node := &LocalNode{}
	remote := NewRemoteNode("smf", nil, node, forwarder.Empty{}, logger.PfcpLog)
	s := remote.NewSess(99)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			s.ApplyCreateURR(&forwarder.URRPlan{URRID: 2, OriginalIE: ie.NewCreateURR(ie.NewMeasurementMethod(0, 1, 0))})
			s.ApplyCreatePDR(pdrPlan(1, "10.0.0.1", false))
			s.ApplyUpdatePDR(pdrPlan(1, "10.0.0.2", true))
			s.ApplyRemovePDR(&forwarder.PDRPlan{PDRID: 1})
			s.ApplyRemoveURR(&forwarder.URRPlan{URRID: 2})
			s.CleanupRemovedURRs()
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			node.GetSessionContext(s.LocalID)
			s.identitySnapshot()
		}
	}()
	wg.Wait()
}

type eesReportDriver struct{ forwarder.Empty }

func (eesReportDriver) ExecuteModificationPlan(*forwarder.ModificationPlan) (*forwarder.ExecutionResult, error) {
	result := forwarder.NewExecutionResult()
	result.USAReports = []report.USAReport{{
		URRID: 2, StartTime: time.Now().Add(-time.Second), EndTime: time.Now(),
		VolumMeasure: report.VolumeMeasure{UplinkVolume: 10},
	}}
	return result, nil
}

func TestEESResponseReportsNeverReenterPFCPQueue(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		for _, deletion := range []bool{false, true} {
			t.Run(testCaseName(enabled, deletion), func(t *testing.T) {
				server := &PfcpServer{srCh: make(chan report.SessReport, 1), log: logger.PfcpLog}
				server.srCh <- report.SessReport{SEID: 777}
				remote := NewRemoteNode("smf", nil, &server.lnode, eesReportDriver{}, logger.PfcpLog)
				sess := remote.NewSess(999) // intentionally not the local SEID
				sess.ApplyCreatePDR(pdrPlan(1, "10.0.0.1", false))
				sess.URRIDs[2] = &URRInfo{}
				var captured report.SessReport
				var identity ees.SessionContext
				if enabled {
					server.RegisterEESReportHandler(func(sr report.SessReport, ctx ees.SessionContext) {
						captured, identity = sr, ctx
					})
				}
				done := make(chan struct{})
				go func() {
					defer close(done)
					addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8805}
					if deletion {
						server.handleSessionDeletionRequest(message.NewSessionDeletionRequest(0, 0, sess.LocalID, 1, 0), addr)
					} else {
						server.handleSessionModificationRequest(message.NewSessionModificationRequest(0, 0, sess.LocalID, 1, 0), addr)
					}
				}()
				select {
				case <-done:
				case <-time.After(time.Second):
					// Unblock the old implementation so a regression does not leak a goroutine.
					<-server.srCh
					t.Fatal("PFCP handler blocked on its own full queue")
				}
				require.Equal(t, 1, len(server.srCh))
				require.Equal(t, uint64(777), (<-server.srCh).SEID)
				if enabled {
					require.Equal(t, sess.LocalID, captured.SEID)
					require.Equal(t, "10.0.0.1", identity.UeIPv4Addr)
					require.Equal(t, uint64(999), identity.RemoteSEID)
					require.NotZero(t, identity.Generation)
					require.Len(t, captured.Reports, 1)
				}
			})
		}
	}
}

func testCaseName(enabled, deletion bool) string {
	name := "disabled"
	if enabled {
		name = "enabled"
	}
	if deletion {
		return name + "/deletion"
	}
	return name + "/modification"
}

type eesDelivery struct {
	seid, remote uint64
	ueIP         string
	period       time.Duration
	urrs         []uint32
}

// With EES enabled the PFCP wire output and forwarder calls must still match
// the upstream golden, while EES alone receives response and kernel usage
// keyed by local SEID, with identity captured before session cleanup.
func TestPFCPParityWithEESEnabled(t *testing.T) {
	var mu sync.Mutex
	var got []eesDelivery
	trace := runPFCPParityScenario(t, func(s *PfcpServer) {
		s.RegisterEESReportHandler(func(sr report.SessReport, identity ees.SessionContext) {
			d := eesDelivery{
				seid: sr.SEID, remote: identity.RemoteSEID, ueIP: identity.UeIPv4Addr, period: identity.MeasurePeriod,
			}
			for _, r := range sr.Reports {
				d.urrs = append(d.urrs, r.(report.USAReport).URRID)
			}
			slices.Sort(d.urrs)
			mu.Lock()
			got = append(got, d)
			mu.Unlock()
		})
	})
	want, err := os.ReadFile(pfcpParityGolden)
	require.NoError(t, err)
	require.Equal(t, string(want), strings.Join(trace, "\n")+"\n")

	mu.Lock()
	defer mu.Unlock()
	// URR 2 is created with PERIO and a 10s Measurement Period in the scenario.
	const p = 10 * time.Second
	require.Equal(t, []eesDelivery{
		{seid: 1, remote: 2, ueIP: "10.60.0.1", period: p, urrs: []uint32{1, 2, 3}}, // modify A response
		{seid: 1, remote: 2, ueIP: "10.60.0.1", period: p, urrs: []uint32{3, 4}},    // remove branch response
		{seid: 1, remote: 2, ueIP: "10.60.0.1", period: p, urrs: []uint32{1}},       // kernel report
		{seid: 1, remote: 2, ueIP: "10.60.0.1", period: p, urrs: []uint32{1, 2}},    // deletion response
		{seid: 2, remote: 1, ueIP: "10.60.0.2", period: p, urrs: []uint32{2}},       // kernel report
		{seid: 2, remote: 1, ueIP: "10.60.0.2", period: p, urrs: []uint32{1, 2, 3, 4}},
	}, got)
}

// The notification period is rounded to the forwarder's real report cadence:
// only a CreateURR with PERIO arms that timer, and a removed URR has none.
func TestEESIdentityCarriesMAQEMeasurementPeriod(t *testing.T) {
	node := &LocalNode{}
	remote := NewRemoteNode("smf", nil, node, forwarder.Empty{}, logger.PfcpLog)
	s := remote.NewSess(99)
	create := func(id uint32, perio bool) {
		trigger := report.ReportingTrigger{}
		if perio {
			trigger.Flags = report.RPT_TRIG_PERIO
		}
		s.ApplyCreateURR(&forwarder.URRPlan{
			URRID: id, ReportingTrigger: trigger, MeasurePeriod: 10 * time.Second,
			OriginalIE: ie.NewCreateURR(ie.NewMeasurementMethod(0, 1, 0)),
		})
	}
	create(ees.SingleUPFMAQEURRID, false)
	require.Zero(t, s.identitySnapshot().MeasurePeriod, "period without PERIO arms no timer")
	create(7, true)
	require.Zero(t, s.identitySnapshot().MeasurePeriod, "only the MAQE URR sets the base period")
	create(ees.SingleUPFMAQEURRID, true)
	require.Equal(t, 10*time.Second, s.identitySnapshot().MeasurePeriod)
	s.ApplyRemoveURR(&forwarder.URRPlan{URRID: ees.SingleUPFMAQEURRID})
	require.Zero(t, s.identitySnapshot().MeasurePeriod)
}
