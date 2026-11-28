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
	"github.com/wmnsk/go-pfcp/message"

	"github.com/free5gc/go-upf/internal/ees"
	"github.com/free5gc/go-upf/internal/forwarder"
	"github.com/free5gc/go-upf/internal/logger"
	"github.com/free5gc/go-upf/internal/report"
	"github.com/free5gc/go-upf/internal/rules"
	"github.com/free5gc/go-upf/pkg/factory"
)

func eesPDR(id uint16, ip string) rules.PDRConfig {
	precedence := uint32(255)
	config := rules.PDRConfig{PDRID: id, Precedence: &precedence}
	if ip != "" {
		config.PDI = &rules.PDI{UEIPAddress: &rules.UEIPAddress{IPv4Address: net.ParseIP(ip).To4()}}
	}
	return config
}

func newEESTestSession() (*LocalNode, *PFCPAssociation, *Session) {
	node := NewLocalNode("upf", time.Time{}, forwarder.Empty{}, logger.PfcpLog)
	remote := node.EstablishAssociation("smf", nil)
	return node, remote, node.CreateSession(remote, 99)
}

func TestEESIdentityLifecycleAndSnapshots(t *testing.T) {
	node, remote, s := newEESTestSession()
	create := rules.RuleChangeSet{SEID: s.LocalID, CreatePDRs: []rules.PDRConfig{eesPDR(1, "10.0.0.1")}}
	require.NoError(t, applyEESRules(s, &create, true))
	before := s.identitySnapshot()
	require.Equal(t, "10.0.0.1", before.UeIPv4Addr)
	update := rules.RuleChangeSet{SEID: s.LocalID, UpdatePDRs: []rules.PDRPatch{{PDRID: 1}}}
	require.NoError(t, applyEESRules(s, &update, false))
	require.Equal(t, "10.0.0.1", s.identitySnapshot().UeIPv4Addr)
	update.UpdatePDRs[0].PDI = eesPDR(1, "10.0.0.2").PDI
	require.NoError(t, applyEESRules(s, &update, false))
	require.Equal(t, "10.0.0.2", s.identitySnapshot().UeIPv4Addr)
	s.ApplyRemovePDR(1)
	require.Empty(t, s.identitySnapshot().UeIPv4Addr)
	id := s.LocalID
	node.DeleteSession(id)
	replacement := node.CreateSession(remote, 99)
	require.Equal(t, id, replacement.LocalID)
	require.NotEqual(t, before.Generation, replacement.identitySnapshot().Generation)
}

func applyEESRules(s *Session, changes *rules.RuleChangeSet, establish bool) error {
	_, err := s.applyRuleChanges(changes, establish, nil)
	return err
}

func TestEESIdentityTrackingKeepsPartialPDRURRs(t *testing.T) {
	_, _, s := newEESTestSession()
	pdr := eesPDR(1, "10.0.0.1")
	pdr.URRIDs = []uint32{2}
	measurement := uint8(2)
	triggers := uint32(0)
	create := rules.RuleChangeSet{
		SEID: s.LocalID, CreatePDRs: []rules.PDRConfig{pdr},
		CreateURRs: []rules.URRConfig{{URRID: 2, MeasureMethod: &measurement, ReportingTriggers: &triggers}},
	}
	require.NoError(t, applyEESRules(s, &create, true))
	require.Equal(t, 1, s.URRIDs[2].refPdrNum)
	patch := rules.PDRPatch(eesPDR(1, "10.0.0.2"))
	update := rules.RuleChangeSet{SEID: s.LocalID, UpdatePDRs: []rules.PDRPatch{patch}}
	require.NoError(t, applyEESRules(s, &update, false))
	require.Equal(t, []uint32{2}, s.PDRIDs[1].URRIDs)
	require.Equal(t, 1, s.URRIDs[2].refPdrNum)
	require.Equal(t, "10.0.0.2", s.identitySnapshot().UeIPv4Addr)
}

type eesReportDatapath struct{ forwarder.SessionDatapath }

func (eesReportDatapath) Modify(c *rules.RuleChangeSet) (*forwarder.ApplyResult, error) {
	result := removedRules(c)
	result.USAReports = []report.USAReport{{
		URRID: 2, StartTime: time.Now().Add(-time.Second), EndTime: time.Now(),
		VolumMeasure: report.VolumeMeasure{UplinkVolume: 10},
	}}
	return result, nil
}

func (d eesReportDatapath) Cleanup(c *rules.RuleChangeSet) (*forwarder.ApplyResult, error) {
	return d.Modify(c)
}

func TestEESResponseReportsNeverReenterPFCPQueue(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		for _, deletion := range []bool{false, true} {
			t.Run(testCaseName(enabled, deletion), func(t *testing.T) {
				server := NewPfcpServer(&factory.Config{
					Pfcp: &factory.Pfcp{NodeID: "127.0.0.1"},
				}, forwarder.Empty{})
				server.srCh = make(chan report.SessReport, 1)
				server.srCh <- report.SessReport{SEID: 777}
				addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8805}
				remote := server.dispatcher.node.EstablishAssociation("smf", addr)
				sess := server.dispatcher.node.CreateSession(remote, 999)
				sess.datapath = eesReportDatapath{}
				pdr := eesPDR(1, "10.0.0.1")
				sess.PDRIDs[1] = &pdr
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
					if deletion {
						server.dispatcher.handleSessionDeletionRequest(message.NewSessionDeletionRequest(0, 0, sess.LocalID, 1, 0), addr)
					} else {
						req := message.NewSessionModificationRequest(0, 0, sess.LocalID, 1, 0)
						server.dispatcher.handleSessionModificationRequest(req, addr)
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
// the golden trace, while EES alone receives response and kernel usage
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
		{seid: 1, remote: 2, ueIP: "10.60.0.1", period: p, urrs: []uint32{1, 3}}, // modify A response
		{seid: 1, remote: 2, ueIP: "10.60.0.1", period: p, urrs: []uint32{3, 4}}, // remove branch response
		{seid: 1, remote: 2, ueIP: "10.60.0.1", period: p, urrs: []uint32{1}},    // kernel report
		{seid: 1, remote: 2, ueIP: "10.60.0.1", period: p, urrs: []uint32{1, 2}}, // deletion response
		{seid: 2, remote: 1, ueIP: "10.60.0.2", period: p, urrs: []uint32{2}},    // kernel report
		{seid: 2, remote: 1, ueIP: "10.60.0.2", period: p, urrs: []uint32{1, 2, 3, 4}},
	}, got)
}

// The notification period is rounded to the forwarder's real report cadence:
// only a CreateURR with PERIO arms that timer, and a removed URR has none.
func TestEESIdentityCarriesMAQEMeasurementPeriod(t *testing.T) {
	_, _, s := newEESTestSession()
	create := func(id uint32, perio bool) {
		triggers := uint32(0)
		if perio {
			triggers = report.RPT_TRIG_PERIO
		}
		period := 10 * time.Second
		s.URRIDs[id] = &URRInfo{Config: rules.URRConfig{
			URRID: id, ReportingTriggers: &triggers, MeasurePeriod: &period,
		}}
	}
	create(ees.SingleUPFMAQEURRID, false)
	require.Zero(t, s.identitySnapshot().MeasurePeriod, "period without PERIO arms no timer")
	create(7, true)
	require.Zero(t, s.identitySnapshot().MeasurePeriod, "only the MAQE URR sets the base period")
	create(ees.SingleUPFMAQEURRID, true)
	require.Equal(t, 10*time.Second, s.identitySnapshot().MeasurePeriod)
	s.ApplyRemoveURR(ees.SingleUPFMAQEURRID)
	require.Zero(t, s.identitySnapshot().MeasurePeriod)
}
