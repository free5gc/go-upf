package pfcp

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"

	"github.com/free5gc/go-upf/internal/forwarder"
	"github.com/free5gc/go-upf/internal/report"
	"github.com/free5gc/go-upf/pkg/factory"
)

// The golden file was recorded from upstream free5gc/go-upf 0012ceb (before
// the EES feature) by running this file there with PFCP_PARITY_WRITE=1. With
// EES disabled, every PFCP message the UPF sends and every forwarder call it
// makes must stay byte-for-byte identical, including in a ULCL-style session.
const pfcpParityGolden = "testdata/ees_disabled_parity.golden"

const paritySMFNodeID = "127.0.0.77"

var parityBaseTime = time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)

// parityDriver reuses the real gtp5g plan builders (pure IE parsing) and
// replaces kernel execution with a deterministic, recorded model.
type parityDriver struct {
	*forwarder.Gtp5g
	mu      sync.Mutex
	calls   []string
	urrs    map[[2]uint64]bool   // installed (lSeid, urrid)
	reads   map[[2]uint64]uint64 // per-URR report count
	handler report.Handler
}

func newParityDriver() *parityDriver {
	return &parityDriver{
		Gtp5g: &forwarder.Gtp5g{},
		urrs:  make(map[[2]uint64]bool), reads: make(map[[2]uint64]uint64),
	}
}

func (d *parityDriver) Close() {}

func (d *parityDriver) HandleReport(h report.Handler) { d.handler = h }

// Called with d.mu held. Values depend only on (lSeid, urrid, nth read), so
// the trace does not depend on Go map iteration order inside the UPF.
func (d *parityDriver) usage(lSeid uint64, urrid uint32, trigger, indent string) report.USAReport {
	key := [2]uint64{lSeid, uint64(urrid)}
	d.reads[key]++
	n := d.reads[key]
	d.calls = append(d.calls, fmt.Sprintf("%susage seid=%d urr=%d n=%d via=%s", indent, lSeid, urrid, n, trigger))
	base := lSeid*1_000_000 + uint64(urrid)*1_000 + n
	return report.USAReport{
		URRID:        urrid,
		USARTrigger:  report.UsageReportTrigger{Flags: report.USAR_TRIG_VOLTH},
		VolumMeasure: report.VolumeMeasure{TotalVolume: base * 3, UplinkVolume: base, DownlinkVolume: base * 2},
		StartTime:    parityBaseTime.Add(time.Duration(base) * time.Second),
		EndTime:      parityBaseTime.Add(time.Duration(base+1) * time.Second),
	}
}

func (d *parityDriver) QueryURR(lSeid uint64, urrid uint32) ([]report.USAReport, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls = append(d.calls, fmt.Sprintf("QueryURR seid=%d urr=%d", lSeid, urrid))
	if !d.urrs[[2]uint64{lSeid, uint64(urrid)}] {
		return nil, fmt.Errorf("urr %d not installed", urrid)
	}
	return []report.USAReport{d.usage(lSeid, urrid, "QueryURR", "  ")}, nil
}

func (d *parityDriver) ExecuteEstablishmentPlan(p *forwarder.ModificationPlan) (*forwarder.ExecutionResult, error) {
	return d.execute("Establishment", p)
}

func (d *parityDriver) ExecuteModificationPlan(p *forwarder.ModificationPlan) (*forwarder.ExecutionResult, error) {
	return d.execute("Modification", p)
}

func (d *parityDriver) execute(kind string, p *forwarder.ModificationPlan) (*forwarder.ExecutionResult, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	result := forwarder.NewExecutionResult()
	d.calls = append(d.calls, fmt.Sprintf("Execute%s seid=%d", kind, p.SEID))
	rec := func(op string, id any, attrs any) {
		d.calls = append(d.calls, fmt.Sprintf("  %s %v %+v", op, id, attrs))
	}
	for _, x := range p.CreateFARs {
		rec("CreateFAR", x.FARID, x.Attrs)
	}
	for _, x := range p.CreateQERs {
		rec("CreateQER", x.QERID, x.Attrs)
	}
	for _, x := range p.CreateURRs {
		rec("CreateURR", x.URRID, x.Attrs)
		d.urrs[[2]uint64{p.SEID, uint64(x.URRID)}] = true
	}
	for _, x := range p.CreateBARs {
		rec("CreateBAR", x.BARID, x.Attrs)
	}
	for _, x := range p.CreatePDRs {
		rec("CreatePDR", x.PDRID, x.Attrs)
	}
	for _, x := range p.RemovePDRs {
		rec("RemovePDR", x.PDRID, nil)
	}
	for _, x := range p.RemoveBARs {
		rec("RemoveBAR", x.BARID, nil)
	}
	for _, x := range p.RemoveURRs {
		rec("RemoveURR", x.URRID, nil)
		key := [2]uint64{p.SEID, uint64(x.URRID)}
		if d.urrs[key] {
			result.USAReports = append(result.USAReports, d.usage(p.SEID, x.URRID, "RemoveURR", "  "))
		}
		delete(d.urrs, key)
	}
	for _, x := range p.RemoveQERs {
		rec("RemoveQER", x.QERID, nil)
	}
	for _, x := range p.RemoveFARs {
		rec("RemoveFAR", x.FARID, nil)
	}
	for _, x := range p.UpdateFARs {
		rec("UpdateFAR", x.FARID, x.Attrs)
	}
	for _, x := range p.UpdateQERs {
		rec("UpdateQER", x.QERID, x.Attrs)
	}
	for _, x := range p.UpdateURRs {
		rec("UpdateURR", x.URRID, x.Attrs)
		result.USAReports = append(result.USAReports, d.usage(p.SEID, x.URRID, "UpdateURR", "  "))
	}
	for _, x := range p.UpdateBARs {
		rec("UpdateBAR", x.BARID, x.Attrs)
	}
	for _, x := range p.UpdatePDRs {
		rec("UpdatePDR", x.PDRID, x.Attrs)
	}
	for _, x := range p.QueryURRs {
		rec("QueryURR", x.QueryURRID, nil)
		result.USAReports = append(result.USAReports, d.usage(p.SEID, x.QueryURRID, "QueryURR", "  "))
	}
	return result, nil
}

// kernelReport mimics a periodic/threshold report pushed by gtp5g.
func (d *parityDriver) kernelReport(lSeid uint64, urrid uint32) {
	d.mu.Lock()
	r := d.usage(lSeid, urrid, "kernel", "")
	d.mu.Unlock()
	d.handler.NotifySessReport(report.SessReport{SEID: lSeid, Reports: []report.Report{r}})
}

// log returns the call trace with order-insensitive grouping: each top-level
// call keeps its indented details, details are sorted, and runs of standalone
// QueryURR calls (issued while iterating session maps) are sorted as units.
func (d *parityDriver) log() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	var blocks [][]string
	for _, line := range d.calls {
		if strings.HasPrefix(line, "  ") && len(blocks) > 0 {
			blocks[len(blocks)-1] = append(blocks[len(blocks)-1], line)
			continue
		}
		blocks = append(blocks, []string{line})
	}
	for _, b := range blocks {
		sort.Strings(b[1:])
	}
	for i := 0; i < len(blocks); {
		j := i
		for j < len(blocks) && strings.HasPrefix(blocks[j][0], "QueryURR ") {
			j++
		}
		if j > i {
			sort.Slice(blocks[i:j], func(a, b int) bool {
				return strings.Join(blocks[i+a], "\n") < strings.Join(blocks[i+b], "\n")
			})
			i = j
			continue
		}
		i++
	}
	var out []string
	for _, b := range blocks {
		out = append(out, b...)
	}
	return out
}

type paritySMF struct {
	t    *testing.T
	conn *net.UDPConn
	upf  *net.UDPAddr
	seq  uint32
	rcv  chan []byte
}

func (c *paritySMF) readLoop() {
	buf := make([]byte, 65535)
	for {
		n, _, err := c.conn.ReadFrom(buf)
		if err != nil {
			close(c.rcv)
			return
		}
		c.rcv <- append([]byte(nil), buf[:n]...)
	}
}

func (c *paritySMF) send(m message.Message) {
	c.t.Helper()
	b := make([]byte, m.MarshalLen())
	require.NoError(c.t, m.MarshalTo(b))
	_, err := c.conn.WriteTo(b, c.upf)
	require.NoError(c.t, err)
}

func (c *paritySMF) next() uint32 { c.seq++; return c.seq }

// recv returns the next UPF message, answering Session Report Requests the way
// the SMF does so no retransmission depends on timing.
func (c *paritySMF) recv() []byte {
	c.t.Helper()
	select {
	case b := <-c.rcv:
		if m, err := message.Parse(b); err == nil && m.MessageType() == message.MsgTypeSessionReportRequest {
			c.send(message.NewSessionReportResponse(0, 0, m.SEID(), m.Sequence(), 0,
				ie.NewCause(ie.CauseRequestAccepted)))
		}
		return b
	case <-time.After(3 * time.Second):
		c.t.Fatal("no PFCP message from UPF")
		return nil
	}
}

func describePFCP(b []byte) string {
	m, err := message.Parse(b)
	if err != nil {
		return "unparsable " + hex.EncodeToString(b)
	}
	if rsp, ok := m.(*message.AssociationSetupResponse); ok {
		// Recovery Time Stamp is wall-clock; compare everything else structurally.
		cause, causeErr := rsp.Cause.Cause()
		if causeErr != nil {
			return "invalid cause " + hex.EncodeToString(b)
		}
		return fmt.Sprintf("%s seq=%d cause=%d", m.MessageTypeName(), m.Sequence(), cause)
	}
	// Top-level IE order follows UPF map iteration (e.g. usage reports on
	// deletion), so compare the exact bytes of each IE as a sorted set.
	ies, err := ie.ParseMultiIEs(b[16:])
	if err != nil {
		return "unparsable IEs " + hex.EncodeToString(b)
	}
	encoded := make([]string, 0, len(ies))
	for _, x := range ies {
		raw, err := x.Marshal()
		if err != nil {
			return "unmarshalable IE " + hex.EncodeToString(b)
		}
		encoded = append(encoded, hex.EncodeToString(raw))
	}
	sort.Strings(encoded)
	return fmt.Sprintf("%s seq=%d seid=%#x len=%d\n  %s", m.MessageTypeName(), m.Sequence(), m.SEID(), len(b),
		strings.Join(encoded, "\n  "))
}

func freeUDPAddr(t *testing.T) *net.UDPAddr {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	addr := conn.LocalAddr().(*net.UDPAddr)
	require.NoError(t, conn.Close())
	return addr
}

func ulclEstablishment(seq uint32, cpSEID uint64, ueIP string, teid uint32) *message.SessionEstablishmentRequest {
	smfIP := net.ParseIP(paritySMFNodeID)
	return message.NewSessionEstablishmentRequest(0, 0, 0, seq, 0,
		ie.NewNodeID(paritySMFNodeID, "", ""),
		ie.NewFSEID(cpSEID, smfIP, nil),
		// FAR 1/2: uplink to the two PSAs (ULCL branches); FAR 3: downlink to AN.
		ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(0x02),
			ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceCore),
				ie.NewOuterHeaderCreation(0x0100, 0x5001, "10.200.200.101", "", 0, 0, 0))),
		ie.NewCreateFAR(ie.NewFARID(2), ie.NewApplyAction(0x02),
			ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceCore),
				ie.NewOuterHeaderCreation(0x0100, 0x5002, "10.200.200.102", "", 0, 0, 0))),
		ie.NewCreateFAR(ie.NewFARID(3), ie.NewApplyAction(0x02),
			ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceAccess),
				ie.NewOuterHeaderCreation(0x0100, teid, "10.200.200.1", "", 0, 0, 0))),
		ie.NewCreateQER(ie.NewQERID(1), ie.NewGateStatus(0, 0), ie.NewMBR(200000, 100000)),
		// Several URRs, deliberately not only ID 2, as with charging/ULCL rules.
		// Reporting Triggers octet 5: 0x02 VOLTH, 0x03 PERIO|VOLTH.
		ie.NewCreateURR(ie.NewURRID(1), ie.NewMeasurementMethod(0, 1, 0),
			ie.NewReportingTriggers(0x02, 0x00), ie.NewVolumeThreshold(0x07, 9000, 6000, 3000)),
		ie.NewCreateURR(ie.NewURRID(2), ie.NewMeasurementMethod(0, 1, 0),
			ie.NewReportingTriggers(0x03, 0x00), ie.NewMeasurementPeriod(10*time.Second),
			ie.NewVolumeThreshold(0x07, 8000, 4000, 4000)),
		ie.NewCreateURR(ie.NewURRID(3), ie.NewMeasurementMethod(0, 1, 0),
			ie.NewReportingTriggers(0x02, 0x00), ie.NewVolumeThreshold(0x07, 7000, 3500, 3500)),
		ie.NewCreateURR(ie.NewURRID(4), ie.NewMeasurementMethod(0, 1, 0),
			ie.NewReportingTriggers(0x02, 0x00), ie.NewVolumeThreshold(0x07, 6000, 3000, 3000)),
		ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(255),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess),
				ie.NewFTEID(0x01, teid+1, net.ParseIP("10.200.200.2"), nil, 0),
				ie.NewNetworkInstance("internet"),
				ie.NewUEIPAddress(2, ueIP, "", 0, 0)),
			ie.NewOuterHeaderRemoval(0, 0), ie.NewFARID(1), ie.NewQERID(1), ie.NewURRID(1), ie.NewURRID(2)),
		ie.NewCreatePDR(ie.NewPDRID(2), ie.NewPrecedence(100),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess),
				ie.NewFTEID(0x01, teid+1, net.ParseIP("10.200.200.2"), nil, 0),
				ie.NewNetworkInstance("internet"),
				ie.NewUEIPAddress(2, ueIP, "", 0, 0),
				ie.NewSDFFilter("permit out ip from 10.100.0.0/16 to assigned", "", "", "", 1)),
			ie.NewOuterHeaderRemoval(0, 0), ie.NewFARID(2), ie.NewQERID(1), ie.NewURRID(3)),
		ie.NewCreatePDR(ie.NewPDRID(3), ie.NewPrecedence(255),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceCore),
				ie.NewNetworkInstance("internet"),
				ie.NewUEIPAddress(2, ueIP, "", 0, 0)),
			ie.NewFARID(3), ie.NewQERID(1), ie.NewURRID(1), ie.NewURRID(2)),
		ie.NewCreatePDR(ie.NewPDRID(4), ie.NewPrecedence(100),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceCore),
				ie.NewNetworkInstance("internet"),
				ie.NewUEIPAddress(2, ueIP, "", 0, 0),
				ie.NewSDFFilter("permit out ip from 10.100.0.0/16 to assigned", "", "", "", 2)),
			ie.NewFARID(3), ie.NewQERID(1), ie.NewURRID(3), ie.NewURRID(4)),
	)
}

// runPFCPParityScenario drives a real PFCP server loop over UDP and returns a
// deterministic trace of UPF output. hook runs before the server starts.
func runPFCPParityScenario(t *testing.T, hook func(*PfcpServer)) []string {
	t.Helper()
	upfAddr := freeUDPAddr(t)
	cfg := &factory.Config{Pfcp: &factory.Pfcp{Addr: "127.0.0.1", NodeID: "127.0.0.1"}}
	driver := newParityDriver()
	server := NewPfcpServer(cfg, driver)
	server.listen = upfAddr.String()
	driver.HandleReport(server)
	if hook != nil {
		hook(server)
	}
	var wg sync.WaitGroup
	server.Start(&wg)

	// Session Report Requests go to <SMF NodeID>:8805, so the fake SMF owns
	// that port on a dedicated loopback address.
	smfConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(paritySMFNodeID), Port: factory.UpfPfcpDefaultPort})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, smfConn.Close()) })
	smf := &paritySMF{t: t, conn: smfConn, upf: upfAddr, rcv: make(chan []byte, 64)}
	go smf.readLoop()

	var trace []string
	step := func(name string, m message.Message, responses int) {
		trace = append(trace, "== "+name)
		if m != nil {
			smf.send(m)
		}
		for i := 0; i < responses; i++ {
			trace = append(trace, describePFCP(smf.recv()))
		}
	}

	// The UPF listener starts asynchronously; retry association until it answers.
	assoc := message.NewAssociationSetupRequest(smf.next(),
		ie.NewNodeID(paritySMFNodeID, "", ""), ie.NewRecoveryTimeStamp(parityBaseTime))
	var first []byte
	for i := 0; i < 50 && first == nil; i++ {
		smf.send(assoc)
		select {
		case first = <-smf.rcv:
		case <-time.After(100 * time.Millisecond):
		}
	}
	require.NotNil(t, first, "UPF did not answer association setup")
	trace = append(trace, "== association", describePFCP(first))

	// Small CP SEIDs as allocated by free5GC SMF; A's remote SEID equals B's
	// local SEID, so a report re-enqueued with a remote SEID hits the wrong session.
	const cpA, cpB = 2, 1
	step("establish A (ULCL rules)", ulclEstablishment(smf.next(), cpA, "10.60.0.1", 0x100), 1)
	step("establish B", ulclEstablishment(smf.next(), cpB, "10.60.0.2", 0x200), 1)
	const seidA, seidB = 1, 2

	// Re-associate PDRs with and without URR ID IEs, add/remove branches and
	// query/update URRs: every path that produces usage in a PFCP response.
	step("modify A", message.NewSessionModificationRequest(0, 0, seidA, smf.next(), 0,
		ie.NewUpdatePDR(ie.NewPDRID(1), ie.NewFARID(1), ie.NewURRID(1)),
		ie.NewUpdatePDR(ie.NewPDRID(3), ie.NewPrecedence(250), ie.NewFARID(3)),
		ie.NewCreatePDR(ie.NewPDRID(5), ie.NewPrecedence(90),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess),
				ie.NewFTEID(0x01, 0x101, net.ParseIP("10.200.200.2"), nil, 0),
				ie.NewNetworkInstance("internet"),
				ie.NewUEIPAddress(2, "10.60.0.1", "", 0, 0),
				ie.NewSDFFilter("permit out ip from 10.101.0.0/16 to assigned", "", "", "", 3)),
			ie.NewOuterHeaderRemoval(0, 0), ie.NewFARID(2), ie.NewURRID(4)),
		ie.NewRemovePDR(ie.NewPDRID(4)),
		ie.NewUpdateFAR(ie.NewFARID(2), ie.NewApplyAction(0x02),
			ie.NewUpdateForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceCore),
				ie.NewOuterHeaderCreation(0x0100, 0x5003, "10.200.200.103", "", 0, 0, 0))),
		ie.NewUpdateURR(ie.NewURRID(3), ie.NewVolumeThreshold(0x07, 5000, 2500, 2500)),
		ie.NewQueryURR(ie.NewURRID(1)),
	), 1)
	step("modify A: remove branch", message.NewSessionModificationRequest(0, 0, seidA, smf.next(), 0,
		ie.NewRemovePDR(ie.NewPDRID(5)),
		ie.NewRemovePDR(ie.NewPDRID(2)),
		ie.NewRemoveURR(ie.NewURRID(4)),
		ie.NewRemoveURR(ie.NewURRID(3)),
	), 1)

	trace = append(trace, "== kernel report A urr 1")
	driver.kernelReport(seidA, 1)
	trace = append(trace, describePFCP(smf.recv()))
	step("delete A", message.NewSessionDeletionRequest(0, 0, seidA, smf.next(), 0), 1)
	trace = append(trace, "== kernel report B urr 2")
	driver.kernelReport(seidB, 2)
	trace = append(trace, describePFCP(smf.recv()))
	step("delete B", message.NewSessionDeletionRequest(0, 0, seidB, smf.next(), 0), 1)

	// Nothing else may arrive: no re-enqueued response usage, no stray reports.
	select {
	case b := <-smf.rcv:
		trace = append(trace, "== unexpected", describePFCP(b))
	case <-time.After(700 * time.Millisecond):
	}
	trace = append(trace, "== forwarder calls")
	return append(trace, driver.log()...)
}

func TestPFCPParityWithEESDisabled(t *testing.T) {
	got := strings.Join(runPFCPParityScenario(t, nil), "\n") + "\n"
	if os.Getenv("PFCP_PARITY_WRITE") != "" {
		require.NoError(t, os.MkdirAll(filepath.Dir(pfcpParityGolden), 0o755))
		require.NoError(t, os.WriteFile(pfcpParityGolden, []byte(got), 0o600))
		return
	}
	want, err := os.ReadFile(pfcpParityGolden)
	require.NoError(t, err)
	require.Equal(t, string(want), got)
}
