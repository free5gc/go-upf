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

const (
	fteidV4   = 0x01
	fteidCh   = 0x04
	fteidChID = 0x08
)

// fteidDriver keeps the PDRs given to the forwarder.
type fteidDriver struct {
	forwarder.Empty
	pdrs map[uint16]*ie.IE
}

func (d *fteidDriver) BuildCreatePDRPlan(_ uint64, req *ie.IE) (*forwarder.PDRPlan, error) {
	id, err := req.PDRID()
	d.pdrs[id] = req
	return &forwarder.PDRPlan{Op: forwarder.OpCreate, OriginalIE: req, PDRID: id}, err
}

func (d *fteidDriver) BuildUpdatePDRPlan(_ uint64, req *ie.IE) (*forwarder.PDRPlan, error) {
	id, err := req.PDRID()
	d.pdrs[id] = req
	return &forwarder.PDRPlan{Op: forwarder.OpUpdate, OriginalIE: req, PDRID: id}, err
}

func (d *fteidDriver) BuildRemovePDRPlan(_ uint64, req *ie.IE) (*forwarder.PDRPlan, error) {
	id, err := req.PDRID()
	return &forwarder.PDRPlan{Op: forwarder.OpRemove, OriginalIE: req, PDRID: id}, err
}

func (d *fteidDriver) ExecuteEstablishmentPlan(*forwarder.ModificationPlan) (*forwarder.ExecutionResult, error) {
	return forwarder.NewExecutionResult(), nil
}

func (d *fteidDriver) ExecuteModificationPlan(*forwarder.ModificationPlan) (*forwarder.ExecutionResult, error) {
	return forwarder.NewExecutionResult(), nil
}

// newFTEIDFixture is a UPF of Node ID 127.0.0.1 and GTP-U address 127.0.0.8, associated with the SMF 127.0.0.2,
// that chooses TEIDs from 1.
func newFTEIDFixture(t *testing.T, strict bool) (*PfcpServer, *fteidDriver, *net.UDPConn) {
	t.Helper()
	d := &fteidDriver{pdrs: make(map[uint16]*ie.IE)}
	s := NewPfcpServer(&factory.Config{
		Pfcp: &factory.Pfcp{
			Addr: "127.0.0.1", NodeID: "127.0.0.1", RetransTimeout: time.Minute, StrictFTEIDAllocation: strict,
		},
		Gtpu: &factory.Gtpu{Forwarder: "gtp5g", IfList: []factory.IfInfo{{Addr: "127.0.0.8", Type: "N3"}}},
	}, d)
	s.lnode.fteids.last = 0
	var err error
	s.conn, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.conn.Close()) })
	t.Cleanup(s.stopTrTimers)
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.2")})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, peer.Close()) })
	smf := s.NewNode("127.0.0.2", &net.UDPAddr{IP: net.ParseIP("127.0.0.2"), Port: 8805}, d)
	s.rnodes[smf.ID] = smf
	return s, d, peer
}

func chooseFTEID(chid uint8) *ie.IE {
	if chid == 0 {
		return ie.NewFTEID(fteidV4|fteidCh, 0, nil, nil, 0)
	}
	return ie.NewFTEID(fteidV4|fteidCh|fteidChID, 0, nil, nil, chid)
}

func cpFTEID(teid uint32) *ie.IE {
	return ie.NewFTEID(fteidV4, teid, net.ParseIP("127.0.0.8"), nil, 0)
}

func uplinkPDR(id uint16, fteid *ie.IE) *ie.IE {
	return ie.NewCreatePDR(ie.NewPDRID(id), ie.NewPrecedence(255),
		ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess), fteid), ie.NewFARID(1))
}

func establish(t *testing.T, s *PfcpServer, peer *net.UDPConn, cpSEID uint64, ies ...*ie.IE,
) *message.SessionEstablishmentResponse {
	t.Helper()
	ies = append([]*ie.IE{
		ie.NewNodeID("127.0.0.2", "", ""),
		ie.NewFSEID(cpSEID, net.ParseIP("127.0.0.2"), nil),
		ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(0x02)),
	}, ies...)
	msg := exchangePeerGuardRequest(t, s, peer, message.NewSessionEstablishmentRequest(0, 0, 0, uint32(cpSEID), 0, ies...))
	rsp, ok := msg.(*message.SessionEstablishmentResponse)
	require.True(t, ok)
	return rsp
}

func modify(t *testing.T, s *PfcpServer, peer *net.UDPConn, upSEID uint64, seq uint32, ies ...*ie.IE,
) *message.SessionModificationResponse {
	t.Helper()
	msg := exchangePeerGuardRequest(t, s, peer, message.NewSessionModificationRequest(0, 0, upSEID, seq, 0, ies...))
	rsp, ok := msg.(*message.SessionModificationResponse)
	require.True(t, ok)
	return rsp
}

func requireCause(t *testing.T, want uint8, cause *ie.IE) {
	t.Helper()
	require.NotNil(t, cause)
	got, err := cause.Cause()
	require.NoError(t, err)
	require.Equal(t, want, got)
}

func upSEID(t *testing.T, rsp *message.SessionEstablishmentResponse) uint64 {
	t.Helper()
	require.NotNil(t, rsp.UPFSEID)
	fseid, err := rsp.UPFSEID.FSEID()
	require.NoError(t, err)
	return fseid.SEID
}

// createdFTEIDs gives the Local F-TEID of each Created PDR, by PDR ID.
func createdFTEIDs(t *testing.T, pdrs []*ie.IE) map[uint16]*ie.FTEIDFields {
	t.Helper()
	fteids := make(map[uint16]*ie.FTEIDFields)
	for _, pdr := range pdrs {
		id, err := pdr.PDRID()
		require.NoError(t, err)
		children, err := pdr.CreatedPDR()
		require.NoError(t, err)
		for _, child := range children {
			if child.Type == ie.FTEID {
				fteids[id], err = child.FTEID()
				require.NoError(t, err)
			}
		}
	}
	return fteids
}

func installedFTEID(t *testing.T, d *fteidDriver, id uint16) *ie.FTEIDFields {
	t.Helper()
	children, err := d.pdrs[id].CreatePDR()
	require.NoError(t, err)
	for _, child := range children {
		if child.Type == ie.PDI {
			fteid, fteidErr := child.FTEID()
			require.NoError(t, fteidErr)
			return fteid
		}
	}
	t.Fatalf("PDR %d has no PDI", id)
	return nil
}

func TestAssociationSetupAdvertisesFTUP(t *testing.T) {
	s, _, peer := newFTEIDFixture(t, false)
	req := message.NewAssociationSetupRequest(1,
		ie.NewNodeID("127.0.0.2", "", ""), ie.NewRecoveryTimeStamp(time.Now()))
	msg := exchangePeerGuardRequest(t, s, peer, req)
	rsp, ok := msg.(*message.AssociationSetupResponse)
	require.True(t, ok)
	requireCause(t, ie.CauseRequestAccepted, rsp.Cause)
	require.NotNil(t, rsp.UPFunctionFeatures)
	require.True(t, rsp.UPFunctionFeatures.HasFTUP())
}

func TestSessionEstablishmentChoosesFTEID(t *testing.T) {
	s, d, peer := newFTEIDFixture(t, false)
	rsp := establish(t, s, peer, 0x10,
		uplinkPDR(1, chooseFTEID(7)),
		uplinkPDR(2, chooseFTEID(7)),
		uplinkPDR(3, chooseFTEID(0)),
		ie.NewCreatePDR(ie.NewPDRID(4), ie.NewPrecedence(255), ie.NewPDI(
			ie.NewSourceInterface(ie.SrcInterfaceCore), ie.NewUEIPAddress(0x02, "10.60.0.1", "", 0, 0),
		), ie.NewFARID(1)),
	)
	requireCause(t, ie.CauseRequestAccepted, rsp.Cause)

	// A Created PDR with its F-TEID for each PDR that asked for one (TS 29.244 clause 5.5.3).
	created := createdFTEIDs(t, rsp.CreatedPDR)
	require.Len(t, created, 3)
	for _, id := range []uint16{1, 2, 3} {
		fteid := created[id]
		require.NotNil(t, fteid, "PDR %d", id)
		require.False(t, fteid.HasCh(), "PDR %d", id)
		require.True(t, fteid.HasIPv4(), "PDR %d", id)
		require.Equal(t, "127.0.0.8", fteid.IPv4Address.String(), "PDR %d", id)
		require.NotZero(t, fteid.TEID, "PDR %d", id)
		// The forwarder has the PDR with the F-TEID that the UP function chose.
		require.Equal(t, fteid, installedFTEID(t, d, id), "PDR %d", id)
	}
	// The same F-TEID for the same CHOOSE ID, another one without.
	require.Equal(t, created[1].TEID, created[2].TEID)
	require.NotEqual(t, created[1].TEID, created[3].TEID)

	alloc := &s.lnode.fteids
	require.Equal(t, 2, alloc.teids[created[1].TEID].pdrs)
	require.Equal(t, 1, alloc.teids[created[3].TEID].pdrs)

	// The deletion of the session frees its F-TEIDs.
	del := exchangePeerGuardRequest(t, s, peer, message.NewSessionDeletionRequest(0, 0, upSEID(t, rsp), 2, 0))
	requireCause(t, ie.CauseRequestAccepted, del.(*message.SessionDeletionResponse).Cause)
	require.Empty(t, alloc.teids)
}

func TestSessionModificationChoosesFTEID(t *testing.T) {
	s, d, peer := newFTEIDFixture(t, false)
	alloc := &s.lnode.fteids
	est := establish(t, s, peer, 0x10, uplinkPDR(1, chooseFTEID(0)))
	requireCause(t, ie.CauseRequestAccepted, est.Cause)
	first := createdFTEIDs(t, est.CreatedPDR)[1]
	seid := upSEID(t, est)

	// A new PDR that asks for an F-TEID gets one, in a Created PDR.
	rsp := modify(t, s, peer, seid, 2, uplinkPDR(2, chooseFTEID(0)))
	requireCause(t, ie.CauseRequestAccepted, rsp.Cause)
	created := createdFTEIDs(t, rsp.CreatedPDR)
	require.Len(t, created, 1)
	require.Equal(t, created[2], installedFTEID(t, d, 2))
	require.NotEqual(t, first.TEID, created[2].TEID)

	// An Update PDR cannot ask for one: on N4, no Updated PDR returns it (TS 29.244 Table 7.5.5.5-1).
	choose := ie.NewUpdatePDR(ie.NewPDRID(1), ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess), chooseFTEID(0)))
	requireCause(t, ie.CauseRuleCreationModificationFailure, modify(t, s, peer, seid, 3, choose).Cause)
	require.Len(t, alloc.teids, 2)

	// The F-TEID of a removed PDR is freed, and so is that of a PDR updated to another F-TEID.
	update := ie.NewUpdatePDR(ie.NewPDRID(1), ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess), cpFTEID(0x2001)))
	rsp = modify(t, s, peer, seid, 4, ie.NewRemovePDR(ie.NewPDRID(2)), update)
	requireCause(t, ie.CauseRequestAccepted, rsp.Cause)
	require.Empty(t, rsp.UpdatedPDR)
	require.NotContains(t, alloc.teids, created[2].TEID)
	require.NotContains(t, alloc.teids, first.TEID)
	require.Contains(t, alloc.teids, uint32(0x2001))
}

func TestStrictFTEIDAllocation(t *testing.T) {
	s, _, peer := newFTEIDFixture(t, true)
	alloc := &s.lnode.fteids

	// A new PDR with an F-TEID of the SMF is rejected (TS 29.244 clause 5.5.1), and the F-TEID chosen for
	// another PDR of the request is freed.
	rsp := establish(t, s, peer, 0x10, uplinkPDR(1, chooseFTEID(0)), uplinkPDR(2, cpFTEID(100)))
	requireCause(t, ie.CauseInvalidFTEIDAllocationOption, rsp.Cause)
	require.Nil(t, rsp.UPFSEID)
	require.Empty(t, alloc.teids)

	// But not in the establishment of a session that is restored.
	rsp = establish(t, s, peer, 0x11, uplinkPDR(1, cpFTEID(100)), ie.NewPFCPSEReqFlags(0x01))
	requireCause(t, ie.CauseRequestAccepted, rsp.Cause)
	require.Empty(t, rsp.CreatedPDR)
	seid := upSEID(t, rsp)

	// A PDR keeps its F-TEID, and cannot take another one of the SMF.
	keep := ie.NewUpdatePDR(ie.NewPDRID(1), ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess), cpFTEID(100)))
	requireCause(t, ie.CauseRequestAccepted, modify(t, s, peer, seid, 3, keep).Cause)
	change := ie.NewUpdatePDR(ie.NewPDRID(1), ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess), cpFTEID(101)))
	requireCause(t, ie.CauseInvalidFTEIDAllocationOption, modify(t, s, peer, seid, 4, change).Cause)
	require.Contains(t, alloc.teids, uint32(100))
	require.NotContains(t, alloc.teids, uint32(101))

	// An Update PDR of a PDR that does not exist is a rule that does not exist, whatever its F-TEID.
	unknown := ie.NewUpdatePDR(ie.NewPDRID(9), ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess), cpFTEID(102)))
	requireCause(t, ie.CauseRuleCreationModificationFailure, modify(t, s, peer, seid, 5, unknown).Cause)
}

func TestRestorationFTEIDInUse(t *testing.T) {
	for name, strict := range map[string]bool{"lenient": false, "strict": true} {
		t.Run(name, func(t *testing.T) {
			s, _, peer := newFTEIDFixture(t, strict)
			resti := ie.NewPFCPSEReqFlags(0x01)

			// A TEID that the UP function chose, and one of the SMF that a restored session has on two PDRs.
			rsp := establish(t, s, peer, 0x10, uplinkPDR(1, chooseFTEID(0)))
			requireCause(t, ie.CauseRequestAccepted, rsp.Cause)
			chosen := createdFTEIDs(t, rsp.CreatedPDR)[1].TEID
			rsp = establish(t, s, peer, 0x11, uplinkPDR(1, cpFTEID(0x2001)), uplinkPDR(2, cpFTEID(0x2001)), resti)
			requireCause(t, ie.CauseRequestAccepted, rsp.Cause)

			// Another restored session cannot have either. TS 23.527 clause 4.3.2 excludes cause 86 for a TEID
			// that another session has, and TS 29.244 Table 8.2.1-1 cause 71 for a restoration.
			for _, teid := range []uint32{chosen, 0x2001} {
				rsp = establish(t, s, peer, 0x12, uplinkPDR(1, cpFTEID(teid)), resti)
				requireCause(t, ie.CauseRequestRejected, rsp.Cause)
				require.Nil(t, rsp.UPFSEID)
			}
			require.Equal(t, 1, s.lnode.fteids.teids[chosen].pdrs)
			require.Equal(t, 2, s.lnode.fteids.teids[0x2001].pdrs)
		})
	}
}

func TestFTEIDsNotReusedAfterRestart(t *testing.T) {
	// A restarted UPF does not choose again the TEIDs of its previous run (TS 23.527 clause 4.3.2).
	cfg := &factory.Config{Pfcp: &factory.Pfcp{NodeID: "127.0.0.1"}}
	before, after := newFTEIDAllocator(cfg), newFTEIDAllocator(cfg)
	require.NotEqual(t, before.choose(nil, nil), after.choose(nil, nil))
}

func TestLenientFTEIDAllocation(t *testing.T) {
	s, _, peer := newFTEIDFixture(t, false)

	// An F-TEID of the SMF is taken, as before, and returned in no Created PDR.
	rsp := establish(t, s, peer, 0x10, uplinkPDR(1, cpFTEID(1)))
	requireCause(t, ie.CauseRequestAccepted, rsp.Cause)
	require.Empty(t, rsp.CreatedPDR)

	// The UP function never chooses a TEID in use, or one of the SMF in the same request, before or after.
	rsp = establish(t, s, peer, 0x11, uplinkPDR(1, cpFTEID(2)), uplinkPDR(2, chooseFTEID(0)), uplinkPDR(3, cpFTEID(3)))
	requireCause(t, ie.CauseRequestAccepted, rsp.Cause)
	chosen := createdFTEIDs(t, rsp.CreatedPDR)[2].TEID
	require.Equal(t, uint32(4), chosen)

	// An F-TEID that the UP function chose belongs to its session: another session cannot take it.
	rsp2 := establish(t, s, peer, 0x12, uplinkPDR(1, cpFTEID(chosen)))
	requireCause(t, ie.CauseInvalidFTEIDAllocationOption, rsp2.Cause)

	// Its session can, for a PDR that it adds.
	mod := modify(t, s, peer, upSEID(t, rsp), 4, uplinkPDR(4, cpFTEID(chosen)))
	requireCause(t, ie.CauseRequestAccepted, mod.Cause)
	require.Equal(t, 2, s.lnode.fteids.teids[chosen].pdrs)
}
