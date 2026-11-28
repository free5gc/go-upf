package pfcp

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"

	"github.com/free5gc/go-upf/internal/forwarder"
	"github.com/free5gc/go-upf/internal/rules"
)

// TS 29.244 7.5.3.1: a rejection due to a mandatory IE missing or faulty
// names the IE in the Offending IE.
func TestSessionEstablishmentOffendingIE(t *testing.T) {
	nodeID := ie.NewNodeID("127.0.0.2", "", "")
	fseid := ie.NewFSEID(0x4321, net.ParseIP("127.0.0.2"), nil)
	emptyFQDN := ie.New(ie.NodeID, []byte{ie.NodeIDFQDN, 0})
	invalidPDR := ie.NewCreatePDR(ie.NewPDRID(11), ie.NewPrecedence(100),
		ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess)), ie.NewOuterHeaderRemoval(255, 0))
	for _, tc := range []struct {
		name         string
		ies          []*ie.IE
		wantCause    uint8
		wantOffender uint16
	}{
		{"missing Node ID", []*ie.IE{fseid}, ie.CauseMandatoryIEMissing, ie.NodeID},
		{"faulty Node ID", []*ie.IE{ie.New(ie.NodeID, nil), fseid}, ie.CauseMandatoryIEIncorrect, ie.NodeID},
		{"empty FQDN Node ID", []*ie.IE{emptyFQDN, fseid}, ie.CauseMandatoryIEIncorrect, ie.NodeID},
		{"missing CP F-SEID", []*ie.IE{nodeID}, ie.CauseMandatoryIEMissing, ie.FSEID},
		{"faulty CP F-SEID", []*ie.IE{nodeID, ie.New(ie.FSEID, nil)}, ie.CauseMandatoryIEIncorrect, ie.FSEID},
		{
			name:         "unknown Outer Header Removal description",
			ies:          []*ie.IE{nodeID, fseid, invalidPDR},
			wantCause:    ie.CauseMandatoryIEIncorrect,
			wantOffender: ie.OuterHeaderRemoval,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, driver, owner, peer := newPeerGuardFixture(t, "127.0.0.2")
			req := message.NewSessionEstablishmentRequest(0, 0, 0, 1, 0, tc.ies...)
			rsp, ok := exchangePeerGuardRequest(t, s, peer, req).(*message.SessionEstablishmentResponse)
			require.True(t, ok)
			require.NotNil(t, rsp.NodeID)
			cause, err := rsp.Cause.Cause()
			require.NoError(t, err)
			require.Equal(t, tc.wantCause, cause)
			require.NotNil(t, rsp.OffendingIE)
			offender, err := rsp.OffendingIE.OffendingIE()
			require.NoError(t, err)
			require.Equal(t, tc.wantOffender, offender)
			require.Zero(t, driver.establishments)
			require.Empty(t, owner.sessionIDs)
		})
	}
}

func TestSessionModificationOuterHeaderRemoval(t *testing.T) {
	truncated := ie.New(ie.OuterHeaderRemoval, nil)
	truncated.Length = 1
	for _, tc := range []struct {
		name            string
		ohr             *ie.IE
		wantCause       uint8
		wantDescription uint8
	}{
		{"omitted", nil, ie.CauseRequestAccepted, 1},
		{"valid one octet", ie.New(ie.OuterHeaderRemoval, []byte{0}), ie.CauseRequestAccepted, 0},
		{"last defined value", ie.NewOuterHeaderRemoval(8, 0), ie.CauseRequestAccepted, 8},
		{"first unknown value", ie.NewOuterHeaderRemoval(9, 0), ie.CauseMandatoryIEIncorrect, 1},
		{"unknown value 255", ie.NewOuterHeaderRemoval(255, 0), ie.CauseMandatoryIEIncorrect, 1},
		{"empty content", ie.New(ie.OuterHeaderRemoval, nil), ie.CauseMandatoryIEIncorrect, 1},
		{"declared length mismatch", truncated, ie.CauseInvalidLength, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _, owner, peer := newPeerGuardFixture(t, "127.0.0.2")
			driver := &authorizationDriver{}
			s.dispatcher.node.newDatapath = func(uint64) forwarder.SessionDatapath { return driver }
			sess := s.dispatcher.node.CreateSession(owner, 0x1234)
			precedence, description := uint32(100), uint8(1)
			sess.PDRIDs[11] = &rules.PDRConfig{
				PDRID: 11, Precedence: &precedence, OuterHeaderRemoval: &description,
			}
			children := []*ie.IE{ie.NewPDRID(11), ie.NewPrecedence(200)}
			if tc.ohr != nil {
				children = append(children, tc.ohr)
			}
			req := message.NewSessionModificationRequest(0, 0, sess.LocalID, 1, 0, ie.NewUpdatePDR(children...))
			rsp, ok := exchangePeerGuardRequest(t, s, peer, req).(*message.SessionModificationResponse)
			require.True(t, ok)
			require.NotNil(t, rsp.Cause)
			cause, err := rsp.Cause.Cause()
			require.NoError(t, err)
			require.Equal(t, tc.wantCause, cause)

			pdr := sess.PDRIDs[11]
			require.NotNil(t, pdr)
			require.Equal(t, tc.wantDescription, *pdr.OuterHeaderRemoval)
			if tc.wantCause == ie.CauseRequestAccepted {
				require.Nil(t, rsp.OffendingIE)
				require.Len(t, driver.modifications, 1)
				require.Equal(t, uint32(200), *pdr.Precedence)
			} else {
				require.NotNil(t, rsp.OffendingIE)
				offender, err := rsp.OffendingIE.OffendingIE()
				require.NoError(t, err)
				require.Equal(t, ie.OuterHeaderRemoval, offender)
				require.Empty(t, driver.modifications)
				require.Equal(t, uint32(100), *pdr.Precedence)
			}
		})
	}
}
