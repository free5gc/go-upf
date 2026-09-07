package pfcp

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

func fullRuleRequest() *message.SessionModificationRequest {
	pdi := ie.NewPDI(
		ie.NewSDFFilter("permit out ip from 10.0.0.1 123 to 20.0.0.1 456", "", "", "", 0),
		ie.NewUEIPAddress(2, "60.60.0.1", "", 0, 0),
		ie.NewFTEID(1, 123, net.IPv4(10, 0, 0, 2).To4(), nil, 0),
		ie.NewSourceInterface(ie.SrcInterfaceAccess),
	)
	return &message.SessionModificationRequest{
		CreatePDR: []*ie.IE{ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(100), pdi,
			ie.NewOuterHeaderRemoval(0, 0), ie.NewFARID(2), ie.NewQERID(3), ie.NewQERID(4), ie.NewURRID(5))},
		CreateFAR: []*ie.IE{ie.NewCreateFAR(ie.NewFARID(2), ie.NewApplyAction(2), ie.NewBARID(6),
			ie.NewForwardingParameters(ie.NewDestinationInterface(0), ie.NewNetworkInstance("internet"),
				ie.NewOuterHeaderCreation(0x100, 321, "10.0.0.3", "", 0, 0, 0), ie.NewForwardingPolicy("1")))},
		CreateQER: []*ie.IE{ie.NewCreateQER(ie.NewQERID(3), ie.NewGateStatus(0, 1),
			ie.NewQERCorrelationID(99), ie.NewMBR(0xffffffffff, 123), ie.NewGBR(456, 789), ie.NewQFI(9), ie.NewRQI(1), ie.NewPagingPolicyIndicator(2))},
		CreateURR: []*ie.IE{ie.NewCreateURR(ie.NewURRID(5), ie.NewMeasurementMethod(0, 1, 1), ie.NewReportingTriggers(1, 0, 0),
			ie.NewMeasurementPeriod(time.Second), ie.NewMeasurementInformation(0x1f), ie.NewVolumeThreshold(7, 1, 2, 3), ie.NewVolumeQuota(7, 4, 5, 6))},
		CreateBAR: ie.NewCreateBAR(ie.NewBARID(6), ie.NewDownlinkDataNotificationDelay(100*time.Millisecond), ie.NewSuggestedBufferingPacketsCount(7)),
		UpdatePDR: []*ie.IE{ie.NewUpdatePDR(ie.NewPDRID(1), ie.NewPrecedence(0), pdi, ie.NewQERID(4))},
		UpdateFAR: []*ie.IE{ie.NewUpdateFAR(ie.NewFARID(2), ie.NewApplyAction(4), ie.NewBARID(6),
			ie.NewUpdateForwardingParameters(ie.NewForwardingPolicy("2"), ie.NewPFCPSMReqFlags(1)))},
		UpdateQER: []*ie.IE{ie.NewUpdateQER(ie.NewQERID(3), ie.NewMBR(0, 0), ie.NewQFI(63))},
		UpdateURR: []*ie.IE{ie.NewUpdateURR(ie.NewURRID(5), ie.NewMeasurementInformation(0), ie.NewMeasurementPeriod(2*time.Second), ie.NewReportingTriggers(0, 0, 0))},
		UpdateBAR: ie.NewUpdateBARWithinSessionModificationRequest(ie.NewBARID(6), ie.NewSuggestedBufferingPacketsCount(0)),
		QueryURR:  []*ie.IE{ie.NewQueryURR(ie.NewURRID(5))},
		RemovePDR: []*ie.IE{ie.NewRemovePDR(ie.NewPDRID(1))},
		RemoveFAR: []*ie.IE{ie.NewRemoveFAR(ie.NewFARID(2))},
		RemoveQER: []*ie.IE{ie.NewRemoveQER(ie.NewQERID(3))},
		RemoveURR: []*ie.IE{ie.NewRemoveURR(ie.NewURRID(5))},
		RemoveBAR: ie.NewRemoveBAR(ie.NewBARID(6)),
	}
}

func TestTypedEstablishmentAndResponseMetadata(t *testing.T) {
	req := fullRuleRequest()
	sess := &Session{LocalID: 42}
	changes, err := sess.BuildEstablishmentPlan(&message.SessionEstablishmentRequest{
		CreatePDR: req.CreatePDR, CreateFAR: req.CreateFAR, CreateQER: req.CreateQER, CreateURR: req.CreateURR, CreateBAR: req.CreateBAR,
	})
	require.NoError(t, err)
	require.Len(t, changes.CreatePDRs, 1)
	require.Len(t, changes.CreateFARs, 1)
	require.Len(t, changes.CreateQERs, 1)
	require.Len(t, changes.CreateURRs, 1)
	require.Len(t, changes.CreateBARs, 1)
	require.Equal(t, uint64(42), changes.SEID)
	require.Equal(t, uint64(0xffffffffff)*1000, changes.CreateQERs[0].MBR.UplinkBps)
	// Drop/mutate the original request: decoded data and response must remain valid.
	for i := range req.CreatePDR[0].Payload {
		req.CreatePDR[0].Payload[i] = 0
	}
	response := createdPDRResponseIEs(changes)
	require.Len(t, response, 1)
	id, err := response[0].PDRID()
	require.NoError(t, err)
	require.Equal(t, uint16(1), id)
	addr, err := response[0].UEIPAddress()
	require.NoError(t, err)
	require.Equal(t, "60.60.0.1", addr.IPv4Address.String())
	require.Equal(t, uint32(123), changes.CreatePDRs[0].PDI.FTEID.TEID)

}

func TestTypedPatchesPreservePresence(t *testing.T) {
	changes, err := (&Session{}).BuildModificationPlan(fullRuleRequest())
	require.NoError(t, err)
	require.Nil(t, changes.UpdateQERs[0].GateStatus)
	require.Nil(t, changes.UpdateQERs[0].GBR)
	require.NotNil(t, changes.UpdateQERs[0].MBR)
	require.Zero(t, changes.UpdateQERs[0].MBR.UplinkBps)
	require.NotNil(t, changes.UpdatePDRs[0].Precedence)
	require.Zero(t, *changes.UpdatePDRs[0].Precedence)
	require.Nil(t, changes.UpdatePDRs[0].FARID)
	require.Equal(t, []uint32{4}, changes.UpdatePDRs[0].QERIDs)
	require.Nil(t, changes.UpdatePDRs[0].URRIDs)
	require.NotNil(t, changes.UpdateFARs[0].ForwardingParameters)
	require.Nil(t, changes.UpdateFARs[0].ForwardingParameters.OuterHeaderCreation)
	require.Nil(t, changes.UpdateURRs[0].MeasureMethod)
	require.Zero(t, *changes.UpdateURRs[0].MeasureInformation)
	require.Zero(t, *changes.UpdateURRs[0].ReportingTriggers)
	require.Nil(t, changes.UpdateBARs[0].DownlinkDataNotificationDelay)
	require.Zero(t, *changes.UpdateBARs[0].SuggestedBufferingPacketsCount)
}

func TestTypedParserRejectsMissingAndMalformedFields(t *testing.T) {
	tests := []struct {
		name  string
		req   *message.SessionModificationRequest
		cause error
	}{
		{"nil request", nil, ErrMissingMandatoryIE},
		{"nil rule", &message.SessionModificationRequest{CreatePDR: []*ie.IE{nil}}, ErrMissingMandatoryIE},
		{"PDR ID", &message.SessionModificationRequest{CreatePDR: []*ie.IE{ie.NewCreatePDR(ie.NewPrecedence(1), ie.NewPDI(ie.NewSourceInterface(0)))}}, ErrMissingMandatoryIE},
		{"PDI source", &message.SessionModificationRequest{CreatePDR: []*ie.IE{ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(1), ie.NewPDI())}}, ErrMissingMandatoryIE},
		{"QER gate", &message.SessionModificationRequest{CreateQER: []*ie.IE{ie.NewCreateQER(ie.NewQERID(1))}}, ErrMissingMandatoryIE},
		{"FAR action", &message.SessionModificationRequest{CreateFAR: []*ie.IE{ie.NewCreateFAR(ie.NewFARID(1))}}, ErrMissingMandatoryIE},
		{"FAR destination", &message.SessionModificationRequest{CreateFAR: []*ie.IE{ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(2), ie.NewForwardingParameters())}}, ErrMissingMandatoryIE},
		{"URR method", &message.SessionModificationRequest{CreateURR: []*ie.IE{ie.NewCreateURR(ie.NewURRID(1), ie.NewReportingTriggers(0, 0, 0))}}, ErrMissingMandatoryIE},
		{"URR triggers", &message.SessionModificationRequest{CreateURR: []*ie.IE{ie.NewCreateURR(ie.NewURRID(1), ie.NewMeasurementMethod(0, 1, 0))}}, ErrMissingMandatoryIE},
		{"BAR ID", &message.SessionModificationRequest{CreateBAR: ie.NewCreateBAR()}, ErrMissingMandatoryIE},
		{"QFI zero", &message.SessionModificationRequest{UpdateQER: []*ie.IE{ie.NewUpdateQER(ie.NewQERID(1), ie.NewQFI(0))}}, ErrMissingMandatoryIE},
		{"short MBR", &message.SessionModificationRequest{UpdateQER: []*ie.IE{ie.NewUpdateQER(ie.NewQERID(1), ie.New(ie.MBR, []byte{1}))}}, ErrMissingMandatoryIE},
		{"truncated SDF", &message.SessionModificationRequest{CreatePDR: []*ie.IE{ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(1), ie.NewPDI(ie.NewSourceInterface(0), ie.New(ie.SDFFilter, []byte{1, 0, 0, 5, 0})))}}, ErrRuleCreationModificationFailed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := (&Session{}).BuildModificationPlan(tt.req)
			require.ErrorIs(t, err, tt.cause)
			require.Nil(t, result, "a parse failure must discard the whole change set")
		})
	}
	_, err := (&Session{}).BuildEstablishmentPlan(nil)
	require.ErrorIs(t, err, ErrMissingMandatoryIE)
}
