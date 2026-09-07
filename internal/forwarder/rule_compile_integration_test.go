package forwarder_test

import (
	"github.com/free5gc/go-upf/internal/forwarder"
	"github.com/free5gc/go-upf/internal/pfcp"
	"github.com/khirono/go-nl"
	"github.com/stretchr/testify/require"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
	"net"
	"sort"
	"testing"
	"time"
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

// Attribute order between different types has no semantic significance. Preserve
// ordering within repeated types, including SDF filters and relationship IDs.
func normalizedAttrs(attrs []nl.Attr) []nl.Attr {
	if attrs == nil {
		return nil
	}
	result := append([]nl.Attr{}, attrs...)
	for i, a := range result {
		if nested, ok := a.Value.(nl.AttrList); ok {
			result[i].Value = nl.AttrList(normalizedAttrs(nested))
		}
	}
	sort.SliceStable(result, func(i, j int) bool { return result[i].Type < result[j].Type })
	return result
}

func TestTypedRuleChangesMatchLegacyBuilders(t *testing.T) {
	sess := &pfcp.Session{LocalID: 42} // No driver: parsing must be independent of datapath.
	req := fullRuleRequest()
	changes, err := sess.BuildModificationPlan(req)
	require.NoError(t, err)
	plan, err := forwarder.CompileRuleChangesForTest(changes)
	require.NoError(t, err)
	require.Nil(t, plan.Rollback)
	legacy, err := forwarder.LegacyRuleChangesForTest(42, req)
	require.NoError(t, err)
	t.Run("CreatePDR", func(t *testing.T) {
		old := legacy.CreatePDRs[0]
		require.NoError(t, err)
		require.Nil(t, plan.CreatePDRs[0].OriginalIE)
		old.OriginalIE = nil
		old.Attrs = normalizedAttrs(old.Attrs)
		actual := *plan.CreatePDRs[0]
		actual.Attrs = normalizedAttrs(actual.Attrs)
		require.Equal(t, *old, actual)
	})
	t.Run("CreateFAR", func(t *testing.T) {
		old := legacy.CreateFARs[0]
		require.NoError(t, err)
		require.Nil(t, plan.CreateFARs[0].OriginalIE)
		old.OriginalIE = nil
		old.Attrs = normalizedAttrs(old.Attrs)
		actual := *plan.CreateFARs[0]
		actual.Attrs = normalizedAttrs(actual.Attrs)
		require.Equal(t, *old, actual)
	})
	t.Run("CreateQER", func(t *testing.T) {
		old := legacy.CreateQERs[0]
		require.NoError(t, err)
		require.Nil(t, plan.CreateQERs[0].OriginalIE)
		old.OriginalIE = nil
		old.Attrs = normalizedAttrs(old.Attrs)
		actual := *plan.CreateQERs[0]
		actual.Attrs = normalizedAttrs(actual.Attrs)
		require.Equal(t, *old, actual)
	})
	t.Run("CreateURR", func(t *testing.T) {
		old := legacy.CreateURRs[0]
		require.NoError(t, err)
		require.Nil(t, plan.CreateURRs[0].OriginalIE)
		old.OriginalIE = nil
		old.Attrs = normalizedAttrs(old.Attrs)
		actual := *plan.CreateURRs[0]
		actual.Attrs = normalizedAttrs(actual.Attrs)
		require.Equal(t, *old, actual)
	})
	t.Run("CreateBAR", func(t *testing.T) {
		old := legacy.CreateBARs[0]
		require.NoError(t, err)
		require.Nil(t, plan.CreateBARs[0].OriginalIE)
		old.OriginalIE = nil
		old.Attrs = normalizedAttrs(old.Attrs)
		actual := *plan.CreateBARs[0]
		actual.Attrs = normalizedAttrs(actual.Attrs)
		require.Equal(t, *old, actual)
	})
	t.Run("UpdatePDR", func(t *testing.T) {
		old := legacy.UpdatePDRs[0]
		require.NoError(t, err)
		require.Nil(t, plan.UpdatePDRs[0].OriginalIE)
		old.OriginalIE = nil
		old.Attrs = normalizedAttrs(old.Attrs)
		actual := *plan.UpdatePDRs[0]
		actual.Attrs = normalizedAttrs(actual.Attrs)
		require.Equal(t, *old, actual)
	})
	t.Run("UpdateFAR", func(t *testing.T) {
		old := legacy.UpdateFARs[0]
		require.NoError(t, err)
		require.Nil(t, plan.UpdateFARs[0].OriginalIE)
		old.OriginalIE = nil
		old.Attrs = normalizedAttrs(old.Attrs)
		actual := *plan.UpdateFARs[0]
		actual.Attrs = normalizedAttrs(actual.Attrs)
		require.Equal(t, *old, actual)
	})
	t.Run("UpdateQER", func(t *testing.T) {
		old := legacy.UpdateQERs[0]
		require.NoError(t, err)
		require.Nil(t, plan.UpdateQERs[0].OriginalIE)
		old.OriginalIE = nil
		old.Attrs = normalizedAttrs(old.Attrs)
		actual := *plan.UpdateQERs[0]
		actual.Attrs = normalizedAttrs(actual.Attrs)
		require.Equal(t, *old, actual)
	})
	t.Run("UpdateURR", func(t *testing.T) {
		old := legacy.UpdateURRs[0]
		require.NoError(t, err)
		require.Nil(t, plan.UpdateURRs[0].OriginalIE)
		old.OriginalIE = nil
		old.Attrs = normalizedAttrs(old.Attrs)
		actual := *plan.UpdateURRs[0]
		actual.Attrs = normalizedAttrs(actual.Attrs)
		require.Equal(t, *old, actual)
	})
	t.Run("UpdateBAR", func(t *testing.T) {
		old := legacy.UpdateBARs[0]
		require.NoError(t, err)
		require.Nil(t, plan.UpdateBARs[0].OriginalIE)
		old.OriginalIE = nil
		old.Attrs = normalizedAttrs(old.Attrs)
		actual := *plan.UpdateBARs[0]
		actual.Attrs = normalizedAttrs(actual.Attrs)
		require.Equal(t, *old, actual)
	})
	t.Run("RemovePDR", func(t *testing.T) {
		old := legacy.RemovePDRs[0]
		require.NoError(t, err)
		require.Nil(t, plan.RemovePDRs[0].OriginalIE)
		old.OriginalIE = nil
		old.Attrs = normalizedAttrs(old.Attrs)
		actual := *plan.RemovePDRs[0]
		actual.Attrs = normalizedAttrs(actual.Attrs)
		require.Equal(t, *old, actual)
	})
	t.Run("RemoveFAR", func(t *testing.T) {
		old := legacy.RemoveFARs[0]
		require.NoError(t, err)
		require.Nil(t, plan.RemoveFARs[0].OriginalIE)
		old.OriginalIE = nil
		old.Attrs = normalizedAttrs(old.Attrs)
		actual := *plan.RemoveFARs[0]
		actual.Attrs = normalizedAttrs(actual.Attrs)
		require.Equal(t, *old, actual)
	})
	t.Run("RemoveQER", func(t *testing.T) {
		old := legacy.RemoveQERs[0]
		require.NoError(t, err)
		require.Nil(t, plan.RemoveQERs[0].OriginalIE)
		old.OriginalIE = nil
		old.Attrs = normalizedAttrs(old.Attrs)
		actual := *plan.RemoveQERs[0]
		actual.Attrs = normalizedAttrs(actual.Attrs)
		require.Equal(t, *old, actual)
	})
	t.Run("RemoveURR", func(t *testing.T) {
		old := legacy.RemoveURRs[0]
		require.NoError(t, err)
		require.Nil(t, plan.RemoveURRs[0].OriginalIE)
		old.OriginalIE = nil
		old.Attrs = normalizedAttrs(old.Attrs)
		actual := *plan.RemoveURRs[0]
		actual.Attrs = normalizedAttrs(actual.Attrs)
		require.Equal(t, *old, actual)
	})
	t.Run("RemoveBAR", func(t *testing.T) {
		old := legacy.RemoveBARs[0]
		require.NoError(t, err)
		require.Nil(t, plan.RemoveBARs[0].OriginalIE)
		old.OriginalIE = nil
		old.Attrs = normalizedAttrs(old.Attrs)
		actual := *plan.RemoveBARs[0]
		actual.Attrs = normalizedAttrs(actual.Attrs)
		require.Equal(t, *old, actual)
	})
	old := legacy.QueryURRs[0]
	require.NoError(t, err)
	old.OriginalIE = nil
	require.Equal(t, old, plan.QueryURRs[0])
}
