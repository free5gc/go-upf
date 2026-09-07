package forwarder

import (
	"testing"
	"time"

	"github.com/free5gc/go-gtp5gnl"
	"github.com/khirono/go-nl"
	"github.com/stretchr/testify/require"
	"github.com/wmnsk/go-pfcp/ie"
)

func TestURRBuildersPublishReportingPresence(t *testing.T) {
	g := new(Gtp5g)
	create, err := g.BuildCreateURRPlan(10, ie.NewCreateURR(
		ie.NewURRID(20), ie.NewMeasurementMethod(0, 1, 1),
		ie.NewReportingTriggers(1, 0, 0), ie.NewMeasurementPeriod(time.Second),
	))
	require.NoError(t, err)
	require.Equal(t, uint8(3), *create.ReportingConfig.MeasureMethod)
	require.True(t, create.ReportingConfig.ReportingTrigger.PERIO())
	require.Equal(t, time.Second, *create.ReportingConfig.MeasurePeriod)
	require.Nil(t, create.ReportingConfig.MeasureInformation)

	update, err := g.BuildUpdateURRPlan(10, ie.NewUpdateURR(
		ie.NewURRID(20), ie.NewMeasurementInformation(0),
		ie.NewReportingTriggers(0, 0, 0),
	))
	require.NoError(t, err)
	require.Nil(t, update.ReportingConfig.MeasureMethod)
	require.Nil(t, update.ReportingConfig.MeasurePeriod)
	require.NotNil(t, update.ReportingConfig.MeasureInformation)
	require.Zero(t, *update.ReportingConfig.MeasureInformation)
	require.NotNil(t, update.ReportingConfig.ReportingTrigger)
	require.Zero(t, update.ReportingConfig.ReportingTrigger.Flags)
}

func TestURRSnapshotPreservesOmittedReportingFields(t *testing.T) {
	d := &snapshotDriver{}
	s := NewSessionDatapath(d, 10)
	attrs := []nl.Attr{
		{Type: gtp5gnl.URR_MEASUREMENT_METHOD, Value: nl.AttrU8(3)},
		{Type: gtp5gnl.URR_REPORTING_TRIGGER, Value: nl.AttrU32(1)},
		{Type: gtp5gnl.URR_MEASUREMENT_PERIOD, Value: nl.AttrU32(time.Second)},
	}
	_, err := s.ExecuteEstablishmentPlan(&ModificationPlan{SEID: 10,
		CreateURRs: []*URRPlan{{URRID: 20, OID: gtp5gnl.OID{10, 20}, Attrs: attrs}},
	})
	require.NoError(t, err)
	_, err = s.ExecuteModificationPlan(&ModificationPlan{SEID: 10, UpdateURRs: []*URRPlan{{URRID: 20,
		Attrs: []nl.Attr{{Type: gtp5gnl.URR_MEASUREMENT_PERIOD, Value: nl.AttrU32(2 * time.Second)}},
	}}})
	require.NoError(t, err)
	require.Equal(t, time.Second, d.seen.Rollback.URRs[20].MeasurePeriod)
	_, err = s.ExecuteModificationPlan(&ModificationPlan{SEID: 10, RemoveURRs: []*URRPlan{{URRID: 20}}})
	require.NoError(t, err)
	old := d.seen.Rollback.URRs[20]
	require.Equal(t, 2*time.Second, old.MeasurePeriod)
	require.Equal(t, uint8(3), old.MeasureMethod)
	require.True(t, old.ReportingTrigger.PERIO())
	require.Len(t, old.Attrs, 3)
}
