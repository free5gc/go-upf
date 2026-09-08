package pfcp

import (
	"errors"
	"testing"

	"github.com/wmnsk/go-pfcp/ie"
)

func TestRuleParsersRejectMissingMandatoryIEs(t *testing.T) {
	reportingTriggers := func() *ie.IE {
		return ie.NewReportingTriggers(0, 0)
	}
	measurementMethod := func() *ie.IE {
		return ie.NewMeasurementMethod(0, 1, 0)
	}

	tests := []struct {
		name  string
		build func() error
	}{
		{
			name: "CreatePDR/PDR ID",
			build: func() error {
				_, err := parseCreatePDR(ie.NewCreatePDR(
					ie.NewPrecedence(100),
					ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess)),
				))
				return err
			},
		},
		{
			name: "CreatePDR/Precedence",
			build: func() error {
				_, err := parseCreatePDR(ie.NewCreatePDR(
					ie.NewPDRID(1),
					ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess)),
				))
				return err
			},
		},
		{
			name: "CreatePDR/PDI",
			build: func() error {
				_, err := parseCreatePDR(ie.NewCreatePDR(
					ie.NewPDRID(1),
					ie.NewPrecedence(100),
				))
				return err
			},
		},
		{
			name: "PDI/Source Interface",
			build: func() error {
				_, err := parseCreatePDR(ie.NewCreatePDR(
					ie.NewPDRID(1),
					ie.NewPrecedence(100),
					ie.NewPDI(),
				))
				return err
			},
		},
		{
			name: "UpdatePDR/PDR ID",
			build: func() error {
				_, err := parseUpdatePDR(ie.NewUpdatePDR(ie.NewPrecedence(100)))
				return err
			},
		},
		{
			name: "CreateFAR/FAR ID",
			build: func() error {
				_, err := parseCreateFAR(ie.NewCreateFAR(ie.NewApplyAction(0x01)))
				return err
			},
		},
		{
			name: "CreateFAR/Apply Action",
			build: func() error {
				_, err := parseCreateFAR(ie.NewCreateFAR(ie.NewFARID(1)))
				return err
			},
		},
		{
			name: "ForwardingParameters/Destination Interface",
			build: func() error {
				_, err := parseCreateFAR(ie.NewCreateFAR(
					ie.NewFARID(1),
					ie.NewApplyAction(0x02),
					ie.NewForwardingParameters(ie.NewNetworkInstance("internet")),
				))
				return err
			},
		},
		{
			name: "UpdateFAR/FAR ID",
			build: func() error {
				_, err := parseUpdateFAR(ie.NewUpdateFAR(ie.NewApplyAction(0x01)))
				return err
			},
		},
		{
			name: "CreateQER/QER ID",
			build: func() error {
				_, err := parseCreateQER(ie.NewCreateQER(
					ie.NewGateStatus(ie.GateStatusOpen, ie.GateStatusOpen),
				))
				return err
			},
		},
		{
			name: "CreateQER/Gate Status",
			build: func() error {
				_, err := parseCreateQER(ie.NewCreateQER(ie.NewQERID(1)))
				return err
			},
		},
		{
			name: "UpdateQER/QER ID",
			build: func() error {
				_, err := parseUpdateQER(ie.NewUpdateQER(ie.NewQFI(9)))
				return err
			},
		},
		{
			name: "CreateURR/URR ID",
			build: func() error {
				_, err := parseCreateURR(ie.NewCreateURR(
					measurementMethod(),
					reportingTriggers(),
				))
				return err
			},
		},
		{
			name: "CreateURR/Measurement Method",
			build: func() error {
				_, err := parseCreateURR(ie.NewCreateURR(
					ie.NewURRID(1),
					reportingTriggers(),
				))
				return err
			},
		},
		{
			name: "CreateURR/Reporting Triggers",
			build: func() error {
				_, err := parseCreateURR(ie.NewCreateURR(
					ie.NewURRID(1),
					measurementMethod(),
				))
				return err
			},
		},
		{
			name: "UpdateURR/URR ID",
			build: func() error {
				_, err := parseUpdateURR(ie.NewUpdateURR(measurementMethod()))
				return err
			},
		},
		{
			name: "CreateBAR/BAR ID",
			build: func() error {
				_, err := parseCreateBAR(ie.NewCreateBAR())
				return err
			},
		},
		{
			name: "UpdateBAR/BAR ID",
			build: func() error {
				_, err := parseUpdateBAR(ie.NewUpdateBARWithinSessionModificationRequest())
				return err
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.build()
			if !errors.Is(err, ErrMissingMandatoryIE) {
				t.Fatalf("expected mandatory-rule-IE error, got %v", err)
			}
		})
	}
}
