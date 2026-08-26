package forwarder

import (
	"testing"

	"github.com/khirono/go-nl"

	"github.com/free5gc/go-gtp5gnl"
)

func decodePlanFlowQoS(t *testing.T, plan *PDRPlan) gtp5gnl.FlowQoS {
	t.Helper()

	for _, attr := range plan.Attrs {
		if attr.Type != gtp5gnl.PDR_FLOW_QOS {
			continue
		}
		attrs, ok := attr.Value.(nl.AttrList)
		if !ok {
			t.Fatalf("PDR_FLOW_QOS value type = %T, want nl.AttrList", attr.Value)
		}
		b := make([]byte, attrs.Len())
		n, err := attrs.Encode(b)
		if err != nil {
			t.Fatalf("encode PDR_FLOW_QOS: %v", err)
		}
		flowQoS, err := gtp5gnl.DecodeFlowQoS(b[:n])
		if err != nil {
			t.Fatalf("decode PDR_FLOW_QOS: %v", err)
		}
		return flowQoS
	}

	t.Fatal("PDR_FLOW_QOS attribute not found")
	return gtp5gnl.FlowQoS{}
}

func TestPDRPlanSetAndClearFlowQoSBinding(t *testing.T) {
	plan := &PDRPlan{
		Attrs: []nl.Attr{
			{Type: gtp5gnl.PDR_PRECEDENCE, Value: nl.AttrU32(255)},
		},
	}

	first := FlowQoSBinding{
		PolicyID:   1001,
		TCClassID:  0x00010020,
		Generation: 1,
	}
	if err := plan.SetFlowQoSBinding(first); err != nil {
		t.Fatalf("SetFlowQoSBinding: %v", err)
	}
	if len(plan.Attrs) != 2 {
		t.Fatalf("attribute count = %d, want 2", len(plan.Attrs))
	}
	got := decodePlanFlowQoS(t, plan)
	if got.Version != gtp5gnl.SHARED_MARK_ABI_VERSION ||
		got.PolicyID != first.PolicyID ||
		got.TCClassID != first.TCClassID ||
		got.Flags != gtp5gnl.FLOW_QOS_VALID ||
		got.Generation != first.Generation {
		t.Fatalf("FlowQoS = %+v, want binding %+v", got, first)
	}

	replacement := FlowQoSBinding{
		PolicyID:   1002,
		TCClassID:  0x00010030,
		Generation: 2,
	}
	if err := plan.SetFlowQoSBinding(replacement); err != nil {
		t.Fatalf("replace FlowQoS binding: %v", err)
	}
	if len(plan.Attrs) != 2 {
		t.Fatalf("replacement duplicated attribute; count = %d", len(plan.Attrs))
	}
	got = decodePlanFlowQoS(t, plan)
	if got.PolicyID != replacement.PolicyID ||
		got.TCClassID != replacement.TCClassID ||
		got.Generation != replacement.Generation {
		t.Fatalf("replacement FlowQoS = %+v, want %+v", got, replacement)
	}

	if err := plan.ClearFlowQoSBinding(3); err != nil {
		t.Fatalf("ClearFlowQoSBinding: %v", err)
	}
	if len(plan.Attrs) != 2 {
		t.Fatalf("clear duplicated attribute; count = %d", len(plan.Attrs))
	}
	got = decodePlanFlowQoS(t, plan)
	if got.Version != gtp5gnl.SHARED_MARK_ABI_VERSION ||
		got.Flags != 0 ||
		got.PolicyID != 0 ||
		got.TCClassID != 0 ||
		got.Generation != 3 {
		t.Fatalf("cleared FlowQoS = %+v", got)
	}
}

func TestPDRPlanRejectsFlowQoSPolicyIDOverflow(t *testing.T) {
	plan := new(PDRPlan)
	err := plan.SetFlowQoSBinding(FlowQoSBinding{
		PolicyID: gtp5gnl.FLOW_QOS_POLICY_ID_MAX + 1,
	})
	if err == nil {
		t.Fatal("SetFlowQoSBinding succeeded, want error")
	}
	if len(plan.Attrs) != 0 {
		t.Fatalf("invalid binding changed plan attributes: %+v", plan.Attrs)
	}
}

func TestValidateGtp5gVersionInfo(t *testing.T) {
	abiV1 := gtp5gnl.SHARED_MARK_ABI_VERSION
	abiV2 := abiV1 + 1

	tests := []struct {
		name    string
		info    *gtp5gnl.VersionInfo
		wantErr bool
	}{
		{
			name: "supported",
			info: &gtp5gnl.VersionInfo{
				DriverVersion: "0.10.2",
				SharedMarkABI: &abiV1,
			},
		},
		{name: "nil info", wantErr: true},
		{name: "empty driver version", info: &gtp5gnl.VersionInfo{}, wantErr: true},
		{
			name:    "legacy module",
			info:    &gtp5gnl.VersionInfo{DriverVersion: "0.10.2"},
			wantErr: true,
		},
		{
			name: "wrong shared mark ABI",
			info: &gtp5gnl.VersionInfo{
				DriverVersion: "0.10.2",
				SharedMarkABI: &abiV2,
			},
			wantErr: true,
		},
		{
			name: "unsupported driver version",
			info: &gtp5gnl.VersionInfo{
				DriverVersion: "0.10.3",
				SharedMarkABI: &abiV1,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateGtp5gVersionInfo(tt.info)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateGtp5gVersionInfo() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
