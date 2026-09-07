package rules

import (
	"net"
	"reflect"
	"testing"
)

func rulePtr[T any](v T) *T { return &v }

func TestPDRMergePresenceAndOwnership(t *testing.T) {
	base := PDRConfig{
		PDRID: 1, FARID: rulePtr(uint32(2)), QERIDs: []uint32{3}, URRIDs: []uint32{4},
		PDI: &PDI{
			FTEID:       &FTEID{IPv4Address: net.IP{10, 0, 0, 1}},
			UEIPAddress: &UEIPAddress{IPv6Address: net.IP{1, 2, 3, 4}},
			SDFFilters: []SDFFilter{{FlowDescription: &FlowDesc{
				Src:      &net.IPNet{IP: net.IP{10, 0, 0, 0}, Mask: net.IPMask{255, 255, 255, 0}},
				Dst:      &net.IPNet{IP: net.IP{20, 0, 0, 0}, Mask: net.IPMask{255, 255, 0, 0}},
				SrcPorts: [][]uint16{{80, 90}}, DstPorts: [][]uint16{{443, 443}},
			}, FlowLabel: rulePtr("abc")}},
		},
	}
	merged := base.Merge(PDRPatch{PDRID: 1, Precedence: rulePtr(uint32(0))})
	if merged.Precedence == nil || *merged.Precedence != 0 || !reflect.DeepEqual(merged.PDI, base.PDI) {
		t.Fatal("absent fields or explicit zero lost")
	}
	*merged.FARID = 99
	merged.QERIDs[0] = 99
	merged.URRIDs[0] = 99
	merged.PDI.FTEID.IPv4Address[0] = 99
	merged.PDI.UEIPAddress.IPv6Address[0] = 99
	filter := &merged.PDI.SDFFilters[0]
	*filter.FlowLabel = "changed"
	filter.FlowDescription.Src.IP[0] = 99
	filter.FlowDescription.Src.Mask[0] = 0
	filter.FlowDescription.Dst.IP[0] = 99
	filter.FlowDescription.Dst.Mask[0] = 0
	filter.FlowDescription.SrcPorts[0][0] = 99
	filter.FlowDescription.DstPorts[0][0] = 99
	original := base.PDI.SDFFilters[0]
	if *base.FARID != 2 ||
		base.QERIDs[0] != 3 ||
		base.URRIDs[0] != 4 ||
		base.PDI.FTEID.IPv4Address[0] != 10 ||
		base.PDI.UEIPAddress.IPv6Address[0] != 1 ||
		*original.FlowLabel != "abc" ||
		original.FlowDescription.Src.IP[0] != 10 ||
		original.FlowDescription.Src.Mask[0] != 255 ||
		original.FlowDescription.Dst.IP[0] != 20 ||
		original.FlowDescription.Dst.Mask[0] != 255 ||
		original.FlowDescription.SrcPorts[0][0] != 80 ||
		original.FlowDescription.DstPorts[0][0] != 443 {
		t.Fatal("merge aliases nested base data")
	}
	replacement := &PDI{SourceInterface: 1}
	merged = base.Merge(PDRPatch{PDRID: 1, PDI: replacement, QERIDs: []uint32{}})
	replacement.SourceInterface = 99
	if merged.PDI.SourceInterface != 1 ||
		merged.PDI.FTEID != nil ||
		merged.PDI.SDFFilters != nil ||
		merged.QERIDs == nil ||
		len(merged.QERIDs) != 0 ||
		len(merged.URRIDs) != 1 {
		t.Fatal("PDI replacement or relationship presence semantics changed")
	}
}

func TestFARNestedMergeAndReplacement(t *testing.T) {
	base := FARConfig{FARID: 1, ForwardingParameters: &ForwardingParameters{
		NetworkInstance: rulePtr("internet"), OuterHeaderCreation: &OuterHeaderCreation{TEID: rulePtr(uint32(42)), IPv4Address: net.IP{10, 0, 0, 1}},
	}}
	merged := base.Merge(FARPatch{FARID: 1, ForwardingParameters: &ForwardingParameters{SMRequestFlags: rulePtr(uint8(0))}})
	if *merged.ForwardingParameters.NetworkInstance != "internet" ||
		*merged.ForwardingParameters.OuterHeaderCreation.TEID != 42 ||
		*merged.ForwardingParameters.SMRequestFlags != 0 {
		t.Fatal("nested partial update lost fields")
	}
	merged.ForwardingParameters.OuterHeaderCreation.IPv4Address[0] = 99
	*merged.ForwardingParameters.OuterHeaderCreation.TEID = 99
	if base.ForwardingParameters.OuterHeaderCreation.IPv4Address[0] != 10 ||
		*base.ForwardingParameters.OuterHeaderCreation.TEID != 42 {
		t.Fatal("FAR aliases base data")
	}
	merged = base.Merge(FARPatch{FARID: 1, ForwardingParameters: &ForwardingParameters{OuterHeaderCreation: &OuterHeaderCreation{Description: 1}}})
	if merged.ForwardingParameters.OuterHeaderCreation.TEID != nil ||
		merged.ForwardingParameters.OuterHeaderCreation.IPv4Address != nil ||
		*merged.ForwardingParameters.NetworkInstance != "internet" {
		t.Fatal("outer header creation was not replaced as a unit")
	}
}
