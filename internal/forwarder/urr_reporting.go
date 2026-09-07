package forwarder

import (
	"github.com/free5gc/go-gtp5gnl"
	"github.com/free5gc/go-upf/internal/report"
	"github.com/khirono/go-nl"
	"time"
)

// urrReportingPatch bridges the existing netlink builders to semantic reporting
// fields. Attribute decoding remains private to forwarder during migration.
// Period conversion preserves the existing applied-attribute representation.
func urrReportingPatch(attrs []nl.Attr) URRReportingPatch {
	var patch URRReportingPatch
	for _, attr := range attrs {
		switch attr.Type {
		case gtp5gnl.URR_MEASUREMENT_METHOD:
			if v, ok := attr.Value.(nl.AttrU8); ok {
				value := uint8(v)
				patch.MeasureMethod = &value
			}
		case gtp5gnl.URR_MEASUREMENT_INFO:
			if v, ok := attr.Value.(nl.AttrU64); ok {
				value := uint64(v)
				patch.MeasureInformation = &value
			}
		case gtp5gnl.URR_REPORTING_TRIGGER:
			if v, ok := attr.Value.(nl.AttrU32); ok {
				patch.ReportingTrigger = &report.ReportingTrigger{Flags: uint32(v)}
			}
		case gtp5gnl.URR_MEASUREMENT_PERIOD:
			if v, ok := attr.Value.(nl.AttrU32); ok {
				value := time.Duration(v)
				patch.MeasurePeriod = &value
			}
		}
	}
	return patch
}
