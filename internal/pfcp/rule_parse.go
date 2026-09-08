package pfcp

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/pkg/errors"
	"github.com/wmnsk/go-pfcp/ie"

	"github.com/free5gc/go-upf/internal/report"
	"github.com/free5gc/go-upf/internal/rules"
	utilpfcp "github.com/free5gc/util/pfcp"
)

func valueOf[T any](value T, err error) (*T, error) {
	if err != nil {
		return nil, err
	}
	return &value, nil
}

func requireRuleField(name string, present bool) error {
	if !present {
		return errors.Wrap(ErrMissingMandatoryIE, name)
	}
	return nil
}

func ruleChildren(i *ie.IE, kind uint16) ([]*ie.IE, error) {
	if i == nil {
		return nil, errors.Wrap(ErrMissingMandatoryIE, "nil rule IE")
	}
	if i.Type != kind {
		return nil, fmt.Errorf("unexpected rule IE type %d, expected %d", i.Type, kind)
	}
	var children []*ie.IE
	var err error
	switch kind {
	case ie.CreatePDR:
		children, err = i.CreatePDR()
	case ie.UpdatePDR:
		children, err = i.UpdatePDR()
	case ie.CreateFAR:
		children, err = i.CreateFAR()
	case ie.UpdateFAR:
		children, err = i.UpdateFAR()
	case ie.CreateQER:
		children, err = i.CreateQER()
	case ie.UpdateQER:
		children, err = i.UpdateQER()
	case ie.CreateURR:
		children, err = i.CreateURR()
	case ie.UpdateURR:
		children, err = i.UpdateURR()
	case ie.CreateBAR:
		children, err = i.CreateBAR()
	case ie.UpdateBARWithinSessionModificationRequest:
		children, err = i.UpdateBAR()
	default:
		return nil, fmt.Errorf("unsupported grouped rule IE %d", kind)
	}
	if err != nil {
		return nil, err
	}
	for _, child := range children {
		if child == nil {
			return nil, errors.Wrap(ErrMissingMandatoryIE, "nil child IE")
		}
	}
	return children, nil
}
func cloneIP(ip net.IP) net.IP { return append(net.IP(nil), ip...) }

func parsePDR(i *ie.IE, create bool) (rules.PDRConfig, error) {
	var p rules.PDRConfig
	kind := ie.UpdatePDR
	if create {
		kind = ie.CreatePDR
	}
	children, err := ruleChildren(i, kind)
	if err != nil {
		return p, err
	}
	hasID := false
	for _, x := range children {
		switch x.Type {
		case ie.PDRID:
			p.PDRID, err = x.PDRID()
			hasID = err == nil
		case ie.Precedence:
			p.Precedence, err = valueOf(x.Precedence())
		case ie.PDI:
			p.PDI, err = parsePDI(x)
		case ie.OuterHeaderRemoval:
			p.OuterHeaderRemoval, err = valueOf(x.OuterHeaderRemovalDescription())
		case ie.FARID:
			p.FARID, err = valueOf(x.FARID())
		case ie.QERID:
			var v uint32
			v, err = x.QERID()
			p.QERIDs = append(p.QERIDs, v)
		case ie.URRID:
			var v uint32
			v, err = x.URRID()
			p.URRIDs = append(p.URRIDs, v)
		}
		if err != nil {
			return p, err
		}
	}
	if err = requireRuleField("PDR ID", hasID); err != nil {
		return p, err
	}
	if create {
		if err = requireRuleField("Precedence", p.Precedence != nil); err != nil {
			return p, err
		}
		if err = requireRuleField("PDI", p.PDI != nil); err != nil {
			return p, err
		}
	}
	return p, nil
}

func parsePDI(i *ie.IE) (*rules.PDI, error) {
	children, err := i.PDI()
	if err != nil {
		return nil, err
	}
	p := &rules.PDI{}
	hasSource := false
	for _, x := range children {
		if x == nil {
			return nil, errors.Wrap(ErrMissingMandatoryIE, "nil PDI child")
		}
		switch x.Type {
		case ie.SourceInterface:
			p.SourceInterface, err = x.SourceInterface()
			hasSource = err == nil
		case ie.FTEID:
			var v *ie.FTEIDFields
			v, err = x.FTEID()
			if err == nil {
				p.FTEID = &rules.FTEID{
					Flags:       v.Flags,
					TEID:        v.TEID,
					IPv4Address: cloneIP(v.IPv4Address),
					IPv6Address: cloneIP(v.IPv6Address),
					ChooseID:    v.ChooseID,
				}
			}
		case ie.UEIPAddress:
			var v *ie.UEIPAddressFields
			v, err = x.UEIPAddress()
			if err == nil {
				p.UEIPAddress = &rules.UEIPAddress{
					Flags:                    v.Flags,
					IPv4Address:              cloneIP(v.IPv4Address),
					IPv6Address:              cloneIP(v.IPv6Address),
					IPv6PrefixDelegationBits: v.IPv6PrefixDelegationBits,
					IPv6PrefixLength:         v.IPv6PrefixLength,
				}
			}
		case ie.SDFFilter:
			var v rules.SDFFilter
			v, err = parseSDFFilter(x)
			if err == nil {
				p.SDFFilters = append(p.SDFFilters, v)
			}
			// NetworkInstance and ApplicationID were ignored by the existing PDI builder.
		}
		if err != nil {
			return nil, err
		}
	}
	if err = requireRuleField("PDI Source Interface", hasSource); err != nil {
		return nil, err
	}
	return p, nil
}

func parseSDFFilter(i *ie.IE) (rules.SDFFilter, error) {
	var result rules.SDFFilter
	if len(i.Payload) < 3 {
		return result, errors.New("SDF Filter payload too short")
	}
	if i.Payload[0]&1 != 0 && (len(i.Payload) < 4 || int(binary.BigEndian.Uint16(i.Payload[2:4])) > len(i.Payload)-4) {
		return result, errors.New("SDF Filter flow description length exceeds payload")
	}
	v, err := i.SDFFilter()
	if err != nil {
		return result, err
	}
	if v.HasFD() {
		result.FlowDescription, err = rules.ParseFlowDesc(v.FlowDescription)
		if err != nil {
			return result, err
		}
	}
	if v.HasTTC() {
		result.ToSTrafficClass = &v.ToSTrafficClass
	}
	if v.HasSPI() {
		result.SecurityParameterIndex = &v.SecurityParameterIndex
	}
	if v.HasFL() {
		result.FlowLabel = &v.FlowLabel
	}
	if v.HasBID() {
		result.SDFFilterID = &v.SDFFilterID
	}
	return result, nil
}

func parseFAR(i *ie.IE, create bool) (rules.FARConfig, error) {
	var p rules.FARConfig
	kind := ie.UpdateFAR
	if create {
		kind = ie.CreateFAR
	}
	children, err := ruleChildren(i, kind)
	if err != nil {
		return p, err
	}
	hasID := false
	for _, x := range children {
		switch x.Type {
		case ie.FARID:
			p.FARID, err = x.FARID()
			hasID = err == nil
		case ie.ApplyAction:
			var b []byte
			b, err = x.ApplyAction()
			if err == nil {
				var act report.ApplyAction
				err = act.Unmarshal(b)
				p.ApplyAction = &act.Flags
			}
		case ie.ForwardingParameters:
			if create {
				p.ForwardingParameters, err = parseForwardingParameters(x, true)
			}
		case ie.UpdateForwardingParameters:
			if !create {
				p.ForwardingParameters, err = parseForwardingParameters(x, false)
			}
		case ie.BARID:
			p.BARID, err = valueOf(x.BARID())
		}
		if err != nil {
			return p, err
		}
	}
	if err = requireRuleField("FAR ID", hasID); err != nil {
		return p, err
	}
	if create {
		err = requireRuleField("Apply Action", p.ApplyAction != nil)
	}
	return p, err
}

func parseForwardingParameters(i *ie.IE, create bool) (*rules.ForwardingParameters, error) {
	var children []*ie.IE
	var err error
	if create {
		children, err = i.ForwardingParameters()
	} else {
		children, err = i.UpdateForwardingParameters()
	}
	if err != nil {
		return nil, err
	}
	p := &rules.ForwardingParameters{}
	for _, x := range children {
		if x == nil {
			return nil, errors.Wrap(ErrMissingMandatoryIE, "nil Forwarding Parameters child")
		}
		switch x.Type {
		case ie.DestinationInterface:
			p.DestinationInterface, err = valueOf(x.DestinationInterface())
		case ie.NetworkInstance:
			p.NetworkInstance, err = valueOf(x.NetworkInstance())
		case ie.ForwardingPolicy:
			p.ForwardingPolicy, err = valueOf(x.ForwardingPolicyIdentifier())
		case ie.PFCPSMReqFlags:
			p.SMRequestFlags, err = valueOf(x.PFCPSMReqFlags())
		case ie.OuterHeaderCreation:
			var v *utilpfcp.OuterHeaderCreationFields
			v, err = utilpfcp.ParseOuterHeaderCreation(x.Payload)
			if err == nil {
				p.OuterHeaderCreation = &rules.OuterHeaderCreation{
					Description: v.OuterHeaderCreationDescription,
					IPv4Address: cloneIP(v.IPv4Address),
					IPv6Address: cloneIP(v.IPv6Address),
					PortNumber:  v.PortNumber,
					CTag:        v.CTag,
					STag:        v.STag,
				}
				if v.HasTEID() {
					p.OuterHeaderCreation.TEID = &v.TEID
				}
			}
		}
		if err != nil {
			return nil, err
		}
	}
	if create {
		err = requireRuleField("Forwarding Parameters Destination Interface", p.DestinationInterface != nil)
	}
	return p, err
}

func parseQER(i *ie.IE, create bool) (rules.QERConfig, error) {
	var p rules.QERConfig
	kind := ie.UpdateQER
	if create {
		kind = ie.CreateQER
	}
	children, err := ruleChildren(i, kind)
	if err != nil {
		return p, err
	}
	hasID := false
	for _, x := range children {
		switch x.Type {
		case ie.QERID:
			p.QERID, err = x.QERID()
			hasID = err == nil
		case ie.QERCorrelationID:
			p.CorrelationID, err = valueOf(x.QERCorrelationID())
		case ie.GateStatus:
			var v uint8
			v, err = x.GateStatus()
			if err == nil {
				p.GateStatus = &rules.GateStatus{Uplink: (v >> 2) & 3, Downlink: v & 3}
				if p.GateStatus.Uplink > ie.GateStatusClosed || p.GateStatus.Downlink > ie.GateStatusClosed {
					err = errors.New("invalid Gate Status")
				}
			}
		case ie.MBR:
			p.MBR, err = parseBitRates(x)
		case ie.GBR:
			p.GBR, err = parseBitRates(x)
		case ie.QFI:
			p.QFI, err = valueOf(x.QFI())
			if err == nil && (*p.QFI == 0 || *p.QFI > 63) {
				err = errors.New("QFI outside range 1..63")
			}
		case ie.RQI:
			p.RQI, err = valueOf(x.RQI())
		case ie.PagingPolicyIndicator:
			p.PagingPolicyIndicator, err = valueOf(x.PagingPolicyIndicator())
		}
		if err != nil {
			return p, err
		}
	}
	if err = requireRuleField("QER ID", hasID); err != nil {
		return p, err
	}
	if create {
		err = requireRuleField("Gate Status", p.GateStatus != nil)
	}
	return p, err
}

func parseBitRates(i *ie.IE) (*rules.DirectionalBitRate, error) {
	var b []byte
	var err error
	if i.Type == ie.MBR {
		b, err = i.MBR()
	} else {
		b, err = i.GBR()
	}
	if err != nil {
		return nil, err
	}
	if len(b) < 10 {
		return nil, errors.New("bit rate requires two 40-bit values")
	}
	read := func(v []byte) uint64 { return uint64(v[0])<<32 | uint64(binary.BigEndian.Uint32(v[1:5])) }
	return &rules.DirectionalBitRate{UplinkBps: read(b[:5]) * 1000, DownlinkBps: read(b[5:10]) * 1000}, nil
}

func parseURR(i *ie.IE, create bool) (rules.URRConfig, error) {
	var p rules.URRConfig
	kind := ie.UpdateURR
	if create {
		kind = ie.CreateURR
	}
	children, err := ruleChildren(i, kind)
	if err != nil {
		return p, err
	}
	hasID := false
	for _, x := range children {
		switch x.Type {
		case ie.URRID:
			p.URRID, err = x.URRID()
			hasID = err == nil
		case ie.MeasurementMethod:
			p.MeasureMethod, err = valueOf(x.MeasurementMethod())
		case ie.MeasurementInformation:
			v, e := x.MeasurementInformation()
			err = e
			value := uint64(v)
			p.MeasureInformation = &value
		case ie.MeasurementPeriod:
			p.MeasurePeriod, err = valueOf(x.MeasurementPeriod())
			if err == nil && *p.MeasurePeriod <= 0 {
				err = errors.New("invalid measurement period")
			}
		case ie.ReportingTriggers:
			var b []byte
			b, err = x.ReportingTriggers()
			if err == nil {
				var trigger report.ReportingTrigger
				err = trigger.Unmarshal(b)
				p.ReportingTriggers = &trigger.Flags
			}
		case ie.VolumeThreshold:
			v, e := x.VolumeThreshold()
			err = e
			if e == nil {
				p.VolumeThreshold = &rules.Volume{
					Flags:    v.Flags,
					Total:    v.TotalVolume,
					Uplink:   v.UplinkVolume,
					Downlink: v.DownlinkVolume,
				}
			}
		case ie.VolumeQuota:
			v, e := x.VolumeQuota()
			err = e
			if e == nil {
				p.VolumeQuota = &rules.Volume{
					Flags:    v.Flags,
					Total:    v.TotalVolume,
					Uplink:   v.UplinkVolume,
					Downlink: v.DownlinkVolume,
				}
			}
		}
		if err != nil {
			return p, err
		}
	}
	if err = requireRuleField("URR ID", hasID); err != nil {
		return p, err
	}
	if create {
		if err = requireRuleField("Measurement Method", p.MeasureMethod != nil); err != nil {
			return p, err
		}
		if err = requireRuleField("Reporting Triggers", p.ReportingTriggers != nil); err != nil {
			return p, err
		}
		if *p.ReportingTriggers&report.RPT_TRIG_PERIO != 0 && (p.MeasurePeriod == nil || *p.MeasurePeriod <= 0) {
			return p, errors.New("invalid measurement period for PERIO trigger")
		}
	}
	return p, nil
}

func parseBAR(i *ie.IE, create bool) (rules.BARConfig, error) {
	var p rules.BARConfig
	kind := ie.UpdateBARWithinSessionModificationRequest
	if create {
		kind = ie.CreateBAR
	}
	children, err := ruleChildren(i, kind)
	if err != nil {
		return p, err
	}
	hasID := false
	for _, x := range children {
		switch x.Type {
		case ie.BARID:
			p.BARID, err = x.BARID()
			hasID = err == nil
		case ie.DownlinkDataNotificationDelay:
			p.DownlinkDataNotificationDelay, err = valueOf(x.DownlinkDataNotificationDelay())
		case ie.SuggestedBufferingPacketsCount:
			v, e := x.SuggestedBufferingPacketsCount()
			err = e
			value := uint16(v)
			p.SuggestedBufferingPacketsCount = &value
		}
		if err != nil {
			return p, err
		}
	}
	return p, requireRuleField("BAR ID", hasID)
}

func parseCreatePDR(i *ie.IE) (rules.PDRConfig, error) { return parsePDR(i, true) }
func parseUpdatePDR(i *ie.IE) (rules.PDRPatch, error) {
	p, err := parsePDR(i, false)
	return rules.PDRPatch(p), err
}

func parseCreateFAR(i *ie.IE) (rules.FARConfig, error) { return parseFAR(i, true) }
func parseUpdateFAR(i *ie.IE) (rules.FARPatch, error) {
	p, err := parseFAR(i, false)
	return rules.FARPatch(p), err
}

func parseCreateQER(i *ie.IE) (rules.QERConfig, error) { return parseQER(i, true) }
func parseUpdateQER(i *ie.IE) (rules.QERPatch, error) {
	p, err := parseQER(i, false)
	return rules.QERPatch(p), err
}

func parseCreateURR(i *ie.IE) (rules.URRConfig, error) { return parseURR(i, true) }
func parseUpdateURR(i *ie.IE) (rules.URRPatch, error) {
	p, err := parseURR(i, false)
	return rules.URRPatch(p), err
}

func parseCreateBAR(i *ie.IE) (rules.BARConfig, error) { return parseBAR(i, true) }
func parseUpdateBAR(i *ie.IE) (rules.BARPatch, error) {
	p, err := parseBAR(i, false)
	return rules.BARPatch(p), err
}
