package forwarder

import (
	"github.com/free5gc/go-gtp5gnl"
	"github.com/khirono/go-nl"
	"github.com/pkg/errors"

	"github.com/free5gc/go-upf/internal/report"
	"github.com/free5gc/go-upf/internal/rules"
	"github.com/free5gc/go-upf/pkg/factory"
)

// CompileChanges is the transition from decoded PFCP semantics to the existing
// public plan used by RuleState and the executor. It performs no datapath I/O.
// RuleState will consume semantic changes directly in the next migration step.
func (s *sessionDatapath) CompileChanges(changes *rules.RuleChangeSet) (*ModificationPlan, error) {
	if changes == nil {
		return nil, errors.New("nil rule changes")
	}
	if changes.SEID != s.localSEID {
		return nil, errors.New("rule changes belong to another session")
	}
	return compileRuleChanges(changes)
}

func compilePDR(seid uint64, p rules.PDRConfig, op OpType) (*PDRPlan, error) {
	plan := &PDRPlan{Op: op, OID: gtp5gnl.OID{seid, uint64(p.PDRID)}, PDRID: p.PDRID}
	if p.Precedence != nil {
		plan.Attrs = append(plan.Attrs, nl.Attr{Type: gtp5gnl.PDR_PRECEDENCE, Value: nl.AttrU32(*p.Precedence)})
	}
	if p.PDI != nil {
		attrs, err := compilePDI(p.PDI)
		if err != nil {
			return nil, err
		}
		plan.Attrs = append(plan.Attrs, nl.Attr{Type: gtp5gnl.PDR_PDI, Value: attrs})
		source := p.PDI.SourceInterface
		plan.SourceInterface = &source
	}
	if p.OuterHeaderRemoval != nil {
		plan.Attrs = append(plan.Attrs, nl.Attr{Type: gtp5gnl.PDR_OUTER_HEADER_REMOVAL, Value: nl.AttrU8(*p.OuterHeaderRemoval)})
	}
	if p.FARID != nil {
		plan.FARID, plan.FARIDPresent = *p.FARID, true
		plan.Attrs = append(plan.Attrs, nl.Attr{Type: gtp5gnl.PDR_FAR_ID, Value: nl.AttrU32(*p.FARID)})
	}
	plan.QERIDsPresent, plan.URRIDsPresent = p.QERIDs != nil, p.URRIDs != nil
	plan.QERIDs, plan.URRIDs = append([]uint32(nil), p.QERIDs...), append([]uint32(nil), p.URRIDs...)
	for _, id := range p.QERIDs {
		plan.Attrs = append(plan.Attrs, nl.Attr{Type: gtp5gnl.PDR_QER_ID, Value: nl.AttrU32(id)})
	}
	for _, id := range p.URRIDs {
		plan.Attrs = append(plan.Attrs, nl.Attr{Type: gtp5gnl.PDR_URR_ID, Value: nl.AttrU32(id)})
	}
	if op == OpCreate {
		plan.Attrs = append(plan.Attrs, nl.Attr{Type: gtp5gnl.PDR_UNIX_SOCKET_PATH, Value: nl.AttrString(gtp5gnl.PdrAddrForNetlink)})
	}
	return plan, nil
}
func compilePDI(p *rules.PDI) (nl.AttrList, error) {
	attrs := nl.AttrList{{Type: gtp5gnl.PDI_SRC_INTF, Value: nl.AttrU8(p.SourceInterface)}}
	if p.FTEID != nil {
		attrs = append(attrs, nl.Attr{Type: gtp5gnl.PDI_F_TEID, Value: nl.AttrList{
			{Type: gtp5gnl.F_TEID_I_TEID, Value: nl.AttrU32(p.FTEID.TEID)},
			{Type: gtp5gnl.F_TEID_GTPU_ADDR_IPV4, Value: nl.AttrBytes(append([]byte(nil), p.FTEID.IPv4Address...))},
		}})
	}
	if p.UEIPAddress != nil {
		attrs = append(attrs, nl.Attr{Type: gtp5gnl.PDI_UE_ADDR_IPV4, Value: nl.AttrBytes(append([]byte(nil), p.UEIPAddress.IPv4Address...))})
	}
	for _, sdf := range p.SDFFilters {
		var fields nl.AttrList
		if sdf.FlowDescription != nil {
			// PFCP Access is zero. Direction reversal belongs to the datapath encoder.
			fd, err := encodeFlowDesc(*sdf.FlowDescription, p.SourceInterface == 0)
			if err != nil {
				return nil, err
			}
			fields = append(fields, nl.Attr{Type: gtp5gnl.SDF_FILTER_FLOW_DESCRIPTION, Value: nl.AttrList(cloneRuleAttrs(fd))})
		}
		// Preserve the legacy encoder's placeholders; correcting these unsupported
		// SDF subfields is separate from moving parsing out of the driver.
		if sdf.ToSTrafficClass != nil {
			fields = append(fields, nl.Attr{Type: gtp5gnl.SDF_FILTER_TOS_TRAFFIC_CLASS, Value: nl.AttrU16(29)})
		}
		if sdf.SecurityParameterIndex != nil {
			fields = append(fields, nl.Attr{Type: gtp5gnl.SDF_FILTER_SECURITY_PARAMETER_INDEX, Value: nl.AttrU32(30)})
		}
		if sdf.FlowLabel != nil {
			fields = append(fields, nl.Attr{Type: gtp5gnl.SDF_FILTER_FLOW_LABEL, Value: nl.AttrU32(31)})
		}
		if sdf.SDFFilterID != nil {
			fields = append(fields, nl.Attr{Type: gtp5gnl.SDF_FILTER_SDF_FILTER_ID, Value: nl.AttrU32(*sdf.SDFFilterID)})
		}
		attrs = append(attrs, nl.Attr{Type: gtp5gnl.PDI_SDF_FILTER, Value: fields})
	}
	return attrs, nil
}
func compileFAR(seid uint64, p rules.FARConfig, op OpType) *FARPlan {
	plan := &FARPlan{Op: op, OID: gtp5gnl.OID{seid, uint64(p.FARID)}, FARID: p.FARID}
	if p.ApplyAction != nil {
		plan.Attrs = append(plan.Attrs, nl.Attr{Type: gtp5gnl.FAR_APPLY_ACTION, Value: nl.AttrU16(*p.ApplyAction)})
		if op == OpUpdate {
			plan.ApplyAction = &report.ApplyAction{Flags: *p.ApplyAction}
		}
	}
	if fp := p.ForwardingParameters; fp != nil {
		var attrs nl.AttrList
		if hc := fp.OuterHeaderCreation; hc != nil {
			fields := nl.AttrList{{Type: gtp5gnl.OUTER_HEADER_CREATION_DESCRIPTION, Value: nl.AttrU16(hc.Description)}}
			port := hc.PortNumber
			if hc.TEID != nil {
				fields = append(fields, nl.Attr{Type: gtp5gnl.OUTER_HEADER_CREATION_O_TEID, Value: nl.AttrU32(*hc.TEID)})
				port = factory.UpfGtpDefaultPort
			}
			fields = append(fields, nl.Attr{Type: gtp5gnl.OUTER_HEADER_CREATION_PORT, Value: nl.AttrU16(port)})
			if hc.IPv4Address != nil {
				fields = append(fields, nl.Attr{Type: gtp5gnl.OUTER_HEADER_CREATION_PEER_ADDR_IPV4, Value: nl.AttrBytes(append([]byte(nil), hc.IPv4Address...))})
			}
			attrs = append(attrs, nl.Attr{Type: gtp5gnl.FORWARDING_PARAMETER_OUTER_HEADER_CREATION, Value: fields})
		}
		if fp.ForwardingPolicy != nil {
			attrs = append(attrs, nl.Attr{Type: gtp5gnl.FORWARDING_PARAMETER_FORWARDING_POLICY, Value: nl.AttrString(*fp.ForwardingPolicy)})
		}
		if fp.SMRequestFlags != nil {
			attrs = append(attrs, nl.Attr{Type: gtp5gnl.FORWARDING_PARAMETER_PFCPSM_REQ_FLAGS, Value: nl.AttrU8(*fp.SMRequestFlags)})
		}
		if attrs != nil {
			plan.Attrs = append(plan.Attrs, nl.Attr{Type: gtp5gnl.FAR_FORWARDING_PARAMETER, Value: attrs})
		}
	}
	if p.BARID != nil {
		plan.Attrs = append(plan.Attrs, nl.Attr{Type: gtp5gnl.FAR_BAR_ID, Value: nl.AttrU8(*p.BARID)})
	}
	return plan
}
func compileQER(seid uint64, p rules.QERConfig, op OpType) *QERPlan {
	plan := &QERPlan{Op: op, OID: gtp5gnl.OID{seid, uint64(p.QERID)}, QERID: p.QERID}
	if p.CorrelationID != nil {
		plan.Attrs = append(plan.Attrs, nl.Attr{Type: gtp5gnl.QER_CORR_ID, Value: nl.AttrU32(*p.CorrelationID)})
	}
	if p.GateStatus != nil {
		plan.DesiredState.GateStatus = &QERGateStatus{Uplink: p.GateStatus.Uplink, Downlink: p.GateStatus.Downlink}
		plan.Attrs = append(plan.Attrs, nl.Attr{Type: gtp5gnl.QER_GATE, Value: nl.AttrU8(p.GateStatus.Uplink<<2 | p.GateStatus.Downlink)})
	}
	for _, rate := range []struct {
		value                             *rules.DirectionalBitRate
		typ, ulHigh, ulLow, dlHigh, dlLow uint16
	}{
		{p.MBR, gtp5gnl.QER_MBR, gtp5gnl.QER_MBR_UL_HIGH32, gtp5gnl.QER_MBR_UL_LOW8, gtp5gnl.QER_MBR_DL_HIGH32, gtp5gnl.QER_MBR_DL_LOW8},
		{p.GBR, gtp5gnl.QER_GBR, gtp5gnl.QER_GBR_UL_HIGH32, gtp5gnl.QER_GBR_UL_LOW8, gtp5gnl.QER_GBR_DL_HIGH32, gtp5gnl.QER_GBR_DL_LOW8},
	} {
		if rate.value == nil {
			continue
		}
		ul, dl := rate.value.UplinkBps/1000, rate.value.DownlinkBps/1000
		plan.Attrs = append(plan.Attrs, nl.Attr{Type: rate.typ, Value: nl.AttrList{
			{Type: rate.ulHigh, Value: nl.AttrU32(ul >> 8)}, {Type: rate.ulLow, Value: nl.AttrU8(ul)},
			{Type: rate.dlHigh, Value: nl.AttrU32(dl >> 8)}, {Type: rate.dlLow, Value: nl.AttrU8(dl)},
		}})
		desired := &DirectionalBitRate{UplinkBps: rate.value.UplinkBps, DownlinkBps: rate.value.DownlinkBps}
		if rate.typ == gtp5gnl.QER_MBR {
			plan.DesiredState.MBR = desired
		} else {
			plan.DesiredState.GBR = desired
		}
	}
	if p.QFI != nil {
		v := *p.QFI
		plan.DesiredState.QFI = &v
		plan.Attrs = append(plan.Attrs, nl.Attr{Type: gtp5gnl.QER_QFI, Value: nl.AttrU8(v)})
	}
	if p.RQI != nil {
		plan.Attrs = append(plan.Attrs, nl.Attr{Type: gtp5gnl.QER_RQI, Value: nl.AttrU8(*p.RQI)})
	}
	if p.PagingPolicyIndicator != nil {
		plan.Attrs = append(plan.Attrs, nl.Attr{Type: gtp5gnl.QER_PPI, Value: nl.AttrU8(*p.PagingPolicyIndicator)})
	}
	return plan
}
func compileURR(seid uint64, p rules.URRConfig, op OpType) *URRPlan {
	plan := &URRPlan{Op: op, OID: gtp5gnl.OID{seid, uint64(p.URRID)}, URRID: p.URRID}
	if p.MeasureMethod != nil {
		plan.MeasureMethod = *p.MeasureMethod
		plan.Attrs = append(plan.Attrs, nl.Attr{Type: gtp5gnl.URR_MEASUREMENT_METHOD, Value: nl.AttrU8(*p.MeasureMethod)})
	}
	if p.ReportingTriggers != nil {
		plan.Attrs = append(plan.Attrs, nl.Attr{Type: gtp5gnl.URR_REPORTING_TRIGGER, Value: nl.AttrU32(*p.ReportingTriggers)})
		if op == OpCreate {
			plan.ReportingTrigger.Flags = *p.ReportingTriggers
		}
	}
	// Keep existing backend duration encoding during this migration.
	if p.MeasurePeriod != nil {
		plan.Attrs = append(plan.Attrs, nl.Attr{Type: gtp5gnl.URR_MEASUREMENT_PERIOD, Value: nl.AttrU32(*p.MeasurePeriod)})
		if op == OpCreate {
			plan.MeasurePeriod = *p.MeasurePeriod
		}
	}
	if p.MeasureInformation != nil {
		plan.Attrs = append(plan.Attrs, nl.Attr{Type: gtp5gnl.URR_MEASUREMENT_INFO, Value: nl.AttrU64(*p.MeasureInformation)})
	}
	for _, volume := range []struct {
		value                    *rules.Volume
		typ, flag, total, ul, dl uint16
	}{
		{p.VolumeThreshold, gtp5gnl.URR_VOLUME_THRESHOLD, gtp5gnl.URR_VOLUME_THRESHOLD_FLAG, gtp5gnl.URR_VOLUME_THRESHOLD_TOVOL, gtp5gnl.URR_VOLUME_THRESHOLD_UVOL, gtp5gnl.URR_VOLUME_THRESHOLD_DVOL},
		{p.VolumeQuota, gtp5gnl.URR_VOLUME_QUOTA, gtp5gnl.URR_VOLUME_QUOTA_FLAG, gtp5gnl.URR_VOLUME_QUOTA_TOVOL, gtp5gnl.URR_VOLUME_QUOTA_UVOL, gtp5gnl.URR_VOLUME_QUOTA_DVOL},
	} {
		v := volume.value
		if v == nil {
			continue
		}
		attrs := nl.AttrList{{Type: volume.flag, Value: nl.AttrU8(v.Flags)}}
		if v.Flags&1 != 0 {
			attrs = append(attrs, nl.Attr{Type: volume.total, Value: nl.AttrU64(v.Total)})
		}
		if v.Flags&2 != 0 {
			attrs = append(attrs, nl.Attr{Type: volume.ul, Value: nl.AttrU64(v.Uplink)})
		}
		if v.Flags&4 != 0 {
			attrs = append(attrs, nl.Attr{Type: volume.dl, Value: nl.AttrU64(v.Downlink)})
		}
		plan.Attrs = append(plan.Attrs, nl.Attr{Type: volume.typ, Value: attrs})
	}
	plan.ReportingConfig = urrReportingPatch(plan.Attrs)
	return plan
}
func compileBAR(seid uint64, p rules.BARConfig, op OpType) *BARPlan {
	plan := &BARPlan{Op: op, OID: gtp5gnl.OID{seid, uint64(p.BARID)}, BARID: p.BARID}
	if p.DownlinkDataNotificationDelay != nil {
		plan.Attrs = append(plan.Attrs, nl.Attr{Type: gtp5gnl.BAR_DOWNLINK_DATA_NOTIFICATION_DELAY, Value: nl.AttrU8(*p.DownlinkDataNotificationDelay)})
	}
	if p.SuggestedBufferingPacketsCount != nil {
		plan.Attrs = append(plan.Attrs, nl.Attr{Type: gtp5gnl.BAR_BUFFERING_PACKETS_COUNT, Value: nl.AttrU16(*p.SuggestedBufferingPacketsCount)})
	}
	return plan
}

func compileRuleChanges(c *rules.RuleChangeSet) (*ModificationPlan, error) {
	plan := NewModificationPlan(c.SEID)
	for _, p := range c.CreateFARs {
		plan.CreateFARs = append(plan.CreateFARs, compileFAR(c.SEID, rules.FARConfig(p), OpCreate))
	}
	for _, p := range c.CreateQERs {
		plan.CreateQERs = append(plan.CreateQERs, compileQER(c.SEID, rules.QERConfig(p), OpCreate))
	}
	for _, p := range c.CreateURRs {
		plan.CreateURRs = append(plan.CreateURRs, compileURR(c.SEID, rules.URRConfig(p), OpCreate))
	}
	for _, p := range c.CreateBARs {
		plan.CreateBARs = append(plan.CreateBARs, compileBAR(c.SEID, rules.BARConfig(p), OpCreate))
	}
	for _, p := range c.CreatePDRs {
		compiled, err := compilePDR(c.SEID, rules.PDRConfig(p), OpCreate)
		if err != nil {
			return nil, err
		}
		plan.CreatePDRs = append(plan.CreatePDRs, compiled)
	}
	for _, p := range c.UpdateFARs {
		plan.UpdateFARs = append(plan.UpdateFARs, compileFAR(c.SEID, rules.FARConfig(p), OpUpdate))
	}
	for _, p := range c.UpdateQERs {
		plan.UpdateQERs = append(plan.UpdateQERs, compileQER(c.SEID, rules.QERConfig(p), OpUpdate))
	}
	for _, p := range c.UpdateURRs {
		plan.UpdateURRs = append(plan.UpdateURRs, compileURR(c.SEID, rules.URRConfig(p), OpUpdate))
	}
	for _, p := range c.UpdateBARs {
		plan.UpdateBARs = append(plan.UpdateBARs, compileBAR(c.SEID, rules.BARConfig(p), OpUpdate))
	}
	for _, p := range c.UpdatePDRs {
		compiled, err := compilePDR(c.SEID, rules.PDRConfig(p), OpUpdate)
		if err != nil {
			return nil, err
		}
		plan.UpdatePDRs = append(plan.UpdatePDRs, compiled)
	}
	for _, id := range c.RemovePDRs {
		plan.RemovePDRs = append(plan.RemovePDRs, &PDRPlan{Op: OpRemove, OID: gtp5gnl.OID{c.SEID, uint64(id)}, PDRID: id})
	}
	for _, id := range c.RemoveFARs {
		plan.RemoveFARs = append(plan.RemoveFARs, &FARPlan{Op: OpRemove, OID: gtp5gnl.OID{c.SEID, uint64(id)}, FARID: id})
	}
	for _, id := range c.RemoveQERs {
		plan.RemoveQERs = append(plan.RemoveQERs, &QERPlan{Op: OpRemove, OID: gtp5gnl.OID{c.SEID, uint64(id)}, QERID: id})
	}
	for _, id := range c.RemoveURRs {
		plan.RemoveURRs = append(plan.RemoveURRs, &URRPlan{Op: OpRemove, OID: gtp5gnl.OID{c.SEID, uint64(id)}, URRID: id})
	}
	for _, id := range c.RemoveBARs {
		plan.RemoveBARs = append(plan.RemoveBARs, &BARPlan{Op: OpRemove, OID: gtp5gnl.OID{c.SEID, uint64(id)}, BARID: id})
	}
	for _, id := range c.QueryURRs {
		plan.QueryURRs = append(plan.QueryURRs, &URRPlan{Op: OpRemove, OID: gtp5gnl.OID{c.SEID, uint64(id)}, QueryURRID: id})
	}
	return plan, nil
}
