package rules

// Clone and Merge return independently owned configurations. Nil patch fields
// preserve the current value; present zero values and empty slices are applied.
func copyValue[T any](p *T) *T {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}
func copySlice[T any](s []T) []T {
	if s == nil {
		return nil
	}
	return append(make([]T, 0, len(s)), s...)
}

func (c PDRConfig) Clone() PDRConfig {
	c.Precedence = copyValue(c.Precedence)
	c.PDI = clonePDI(c.PDI)
	c.OuterHeaderRemoval = copyValue(c.OuterHeaderRemoval)
	c.FARID = copyValue(c.FARID)
	c.QERIDs = copySlice(c.QERIDs)
	c.URRIDs = copySlice(c.URRIDs)
	return c
}

func (c PDRConfig) Merge(p PDRPatch) PDRConfig {
	if p.Precedence != nil {
		c.Precedence = p.Precedence
	}
	if p.PDI != nil {
		c.PDI = p.PDI
	}
	if p.OuterHeaderRemoval != nil {
		c.OuterHeaderRemoval = p.OuterHeaderRemoval
	}
	if p.FARID != nil {
		c.FARID = p.FARID
	}
	if p.QERIDs != nil {
		c.QERIDs = p.QERIDs
	}
	if p.URRIDs != nil {
		c.URRIDs = p.URRIDs
	}
	return c.Clone()
}

func (c FARConfig) Clone() FARConfig {
	c.ApplyAction = copyValue(c.ApplyAction)
	c.ForwardingParameters = cloneForwardingParameters(c.ForwardingParameters)
	c.BARID = copyValue(c.BARID)
	return c
}

func (c FARConfig) Merge(p FARPatch) FARConfig {
	if p.ApplyAction != nil {
		c.ApplyAction = p.ApplyAction
	}
	if p.ForwardingParameters != nil {
		c.ForwardingParameters = mergeForwardingParameters(c.ForwardingParameters, p.ForwardingParameters)
	}
	if p.BARID != nil {
		c.BARID = p.BARID
	}
	return c.Clone()
}

func (c QERConfig) Clone() QERConfig {
	c.CorrelationID = copyValue(c.CorrelationID)
	c.GateStatus = copyValue(c.GateStatus)
	c.MBR = copyValue(c.MBR)
	c.GBR = copyValue(c.GBR)
	c.QFI = copyValue(c.QFI)
	c.RQI = copyValue(c.RQI)
	c.PagingPolicyIndicator = copyValue(c.PagingPolicyIndicator)
	return c
}

func (c QERConfig) Merge(p QERPatch) QERConfig {
	if p.CorrelationID != nil {
		c.CorrelationID = p.CorrelationID
	}
	if p.GateStatus != nil {
		c.GateStatus = p.GateStatus
	}
	if p.MBR != nil {
		c.MBR = p.MBR
	}
	if p.GBR != nil {
		c.GBR = p.GBR
	}
	if p.QFI != nil {
		c.QFI = p.QFI
	}
	if p.RQI != nil {
		c.RQI = p.RQI
	}
	if p.PagingPolicyIndicator != nil {
		c.PagingPolicyIndicator = p.PagingPolicyIndicator
	}
	return c.Clone()
}

func (c URRConfig) Clone() URRConfig {
	c.MeasureMethod = copyValue(c.MeasureMethod)
	c.ReportingTriggers = copyValue(c.ReportingTriggers)
	c.MeasurePeriod = copyValue(c.MeasurePeriod)
	c.MeasureInformation = copyValue(c.MeasureInformation)
	c.VolumeThreshold = copyValue(c.VolumeThreshold)
	c.VolumeQuota = copyValue(c.VolumeQuota)
	return c
}

func (c URRConfig) Merge(p URRPatch) URRConfig {
	if p.MeasureMethod != nil {
		c.MeasureMethod = p.MeasureMethod
	}
	if p.ReportingTriggers != nil {
		c.ReportingTriggers = p.ReportingTriggers
	}
	if p.MeasurePeriod != nil {
		c.MeasurePeriod = p.MeasurePeriod
	}
	if p.MeasureInformation != nil {
		c.MeasureInformation = p.MeasureInformation
	}
	if p.VolumeThreshold != nil {
		c.VolumeThreshold = p.VolumeThreshold
	}
	if p.VolumeQuota != nil {
		c.VolumeQuota = p.VolumeQuota
	}
	return c.Clone()
}

func (c BARConfig) Clone() BARConfig {
	c.DownlinkDataNotificationDelay = copyValue(c.DownlinkDataNotificationDelay)
	c.SuggestedBufferingPacketsCount = copyValue(c.SuggestedBufferingPacketsCount)
	return c
}

func (c BARConfig) Merge(p BARPatch) BARConfig {
	if p.DownlinkDataNotificationDelay != nil {
		c.DownlinkDataNotificationDelay = p.DownlinkDataNotificationDelay
	}
	if p.SuggestedBufferingPacketsCount != nil {
		c.SuggestedBufferingPacketsCount = p.SuggestedBufferingPacketsCount
	}
	return c.Clone()
}

func clonePDI(p *PDI) *PDI {
	n := copyValue(p)
	if n == nil {
		return nil
	}
	n.FTEID = copyValue(p.FTEID)
	if n.FTEID != nil {
		n.FTEID.IPv4Address = copySlice(p.FTEID.IPv4Address)
		n.FTEID.IPv6Address = copySlice(p.FTEID.IPv6Address)
	}
	n.UEIPAddress = copyValue(p.UEIPAddress)
	if n.UEIPAddress != nil {
		n.UEIPAddress.IPv4Address = copySlice(p.UEIPAddress.IPv4Address)
		n.UEIPAddress.IPv6Address = copySlice(p.UEIPAddress.IPv6Address)
	}
	n.SDFFilters = copySlice(p.SDFFilters)
	for i := range n.SDFFilters {
		f := &n.SDFFilters[i]
		f.ToSTrafficClass = copyValue(f.ToSTrafficClass)
		f.SecurityParameterIndex = copyValue(f.SecurityParameterIndex)
		f.FlowLabel = copyValue(f.FlowLabel)
		f.SDFFilterID = copyValue(f.SDFFilterID)
		f.FlowDescription = copyValue(f.FlowDescription)
		if d := f.FlowDescription; d != nil {
			d.Src = copyValue(d.Src)
			d.Dst = copyValue(d.Dst)
			if d.Src != nil {
				d.Src.IP = copySlice(d.Src.IP)
				d.Src.Mask = copySlice(d.Src.Mask)
			}
			if d.Dst != nil {
				d.Dst.IP = copySlice(d.Dst.IP)
				d.Dst.Mask = copySlice(d.Dst.Mask)
			}
			d.SrcPorts = clonePorts(d.SrcPorts)
			d.DstPorts = clonePorts(d.DstPorts)
		}
	}
	return n
}
func clonePorts(p [][]uint16) [][]uint16 {
	n := copySlice(p)
	for i := range n {
		n[i] = copySlice(n[i])
	}
	return n
}
func cloneForwardingParameters(p *ForwardingParameters) *ForwardingParameters {
	n := copyValue(p)
	if n == nil {
		return nil
	}
	n.DestinationInterface = copyValue(p.DestinationInterface)
	n.NetworkInstance = copyValue(p.NetworkInstance)
	n.ForwardingPolicy = copyValue(p.ForwardingPolicy)
	n.SMRequestFlags = copyValue(p.SMRequestFlags)
	n.OuterHeaderCreation = copyValue(p.OuterHeaderCreation)
	if o := n.OuterHeaderCreation; o != nil {
		o.TEID = copyValue(o.TEID)
		o.IPv4Address = copySlice(o.IPv4Address)
		o.IPv6Address = copySlice(o.IPv6Address)
	}
	return n
}
func mergeForwardingParameters(c, p *ForwardingParameters) *ForwardingParameters {
	n := ForwardingParameters{}
	if c != nil {
		n = *c
	}
	if p.DestinationInterface != nil {
		n.DestinationInterface = p.DestinationInterface
	}
	if p.NetworkInstance != nil {
		n.NetworkInstance = p.NetworkInstance
	}
	if p.ForwardingPolicy != nil {
		n.ForwardingPolicy = p.ForwardingPolicy
	}
	if p.SMRequestFlags != nil {
		n.SMRequestFlags = p.SMRequestFlags
	}
	if p.OuterHeaderCreation != nil {
		n.OuterHeaderCreation = p.OuterHeaderCreation
	}
	return &n
}
