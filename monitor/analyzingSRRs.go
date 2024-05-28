package monitor

import (
	"fmt"
	"sync"

	"github.com/aalayanahmad/go-upf/internal/pfcp"
)

// without UE applies the same to all UEs connect to a certain destination
var QoSflow_RequestedMonitoring sync.Map
var QoSflow_ReportedFrequency sync.Map
var QoSflow_PacketDelayThresholds sync.Map
var QoSflow_DownlinkPacketDelayThresholds sync.Map
var QoSflow_UplinkPacketDelayThresholds sync.Map
var QoSflow_RoundTripPacketDelayThresholdso sync.Map
var QoSflow_MinimumWaitTime sync.Map
var QoSflow_MeasurementPeriod sync.Map

func GetSRRContent(srrID uint8) ([]*pfcp.QoSControlInfo, error) {
	pfcp.SrrMapLock.RLock()
	defer pfcp.SrrMapLock.RUnlock()

	srrInfos, exists := pfcp.Sotred_srrs_to_be_used_by_upf[srrID]
	if !exists {
		return nil, fmt.Errorf("SRR ID %d not found", srrID)
	}

	return srrInfos, nil
}

// put in a separate file isnide montior
// find QoS what needs to be monitored and threshold for that!
func GetQoSFlowMonitoringContent(srrInfos []*pfcp.QoSControlInfo) {
	for _, srrInfo := range srrInfos {
		qfi := srrInfo.QFI
		ReqQoSMonit := srrInfo.RequestedQoSMonitoring
		ReportingFrequency := srrInfo.ReportingFrequency
		PacketDelayThresholds := srrInfo.PacketDelayThresholds
		DownlinkPacketDelayThresholds := srrInfo.DownlinkPacketDelayThresholds
		UplinkPacketDelayThresholds := srrInfo.UplinkPacketDelayThresholds
		RoundTripPacketDelayThresholds := srrInfo.RoundTripPacketDelayThresholds
		MinimumWaitTime := srrInfo.MinimumWaitTime
		MeasurementPeriod := srrInfo.MeasurementPeriod
		var qfi_int int = int(qfi)
		var qfi_reference string
		if qfi_int == 1 {
			qfi_reference = "10.100.200.3"
		}
		if qfi_int == 2 {
			qfi_reference = "10.100.200.4"
		}
		QoSflow_RequestedMonitoring.Store(qfi_reference, ReqQoSMonit)
		QoSflow_ReportedFrequency.Store(qfi_reference, ReportingFrequency)
		QoSflow_PacketDelayThresholds.Store(qfi_reference, PacketDelayThresholds)
		QoSflow_DownlinkPacketDelayThresholds.Store(qfi_reference, DownlinkPacketDelayThresholds)
		QoSflow_UplinkPacketDelayThresholds.Store(qfi_reference, UplinkPacketDelayThresholds)
		QoSflow_RoundTripPacketDelayThresholdso.Store(qfi_reference, RoundTripPacketDelayThresholds)
		QoSflow_MinimumWaitTime.Store(qfi_reference, MinimumWaitTime)
		QoSflow_MeasurementPeriod.Store(qfi_reference, MeasurementPeriod)
	}
}
