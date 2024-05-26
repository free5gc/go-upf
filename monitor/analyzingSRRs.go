package monitor

import (
	"fmt"
	"sync"

	"github.com/aalayanahmad/go-upf/internal/pfcp"
)

// without UE applies the same to all UEs connecte to a certain destination
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
		request_qos_monit := srrInfo.RequestedQoSMonitoring
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
		var request_qos_monit_int int = int(request_qos_monit)
		var ReportingFrequency_int int = int(ReportingFrequency)
		var PacketDelayThresholds_int int = int(PacketDelayThresholds)
		var DownlinkPacketDelayThresholds_int int = int(DownlinkPacketDelayThresholds)
		var UplinkPacketDelayThresholds_int int = int(UplinkPacketDelayThresholds)
		var RoundTripPacketDelayThresholds_int int = int(RoundTripPacketDelayThresholds)
		var MinimumWaitTime_int int = int(MinimumWaitTime)
		var MeasurementPeriod_int int = int(MeasurementPeriod)
		QoSflow_RequestedMonitoring.Store(qfi_reference, request_qos_monit_int)
		QoSflow_ReportedFrequency.Store(qfi_reference, ReportingFrequency_int)
		QoSflow_PacketDelayThresholds.Store(qfi_reference, PacketDelayThresholds_int)
		QoSflow_DownlinkPacketDelayThresholds.Store(qfi_reference, DownlinkPacketDelayThresholds_int)
		QoSflow_UplinkPacketDelayThresholds.Store(qfi_reference, UplinkPacketDelayThresholds_int)
		QoSflow_RoundTripPacketDelayThresholdso.Store(qfi_reference, RoundTripPacketDelayThresholds_int)
		QoSflow_MinimumWaitTime.Store(qfi_reference, MinimumWaitTime_int)
		QoSflow_MeasurementPeriod.Store(qfi_reference, MeasurementPeriod_int)
		fmt.Println("QFI: ", qfi_int, " RequestedQoSMonitoring: ", request_qos_monit_int, " ReportingFrequency: ", ReportingFrequency_int, " PacketDelayThresholds: ", PacketDelayThresholds_int, " DownlinkPacketDelayThresholds: ", DownlinkPacketDelayThresholds_int, " UplinkPacketDelayThresholds: ", UplinkPacketDelayThresholds_int, " RoundTripPacketDelayThresholds: ", RoundTripPacketDelayThresholds_int, " MinimumWaitTime: ", MinimumWaitTime_int, " MeasurementPeriod: ", MeasurementPeriod_int)
	}
}
