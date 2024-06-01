package pfcp

import (
	"fmt"
	"sync"
)

// QoS flows are based on destination IPs in our case
var QoSflow_RequestedMonitoring sync.Map
var QoSflow_ReportedFrequency sync.Map
var QoSflow_PacketDelayThresholds sync.Map
var QoSflow_DownlinkPacketDelayThresholds sync.Map
var QoSflow_UplinkPacketDelayThresholds sync.Map
var QoSflow_RoundTripPacketDelayThresholds sync.Map
var QoSflow_MinimumWaitTime sync.Map
var QoSflow_MeasurementPeriod sync.Map

func GetSRRContent(srrID uint8) ([]*QoSControlInfo, error) {
	SrrMapLock.RLock()
	defer SrrMapLock.RUnlock()

	srrInfos, exists := SotredSrrsToBeUsedByUpf[srrID]
	if !exists {
		return nil, fmt.Errorf("SRR ID %d not found", srrID)
	}

	return srrInfos, nil
}

// will be used by capturePackets to retrieve all required QoSFlow for monitoring
func GetQoSFlowMonitoringContent() error {
	srrInfos, err := GetSRRContent(uint8(1))
	if err != nil {
		return err
	}
	var qfi_destination string
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
		if qfi == uint8(1) {
			qfi_destination = "10.100.200.3" //change according to destination1 IP
		}
		if qfi == uint8(2) {
			qfi_destination = "10.100.200.4" //change according to destination2 IP
		}
		QoSflow_RequestedMonitoring.Store(qfi_destination, ReqQoSMonit)
		QoSflow_ReportedFrequency.Store(qfi_destination, ReportingFrequency)
		QoSflow_PacketDelayThresholds.Store(qfi_destination, PacketDelayThresholds)
		QoSflow_DownlinkPacketDelayThresholds.Store(qfi_destination, DownlinkPacketDelayThresholds)
		QoSflow_UplinkPacketDelayThresholds.Store(qfi_destination, UplinkPacketDelayThresholds)
		QoSflow_RoundTripPacketDelayThresholds.Store(qfi_destination, RoundTripPacketDelayThresholds)
		QoSflow_MinimumWaitTime.Store(qfi_destination, MinimumWaitTime)
		QoSflow_MeasurementPeriod.Store(qfi_destination, MeasurementPeriod)
	}
	return nil
}
