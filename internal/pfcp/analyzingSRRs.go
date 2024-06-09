package pfcp

import (
	"fmt"
	"log"
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
	log.Println("found srr")
	return srrInfos, nil
}

// will be used by capturePackets to retrieve all required QoSFlow for monitoring
func GetQoSFlowMonitoringContent() error {
	srrInfos, err := GetSRRContent(uint8(1))
	if err != nil {
		return err
	}
	var qfi_destination string
	log.Println("retrieving values")
	for _, srrInfo := range srrInfos {
		log.Println("in SRR info line")
		qfi := srrInfo.QFI
		log.Println("qfi", qfi)
		ReqQoSMonit := srrInfo.RequestedQoSMonitoring
		log.Println("requestMont", ReqQoSMonit)
		ReportingFrequency := srrInfo.ReportingFrequency
		log.Println("ReportingFrequency", ReportingFrequency)
		PacketDelayThresholds := srrInfo.PacketDelayThresholds
		log.Println("PacketDelayThresholds", PacketDelayThresholds)
		DownlinkPacketDelayThresholds := srrInfo.DownlinkPacketDelayThresholds
		log.Println("DownlinkPacketDelayThresholds", DownlinkPacketDelayThresholds)
		UplinkPacketDelayThresholds := srrInfo.UplinkPacketDelayThresholds
		log.Println("UplinkPacketDelayThresholds", UplinkPacketDelayThresholds)
		RoundTripPacketDelayThresholds := srrInfo.RoundTripPacketDelayThresholds
		log.Println("RoundTripPacketDelayThresholds", RoundTripPacketDelayThresholds)
		MinimumWaitTime := srrInfo.MinimumWaitTime
		log.Println("MinimumWaitTime", MinimumWaitTime)
		MeasurementPeriod := srrInfo.MeasurementPeriod
		log.Println("MeasurementPeriod", MeasurementPeriod)
		if qfi == uint8(1) {
			qfi_destination = "10.100.200.2" //change according to destination1 IP
		}
		if qfi == uint8(2) {
			qfi_destination = "10.100.200.3" //change according to destination2 IP
		}
		QoSflow_RequestedMonitoring.Store(qfi_destination, ReqQoSMonit)
		log.Println("stored RequestedMonitoring for", qfi_destination)
		QoSflow_ReportedFrequency.Store(qfi_destination, ReportingFrequency)
		log.Println("stored ReportedFrequency for", qfi_destination)
		QoSflow_PacketDelayThresholds.Store(qfi_destination, PacketDelayThresholds)
		log.Println("stored PacketDelayThresholds for", qfi_destination)
		QoSflow_DownlinkPacketDelayThresholds.Store(qfi_destination, DownlinkPacketDelayThresholds)
		log.Println("stored DownlinkPacketDelayThresholds for", qfi_destination)
		QoSflow_UplinkPacketDelayThresholds.Store(qfi_destination, UplinkPacketDelayThresholds)
		log.Println("stored UplinkPacketDelayThresholds for", qfi_destination)
		QoSflow_RoundTripPacketDelayThresholds.Store(qfi_destination, RoundTripPacketDelayThresholds)
		log.Println("stored RoundTripPacketDelayThresholds for", qfi_destination)
		QoSflow_MinimumWaitTime.Store(qfi_destination, MinimumWaitTime)
		log.Println("stored MinimumWaitTime for", qfi_destination)
		QoSflow_MeasurementPeriod.Store(qfi_destination, MeasurementPeriod)
		log.Println("stored MeasurementPeriod for", qfi_destination)
	}
	return nil
}
