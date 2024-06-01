package pfcp

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const (
	Number_of_simultaneous_workers = 15 //fine tune through testing (until the actual delay stabalizes and this measuring is not delaying it!)
)

var (
	//upLink only
	Time_of_last_arrived_packet_per_UE_destination_combo = make(map[string]time.Time)
	Start_time_per_UE_destination_combo                  = make(map[string]time.Time)
	Latest_latency_measured_per_UE_destination_combo     = make(map[string]uint32)
	Time_of_last_issued_report_per_UE_destination_combo  = make(map[string]time.Time)
	Packet_count                                         = make(map[string]uint8)
	Mu1                                                  sync.Mutex
)

type ToBeReported struct {
	QFI                      uint8
	QoSMonitoringMeasurement uint32
	EventTimeStamp           time.Time //change to uint32 later NOT PRESSING
	StartTime                time.Time //change to uint32
}

var toBeReported_Chan = make(chan ToBeReported, 1000) //buffer size

func GetValuesToBeReported_Chan() <-chan ToBeReported { //everytime they change fill this report and buffer it to the channel
	return toBeReported_Chan
}

func CapturePackets(interface_name string, file_to_save_captured_packets string) {
	err := GetQoSFlowMonitoringContent()
	if err != nil {
		fmt.Println("error:", err)
		fmt.Println("no SRR")
		return //no SRR was found
	}

	handle, err := pcap.OpenLive(interface_name, 2048, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	if err := handle.SetBPFFilter("udp port 2152"); err != nil { //capture only gtp packets
		log.Fatal(err)
	}

	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, os.Interrupt, syscall.SIGTERM)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	fmt.Println("--ahmad implemented -- started capturing packets on:", interface_name)

	packetQueue := make(chan gopacket.Packet, 1000)
	stopChan := make(chan struct{})
	var wg sync.WaitGroup

	for i := 0; i < Number_of_simultaneous_workers; i++ {
		wg.Add(1)
		go worker(packetQueue, stopChan, &wg)
	}

	go func() {
		<-signalChannel
		close(stopChan)
	}()

	for packet := range packetSource.Packets() {
		select {
		case packetQueue <- packet:
		case <-stopChan:
			close(packetQueue)
			wg.Wait()
			return
		}
	}
}

func worker(packetQueue <-chan gopacket.Packet, stopChan <-chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()
	for {
		select {
		case packet, ok := <-packetQueue:
			if !ok {
				return
			}
			processPacket(packet)
		case <-stopChan:
			return
		}
	}
}

func processPacket(packet gopacket.Packet) {
	var outerIPv4, innerIPv4 *layers.IPv4
	var gtpLayer *layers.GTPv1U

	for _, layer := range packet.Layers() {
		switch layer := layer.(type) {
		case *layers.IPv4:
			if outerIPv4 == nil {
				outerIPv4 = layer
			} else {
				innerIPv4 = layer
			}
		case *layers.GTPv1U:
			gtpLayer = layer
		}
	}

	if gtpLayer != nil && innerIPv4 != nil {
		srcIP := innerIPv4.SrcIP.String()
		dstIP := innerIPv4.DstIP.String()
		Mu1.Lock()
		frequency, exists := QoSflow_ReportedFrequency.Load(dstIP)
		if !exists {
			Mu1.Unlock()
			return
		}

		perioOrEvent, ok := frequency.(uint8)
		if !ok {
			fmt.Println("not of type uint8")
			Mu1.Unlock()
			return
		}

		timeToWaitBeforeNextReport, exists := QoSflow_MinimumWaitTime.Load(dstIP)
		if !exists {
			Mu1.Unlock()
			return
		}
		timeToWaitBeforeNextReportDuration, ok := timeToWaitBeforeNextReport.(time.Duration)

		if isInRange(srcIP) { //source IP is one of the UEs
			if perioOrEvent == uint8(1) { //is it event triggered
				key := srcIP + "->" + dstIP //store required values for reports for each src dest pair
				if _, exists := Start_time_per_UE_destination_combo[key]; !exists {
					Start_time_per_UE_destination_combo[key] = time.Now() //only when the monitoring starts
				}

				if count, exists := Packet_count[key]; exists {
					Packet_count[key] = count + 1
				} else {
					Packet_count[key] = 1
				}

				currentTime := time.Now()

				ulThresholdForThisFlow, exists := QoSflow_UplinkPacketDelayThresholds.Load(dstIP)
				if !exists {
					fmt.Println("No values for this flow")
					Mu1.Unlock()
					return
				}
				ulThreshold, ok := ulThresholdForThisFlow.(uint32)
				if !ok {
					fmt.Println("Loaded value is not of type uint32")
					Mu1.Unlock()
					return
				}

				lastArrivalTimeForThisSrcAndDest, exists := Time_of_last_arrived_packet_per_UE_destination_combo[key]
				if !exists {
					lastArrivalTimeForThisSrcAndDest = currentTime
				}

				timeSinceLastReport, exists := Time_of_last_issued_report_per_UE_destination_combo[key]
				if lastArrivalTimeForThisSrcAndDest != currentTime && !exists {
					latency := currentTime.Sub(lastArrivalTimeForThisSrcAndDest)
					latencyInMs := uint32(latency.Milliseconds())
					if latencyInMs > ulThreshold {
						var qfiVal uint8
						if dstIP == "10.100.200.3" || dstIP == "10.100.200.4" {
							qfiVal = 2
						}
						Time_of_last_issued_report_per_UE_destination_combo[key] = currentTime
						newValuesToFill := ToBeReported{
							QFI:                      qfiVal,
							QoSMonitoringMeasurement: latencyInMs,
							EventTimeStamp:           currentTime,
							StartTime:                Start_time_per_UE_destination_combo[key],
						}
						toBeReported_Chan <- newValuesToFill
					}
					Latest_latency_measured_per_UE_destination_combo[key] = latencyInMs
					fmt.Printf("Key: %s, Latency: %v ms\n", key, latencyInMs)
				} else if lastArrivalTimeForThisSrcAndDest != currentTime && exists {
					if time.Since(timeSinceLastReport) >= timeToWaitBeforeNextReportDuration {
						latency := currentTime.Sub(lastArrivalTimeForThisSrcAndDest)
						latency_in_ms := uint32(latency.Milliseconds())
						if latency_in_ms > ulThreshold {
							var qfi_val uint8
							if dstIP == "10.100.200.3" {
								qfi_val = 2
							}

							if dstIP == "10.100.200.4" {
								qfi_val = 2
							}
							new_values_to_fill := ToBeReported{
								QFI:                      qfi_val,
								QoSMonitoringMeasurement: latency_in_ms,
								EventTimeStamp:           currentTime,
								StartTime:                Start_time_per_UE_destination_combo[key],
							}
							toBeReported_Chan <- new_values_to_fill
						}
						Latest_latency_measured_per_UE_destination_combo[key] = latency_in_ms
						fmt.Printf("Key: %s, Latency: %v ms\n", key, latency_in_ms)
					}
				}
				Time_of_last_arrived_packet_per_UE_destination_combo[key] = currentTime
			}
		}
		Mu1.Unlock()
	}
}

func isInRange(ip string) bool { //if its uplink
	return strings.HasPrefix(ip, "10.60.0") || strings.HasPrefix(ip, "10.61.0")
}
