package monitor

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
	number_of_packets_to_be_captured = 50 // just for testing
	number_of_simultaneous_workers   = 15
)

var (
	time_of_last_arrived_packet_from_each_UE_destination_combo = make(map[string]time.Time) // upLink only
	start_time_of_each_UE_destination_combo                    = make(map[string]time.Time) // upLink only
	latest_latency_measure_per_UE_destination_combo            = make(map[string]uint32)    // upLink only
	mu                                                         sync.Mutex
)

func CapturePackets(interface_name string, file_to_save_captured_packets string) {
	handle, err := pcap.OpenLive(interface_name, 2048, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	if err := handle.SetBPFFilter("udp port 2152"); err != nil { // capture gtp packets
		log.Fatal(err)
	}

	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, os.Interrupt, syscall.SIGTERM)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	fmt.Println("--ahmad implemented -- Started capturing packets on:", interface_name)

	packetQueue := make(chan gopacket.Packet, 1000)
	stopChan := make(chan struct{})
	var wg sync.WaitGroup

	for i := 0; i < number_of_simultaneous_workers; i++ {
		wg.Add(1)
		go worker(packetQueue, stopChan, &wg)
	}

	go func() {
		<-signalChannel
		close(stopChan)
	}()

	packets_captured_so_far := 0
	for packet := range packetSource.Packets() {
		select {
		case packetQueue <- packet:
			packets_captured_so_far++
			if packets_captured_so_far >= number_of_packets_to_be_captured {
				close(stopChan)
				wg.Wait()
				return
			}
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
		frequency, exists := QoSflow_ReportedFrequency.Load(dstIP)
		if !exists {
			return
		}
		perio_or_evett, ok := frequency.(uint8)
		if !ok {
			fmt.Println("Loaded value is not of type uint8")
			return
		}

		if isInRange(srcIP) && perio_or_evett == uint8(1) {
			key := srcIP + "->" + dstIP
			mu.Lock()
			if _, exists := start_time_of_each_UE_destination_combo[key]; !exists {
				start_time_of_each_UE_destination_combo[key] = time.Now()
			}
			currentTime := time.Now()

			ul_thresdhold_for_this_flow, exists := QoSflow_UplinkPacketDelayThresholds.Load(dstIP)
			if !exists {
				fmt.Println("No values for this flow")
				mu.Unlock()
				return
			}
			ul_threshold, ok := ul_thresdhold_for_this_flow.(uint32)
			if !ok {
				fmt.Println("Loaded value is not of type uint32")
				mu.Unlock()
				return
			}
			last_arrival_time_for_this_src_and_dest, exists := time_of_last_arrived_packet_from_each_UE_destination_combo[key]
			if exists {
				latency := currentTime.Sub(last_arrival_time_for_this_src_and_dest)
				latency_in_ms := uint32(latency.Milliseconds())
				if latency_in_ms > ul_threshold {
					var qfi_val uint8
					if dstIP == "10.100.200.3" {
						qfi_val = 2
					}

					if dstIP == "10.100.200.4" {
						qfi_val = 2
					}
					trigger_report_through_new_monitoring_value(qfi_val, latency_in_ms, start_time_of_each_UE_destination_combo[key], time.Now())
				}
				latest_latency_measure_per_UE_destination_combo[key] = latency_in_ms
				fmt.Printf("Key: %s, Latency: %v ms\n", key, latency_in_ms)
			}
			time_of_last_arrived_packet_from_each_UE_destination_combo[key] = currentTime
			mu.Unlock()
		}

		fmt.Printf("Inner IPv4 Src IP: %s, Dst IP: %s\n", srcIP, dstIP)
	}

	fmt.Println("***thank u, next***")
}

func isInRange(ip string) bool {
	return strings.HasPrefix(ip, "10.60.0") || strings.HasPrefix(ip, "10.61.0")
}

func trigger_report_through_new_monitoring_value(qfi_val uint8, monitoring_value uint32, start time.Time, current time.Time) (uint8, uint32, time.Time, time.Time) {
	fmt.Printf("Reporting new monitoring value: %d, start: %v, current: %v\n", monitoring_value, start, current)
	return qfi_val, monitoring_value, start, current
}
