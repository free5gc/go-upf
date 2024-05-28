package monitor

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/aalayanahmad/go-upf/internal/pfcp"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const (
	number_of_packets_to_be_captured = 35
	number_of_simultaneous_workers   = 35
)

var (
	latestArrivalTimes = make(map[string]time.Time)
	latencies          = make(map[string]time.Duration)
	mu                 sync.Mutex
)
var server_to_send_report pfcp.PfcpServer

func CapturePackets(interfaceName string, fileToSaveCapturedPackets string) {
	handle, err := pcap.OpenLive(interfaceName, 2048, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	if err := handle.SetBPFFilter("udp port 2152"); err != nil {
		log.Fatal(err)
	}

	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, os.Interrupt, syscall.SIGTERM)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	fmt.Println("Started capturing packets on:", interfaceName)

	packetQueue := make(chan gopacket.Packet, 555)
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

	packetsCaptured := 0
	for packet := range packetSource.Packets() {
		select {
		case packetQueue <- packet:
			packetsCaptured++
			if packetsCaptured >= number_of_packets_to_be_captured {
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
		_, period_or_event := QoSflow_ReportedFrequency.Load(dstIP)
		if !period_or_event {
			return
		}
		_, ul_thresdhold := QoSflow_UplinkPacketDelayThresholds.Load(dstIP)
		if !ul_thresdhold {
			return
		}
		if isInRange(srcIP) {
			key := srcIP + "->" + dstIP
			currentTime := time.Now()

			mu.Lock()
			lastArrivalTime, exists := latestArrivalTimes[key]
			if exists {
				latency := currentTime.Sub(lastArrivalTime)
				latencies[key] = latency
				fmt.Printf("Key: %s, Latency: %v ms\n", key, latency.Milliseconds())
			}
			latestArrivalTimes[key] = currentTime
			mu.Unlock()
		}

		fmt.Printf("Inner IPv4 Src IP: %s, Dst IP: %s\n", srcIP, dstIP)
	}

	fmt.Println("*")
}

func isInRange(ip string) bool {
	return ip[:7] == "10.60.0" || ip[:7] == "10.61.0"
}

func getMonitoringValue() uint8 {
	// Implementation for fetching the monitoring value
	return 5 // Example value, replace with actual implementation
}

func getMonitoringThreshold() uint8 {
	// Implementation for fetching the monitoring threshold
	return 10 // Example value, replace with actual implementation
}
