package monitor

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/aalayanahmad/go-upf/internal/pfcp"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

const (
	number_of_packets_to_be_captured = 35
	number_of_simultaneous_workers   = 35
)

var packets_latest_arrival_map sync.Map
var QoS_flow_latency_map sync.Map

var QoS_flow_related_monitoring_info sync.Map

func CapturePackets(interface_name, file_to_save_captured_packets string) {
	handle, err := pcap.OpenLive(interface_name, 2048, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, os.Interrupt, syscall.SIGTERM)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	fmt.Println("it's me hi! i started capturing packets on: ", interface_name)

	file, err := os.Create(file_to_save_captured_packets)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	packetQueue := make(chan gopacket.Packet, 555)
	stopChan := make(chan struct{})
	var wg sync.WaitGroup

	for i := 0; i < number_of_simultaneous_workers; i++ {
		wg.Add(1)
		go worker(packetQueue, stopChan, &wg, file)
	}

	go func() {
		<-signalChannel
		close(stopChan)
	}()

	packets_captured := 0
	for packet := range packetSource.Packets() {
		select {
		case packetQueue <- packet:
			packets_captured++
			if packets_captured >= number_of_packets_to_be_captured {
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

func worker(packetQueue <-chan gopacket.Packet, stopChan <-chan struct{}, wg *sync.WaitGroup, file *os.File) {
	defer wg.Done()
	for {
		select {
		case packet, ok := <-packetQueue:
			if !ok {
				return
			}
			processPacket(packet, file)
		case <-stopChan:
			return
		}
	}
}

func GetSRRContent(srrID uint8) ([]*pfcp.QoSControlInfo, error) {
	srrID = uint8(1)

	pfcp.SrrMapLock.RLock()
	defer pfcp.SrrMapLock.RUnlock()

	srrInfos, exists := pfcp.Sotred_srrs_to_be_used_by_upf[srrID]
	if !exists {
		return nil, fmt.Errorf("SRR ID %d not found", srrID)
	}

	return srrInfos, nil
}

// find QoS what needs to be monitored and threshold for that!
func GetQoSFlowMonitoringContent(srrID uint8) {
	//
}
func processPacket(packet gopacket.Packet, file *os.File) {

	// Loop through all layers in the packet
	for _, layer := range packet.Layers() {
		fmt.Fprintf(file, "Layer Namr: %s\n", layer)
	}
	//if (for this src+dest the qfi says event triggered comaopre latency to thresdhold there!)
	//else need to issue a report
	//if src is in range 10.60.0.X or 10.61.0.X
	//string key_value := src_ip + dest_ip
	//variable for current arrival time of this packet
	//find latency
	//check if there is need to report
	//store this in packets_latest arrival time
}
