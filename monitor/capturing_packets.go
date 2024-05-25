package monitor

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

const (
	number_of_packets_to_be_captured = 35
	number_of_simultaneous_workers   = 35
)

var packets_latest_arrival_map sync.Map
var flow_latency_map sync.Map

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

func processPacket(packet gopacket.Packet, file *os.File) {

	// Loop through all layers in the packet
	for _, layer := range packet.Layers() {
		fmt.Fprintf(file, "Layer Namr: %s\n", layer)
	}
	//if src is in range 10.60.0.X or 10.61.0.X
	//string key_value := src_ip + dest_ip
	//variable for current arrival time of this packet
	//find latency
	//check if there is need to report
	//store this in packets_latest arrival time
}
