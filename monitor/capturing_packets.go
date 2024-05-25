package monitor

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const (
	maxPackets  = 10 // number of packets to capture
	workerCount = 5  // number of workers
)

func CapturingPackets(iface, filePath string) {
	handle, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, os.Interrupt, syscall.SIGTERM)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	fmt.Println("Started capturing packets on", iface)

	file, err := os.Create(filePath)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	packetQueue := make(chan gopacket.Packet, 1000)
	stopChan := make(chan struct{})
	var wg sync.WaitGroup

	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go worker(packetQueue, stopChan, &wg, file)
	}

	go func() {
		<-signalChannel
		close(stopChan)
	}()

	packetCount := 0
	for packet := range packetSource.Packets() {
		select {
		case packetQueue <- packet:
			packetCount++
			if packetCount >= maxPackets {
				break
			}
		case <-stopChan:
			break
		}
	}

	close(packetQueue)
	wg.Wait()
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

func processPacket(packet gopacket.Packet, file *os.File) bool {
	gtpLayer := packet.Layer(layers.LayerTypeGTPv1U)
	if gtpLayer != nil {
		gtp, _ := gtpLayer.(*layers.GTPv1U)

		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer == nil {
			ipLayer = packet.Layer(layers.LayerTypeIPv6)
		}

		fmt.Fprintf(file, "GTP Packet - TEID: %d, Length: %d\n", gtp.TEID, gtp.MessageLength)

		if ipLayer != nil {
			switch ip := ipLayer.(type) {
			case *layers.IPv4:
				fmt.Fprintf(file, "IPv4 Packet - SrcIP: %s, DstIP: %s\n", ip.SrcIP, ip.DstIP)
			case *layers.IPv6:
				fmt.Fprintf(file, "IPv6 Packet - SrcIP: %s, DstIP: %s\n", ip.SrcIP, ip.DstIP)
			}
		}

		return true
	}
	return false
}

//next analyze the osource and destination of each packet
//if source is 10.60.0.X or 10.61.0.X then this is a UL packet
//else it is DL
//if it is UL find time and log it in the a map with keys = src+dest+qfi
//add that to SRR make all these global
//then if it is event triggered start comparing to threshold of UL and then initiate report.
