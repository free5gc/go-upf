package monitor

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const maxPackets = 10 //number of gtp packets to capture

func CapturingPackets(iface, filePath string) {
	// Open the device for capturing
	handle, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Set up a signal channel to handle interrupts
	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, os.Interrupt, syscall.SIGTERM)

	// Set up packet source
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	fmt.Println("Starting to sniff packets on", iface)

	// Create a file to write captured packets
	file, err := os.Create(filePath)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	// Capture and process packets
	packetCount := 0
	for packet := range packetSource.Packets() {
		if processPacket(packet, file) {
			packetCount++
			if packetCount >= maxPackets {
				break

			}
		}
	}
}
func processPacket(packet gopacket.Packet, file *os.File) bool {
	gtpLayer := packet.Layer(layers.LayerTypeGTPv1U)
	if gtpLayer != nil {
		gtp, _ := gtpLayer.(*layers.GTPv1U)

		// Extract IP layer (if available)
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer == nil {
			ipLayer = packet.Layer(layers.LayerTypeIPv6)
		}

		// Write GTP packet details to file
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
