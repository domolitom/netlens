package packet

import (
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// Function to list network interfaces
func ListInterfaces() {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal("Error finding devices: ", err)
	}

	fmt.Println("📡 Available Network Interfaces:")
	for _, device := range devices {
		fmt.Printf("- %s (%s)\n", device.Name, device.Description)
	}
}

// Function to capture network traffic on an interface
func CapturePackets(interfaceName string) {
	handle, err := pcap.OpenLive(interfaceName, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Start capturing
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	fmt.Println("\n🚀 Capturing Packets on", interfaceName)
	//create a map that counts the nr of packets per source IP
	ipPairs := make(map[[2]string]int)
	// Create a timeout channel
	timeout := time.After(60 * time.Second)

captureLoop:
	for {
		select {
		case packet := <-packetSource.Packets():
			// Extract IP layer
			if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
				ip, _ := ipLayer.(*layers.IPv4)
				srcIP := ip.SrcIP.String()
				destIP := ip.DstIP.String()
				ipPairs[[2]string{srcIP, destIP}]++
				fmt.Printf("Packet from %s to %s\n", srcIP, destIP)
			} else {
				fmt.Println("No IP layer found.")
			}

			// Print some packet info
			//fmt.Println(packet)
		case <-timeout:
			// Timeout reached, exit the loop
			fmt.Println("\n⏰ Timeout reached, stopping packet capture.")
			break captureLoop
		}
	}

	// Print the counts
	fmt.Println("\n📊 Packet counts per (source IP, destination IP) pair:")
	for pair, count := range ipPairs {
		fmt.Printf("%s -> %s: %d packets\n", pair[0], pair[1], count)
	}
}
