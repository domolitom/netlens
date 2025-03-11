package packet

import (
	"fmt"
	"log"

	"github.com/google/gopacket"
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
	for packet := range packetSource.Packets() {
		// Print some packet info
		fmt.Println(packet)
	}
}
