package packet

import (
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/domolitom/netlens/internal/utils"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

const (
	// The same default as tcpdump.
	defaultSnapLen = 262144
)

var (
	writeToFile = true
	w           *pcapgo.Writer
	timeout     = time.After(20 * time.Second)
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
	if writeToFile {
		f, _ := os.Create("netlens.pcap")
		w = pcapgo.NewWriter(f)
		w.WriteFileHeader(defaultSnapLen, layers.LinkTypeEthernet)
		defer f.Close()
	}

	handle, err := pcap.OpenLive(interfaceName, defaultSnapLen, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Start capturing
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	fmt.Println("\n🚀 Capturing Packets on", interfaceName)
	//create a map that counts the nr of packets per source IP
	// Create a timeout channel
	AnalyzePackets(packetSource)

}
func ReadPackets(pcapFile string) {
	handle, err := pcap.OpenOffline(pcapFile)
	if err != nil {
		log.Fatalf("Failed to open pcap file %s: %v", pcapFile, err)
	}
	defer handle.Close()

	// Temporarily disable writing to file during analysis
	originalWriteToFile := writeToFile
	writeToFile = false
	defer func() { writeToFile = originalWriteToFile }() // Restore original value after function execution

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	AnalyzePackets(packetSource)
}

func AnalyzePackets(pSource *gopacket.PacketSource) {
	ipPairs := make(map[[2]string]int)
captureLoop:
	for {
		select {
		case packet := <-pSource.Packets():
			if packet.Layer(layers.LayerTypeIPv4) != nil {
				ip, _ := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
				srcIP := ip.SrcIP.String()
				destIP := ip.DstIP.String()
				ipPairs[[2]string{srcIP, destIP}]++
				fmt.Printf("IPv4 Packet from %s to %s at %d\n", srcIP, destIP, packet.Metadata().Timestamp.Unix())

			} else if packet.Layer(layers.LayerTypeARP) != nil {
				arpLayer := packet.Layer(layers.LayerTypeARP)
				arp, _ := arpLayer.(*layers.ARP)

				srcIP := net.IP(arp.SourceProtAddress).String()
				destIP := net.IP(arp.DstProtAddress).String()

				fmt.Printf("ARP operation: %d, source IP: %s, destination IP: %s, timestamp: %d\n",
					arp.Operation, srcIP, destIP, packet.Metadata().Timestamp.Unix())
			} else {
				fmt.Printf("Unhandled packet layer type. Layers: %s", utils.GetPacketLayers(packet))
			}
			if writeToFile {
				w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
			}
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
