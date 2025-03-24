package packet

import (
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const (
	// The same default as tcpdump.
	defaultSnapLen = 262144
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
	handle, err := pcap.OpenLive(interfaceName, defaultSnapLen, true, pcap.BlockForever)
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
			switch {
			case packet.Layer(layers.LayerTypeIPv4) != nil:
				ip, _ := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
				srcIP := ip.SrcIP.String()
				destIP := ip.DstIP.String()
				ipPairs[[2]string{srcIP, destIP}]++
				fmt.Printf("IPv4 Packet from %s to %s\n", srcIP, destIP)
			case packet.Layer(layers.LayerTypeIPv6) != nil:
				ip, _ := packet.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
				srcIP := ip.SrcIP.String()
				destIP := ip.DstIP.String()
				ipPairs[[2]string{srcIP, destIP}]++
				fmt.Printf("IPv6 Packet from %s to %s\n", srcIP, destIP)
			case packet.Layer(layers.LayerTypeEthernet) != nil:
				ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
				ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
				fmt.Println("Ethernet type: ", ethernetPacket.EthernetType)
			case packet.Layer(layers.LayerTypeTCP) != nil:
				tcpLayer := packet.Layer(layers.LayerTypeTCP)
				tcp, _ := tcpLayer.(*layers.TCP)
				fmt.Println("TCP src port: ", tcp.SrcPort)
				fmt.Println("TCP dst port: ", tcp.DstPort)
			case packet.Layer(layers.LayerTypeUDP) != nil:
				udpLayer := packet.Layer(layers.LayerTypeUDP)
				udp, _ := udpLayer.(*layers.UDP)
				fmt.Println("UDP src port: ", udp.SrcPort)
				fmt.Println("UDP dst port: ", udp.DstPort)
			case packet.Layer(layers.LayerTypeDNS) != nil:
				dnsLayer := packet.Layer(layers.LayerTypeDNS)
				dns, _ := dnsLayer.(*layers.DNS)
				fmt.Println("DNS query: ", dns.Questions)
			case packet.Layer(layers.LayerTypeICMPv4) != nil:
				icmpLayer := packet.Layer(layers.LayerTypeICMPv4)
				icmp, _ := icmpLayer.(*layers.ICMPv4)
				fmt.Println("ICMP type: ", icmp.TypeCode.Type())
				fmt.Println("ICMP code: ", icmp.TypeCode.Code())
			case packet.Layer(layers.LayerTypeICMPv6) != nil:
				icmpLayer := packet.Layer(layers.LayerTypeICMPv6)
				icmp, _ := icmpLayer.(*layers.ICMPv6)
				fmt.Println("ICMP type: ", icmp.TypeCode.Type())
				fmt.Println("ICMP code: ", icmp.TypeCode.Code())
			case packet.Layer(layers.LayerTypeARP) != nil:
				arpLayer := packet.Layer(layers.LayerTypeARP)
				arp, _ := arpLayer.(*layers.ARP)
				fmt.Println("ARP operation: ", arp.Operation)
				fmt.Println("ARP source IP: ", arp.SourceProtAddress)
				fmt.Println("ARP destination IP: ", arp.DstProtAddress)
			default:
				fmt.Println("Unknown packet type.")
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
