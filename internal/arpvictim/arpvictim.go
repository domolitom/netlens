package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// Constants for ARP operations
const (
	ARPRequest = 1
	ARPReply   = 2
)

// Global variables
var (
	iface      *net.Interface
	localIP    net.IP
	localMAC   net.HardwareAddr
	gatewayIP  net.IP
	arpCache   = make(map[string]net.HardwareAddr)
	arpMutex   sync.RWMutex
	pcapHandle *pcap.Handle
)

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)
	log.Println("Starting low-level victim service with debug capabilities...")

	// Initialize network interfaces and configuration
	if err := initNetworking(); err != nil {
		log.Fatalf("Failed to initialize networking: %v", err)
	}

	// Start background tasks
	go monitorARPCache(10 * time.Second)
	go captureARPPackets()

	// Create HTTP API server with debug endpoints
	setupHTTPServer()
}

func initNetworking() error {
	// Find default interface
	defaultIface, defaultIP, err := findDefaultInterface()
	if err != nil {
		return fmt.Errorf("failed to find default interface: %v", err)
	}

	iface = defaultIface
	localIP = defaultIP
	localMAC = iface.HardwareAddr

	// Try to find gateway IP
	gateway, err := findDefaultGateway()
	if err != nil {
		log.Printf("Warning: Failed to find default gateway: %v", err)
	} else {
		gatewayIP = gateway
	}

	// Print network configuration
	log.Printf("Network configuration:")
	log.Printf("  Interface: %s (%s)", iface.Name, iface.HardwareAddr)
	log.Printf("  Local IP: %s", localIP)
	log.Printf("  Gateway IP: %s", gatewayIP)

	// Initialize packet capture
	handle, err := pcap.OpenLive(iface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("failed to open pcap handle: %v", err)
	}
	pcapHandle = handle

	// Set BPF filter for ARP packets only
	if err := pcapHandle.SetBPFFilter("arp"); err != nil {
		return fmt.Errorf("failed to set BPF filter: %v", err)
	}

	return nil
}

func findDefaultInterface() (*net.Interface, net.IP, error) {
	// Get all interfaces
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, nil, err
	}

	for _, iface := range ifaces {
		// Skip loopback and interfaces that are down
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}

		// Skip interfaces without MAC address
		if len(iface.HardwareAddr) == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}

			// Skip IPv6 addresses
			if ipNet.IP.To4() == nil {
				continue
			}

			// Skip loopback addresses
			if ipNet.IP.IsLoopback() {
				continue
			}

			// Found a valid interface with IPv4 address
			return &iface, ipNet.IP, nil
		}
	}

	return nil, nil, fmt.Errorf("no suitable interface found")
}

func findDefaultGateway() (net.IP, error) {
	// Read the routing table
	file, err := os.Open("/proc/net/route")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Scan() // Skip header line

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 3 {
			// Check for default route (destination 0.0.0.0)
			if fields[1] == "00000000" {
				// Gateway is in hex, reversed byte order
				gateway := fields[2]
				bytes, err := hex.DecodeString(gateway)
				if err != nil {
					return nil, err
				}

				// Reverse bytes for correct IP address
				if len(bytes) == 4 {
					return net.IPv4(bytes[3], bytes[2], bytes[1], bytes[0]), nil
				}
			}
		}
	}

	return nil, fmt.Errorf("default gateway not found")
}

func monitorARPCache(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	log.Printf("Starting ARP cache monitoring (every %s)", interval)

	// Also run immediately at startup
	updateARPCache()

	for range ticker.C {
		updateARPCache()
	}
}

func updateARPCache() {
	// Read ARP cache from system
	cmd := exec.Command("ip", "neigh", "show")
	output, err := cmd.Output()
	if err != nil {
		log.Printf("Error getting ARP cache: %v", err)
		return
	}

	// Parse output
	newCache := make(map[string]net.HardwareAddr)
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) >= 5 && fields[3] == "lladdr" {
			ipAddr := fields[0]
			macAddr, err := net.ParseMAC(fields[4])
			if err != nil {
				continue
			}
			newCache[ipAddr] = macAddr
		}
	}

	// Update our cache
	arpMutex.Lock()
	arpCache = newCache
	arpMutex.Unlock()

	log.Printf("Updated ARP cache: %d entries", len(newCache))
	for ip, mac := range newCache {
		log.Printf("  %s -> %s", ip, mac)
	}
}

func captureARPPackets() {
	log.Printf("Starting ARP packet capture on interface %s", iface.Name)

	packetSource := gopacket.NewPacketSource(pcapHandle, pcapHandle.LinkType())
	for packet := range packetSource.Packets() {
		arpLayer := packet.Layer(layers.LayerTypeARP)
		if arpLayer == nil {
			continue
		}

		arp := arpLayer.(*layers.ARP)
		sourceIP := net.IP(arp.SourceProtAddress).String()
		sourceMAC := net.HardwareAddr(arp.SourceHwAddress).String()
		destIP := net.IP(arp.DstProtAddress).String()
		destMAC := net.HardwareAddr(arp.DstHwAddress).String()

		// Determine operation type
		var opString string
		switch arp.Operation {
		case layers.ARPRequest:
			opString = "REQUEST"
		case layers.ARPReply:
			opString = "REPLY"
		default:
			opString = fmt.Sprintf("UNKNOWN(%d)", arp.Operation)
		}

		log.Printf("ARP %s: %s (%s) -> %s (%s)",
			opString, sourceIP, sourceMAC, destIP, destMAC)

		// If this is a reply, update our ARP cache
		if arp.Operation == layers.ARPReply {
			arpMutex.Lock()
			newMAC, _ := net.ParseMAC(sourceMAC)
			arpCache[sourceIP] = newMAC
			arpMutex.Unlock()
		}
	}
}

func sendARPRequest(targetIP net.IP) error {
	log.Printf("Sending ARP request to discover %s", targetIP)

	// Create ethernet layer
	eth := layers.Ethernet{
		SrcMAC:       localMAC,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, // Broadcast
		EthernetType: layers.EthernetTypeARP,
	}

	// Create ARP layer
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         ARPRequest,
		SourceHwAddress:   localMAC,
		SourceProtAddress: localIP.To4(),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0}, // We're looking for this
		DstProtAddress:    targetIP.To4(),
	}

	// Create buffer and serialize layers
	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	if err := gopacket.SerializeLayers(buffer, options, &eth, &arp); err != nil {
		return fmt.Errorf("error serializing ARP packet: %v", err)
	}

	// Send packet
	if err := pcapHandle.WritePacketData(buffer.Bytes()); err != nil {
		return fmt.Errorf("error sending ARP packet: %v", err)
	}

	log.Printf("ARP request sent successfully")
	return nil
}

func setupHTTPServer() {
	// Root endpoint - shows basic info
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Victim Debug Service\n\n")
		fmt.Fprintf(w, "Network Configuration:\n")
		fmt.Fprintf(w, "  Interface: %s (%s)\n", iface.Name, iface.HardwareAddr)
		fmt.Fprintf(w, "  Local IP: %s\n", localIP)
		fmt.Fprintf(w, "  Gateway IP: %s\n\n", gatewayIP)

		fmt.Fprintf(w, "Available Debug Endpoints:\n")
		fmt.Fprintf(w, "  /arp - View current ARP cache\n")
		fmt.Fprintf(w, "  /find?ip=x.x.x.x - Send ARP request to discover MAC\n")
		fmt.Fprintf(w, "  /interfaces - Show all network interfaces\n")
		fmt.Fprintf(w, "  /netstat - Show active connections\n")
		fmt.Fprintf(w, "  /ping?host=x.x.x.x - Test connectivity\n")
		fmt.Fprintf(w, "  /traceroute?host=x.x.x.x - Trace route to host\n")

		fmt.Fprintf(w, "\nRequest Information:\n")
		fmt.Fprintf(w, "  Client IP: %s\n", r.RemoteAddr)
		fmt.Fprintf(w, "  Request Time: %s\n", time.Now().Format(time.RFC1123))
	})

	// ARP cache endpoint
	http.HandleFunc("/arp", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Current ARP Cache:\n\n")

		arpMutex.RLock()
		defer arpMutex.RUnlock()

		if len(arpCache) == 0 {
			fmt.Fprintf(w, "No entries in ARP cache.\n")
			return
		}

		for ip, mac := range arpCache {
			fmt.Fprintf(w, "%s -> %s\n", ip, mac)
		}
	})

	// ARP discovery endpoint
	http.HandleFunc("/find", func(w http.ResponseWriter, r *http.Request) {
		ip := r.URL.Query().Get("ip")
		if ip == "" {
			http.Error(w, "Please provide an IP address as 'ip' query parameter", http.StatusBadRequest)
			return
		}

		targetIP := net.ParseIP(ip)
		if targetIP == nil {
			http.Error(w, "Invalid IP address format", http.StatusBadRequest)
			return
		}

		// First check if we already have this in cache
		arpMutex.RLock()
		mac, found := arpCache[ip]
		arpMutex.RUnlock()

		if found {
			fmt.Fprintf(w, "Found in ARP cache: %s -> %s\n", ip, mac)
			fmt.Fprintf(w, "Sending new ARP request anyway...\n")
		}

		// Send ARP request
		if err := sendARPRequest(targetIP); err != nil {
			fmt.Fprintf(w, "Error sending ARP request: %v\n", err)
			return
		}

		fmt.Fprintf(w, "ARP request sent for %s\n", ip)
		fmt.Fprintf(w, "Check /arp endpoint in a moment to see the result\n")
	})

	// Interfaces endpoint
	http.HandleFunc("/interfaces", func(w http.ResponseWriter, r *http.Request) {
		interfaces, err := net.Interfaces()
		if err != nil {
			http.Error(w, fmt.Sprintf("Error getting interfaces: %v", err), http.StatusInternalServerError)
			return
		}

		fmt.Fprintf(w, "Network Interfaces:\n\n")

		for _, iface := range interfaces {
			fmt.Fprintf(w, "Interface: %s\n", iface.Name)
			fmt.Fprintf(w, "  Hardware Address: %s\n", iface.HardwareAddr)
			fmt.Fprintf(w, "  Flags: %s\n", iface.Flags.String())

			addrs, err := iface.Addrs()
			if err != nil {
				fmt.Fprintf(w, "  Error getting addresses: %v\n", err)
				continue
			}

			for _, addr := range addrs {
				fmt.Fprintf(w, "  Address: %s\n", addr.String())
			}

			fmt.Fprintf(w, "\n")
		}
	})

	// Netstat endpoint
	http.HandleFunc("/netstat", func(w http.ResponseWriter, r *http.Request) {
		cmd := exec.Command("netstat", "-tuln")
		output, err := cmd.Output()
		if err != nil {
			http.Error(w, fmt.Sprintf("Error running netstat: %v", err), http.StatusInternalServerError)
			return
		}

		fmt.Fprintf(w, "Active Network Connections:\n\n")
		fmt.Fprintf(w, "%s\n", string(output))
	})

	// Ping endpoint
	http.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		host := r.URL.Query().Get("host")
		if host == "" {
			http.Error(w, "Please provide a host as 'host' query parameter", http.StatusBadRequest)
			return
		}

		cmd := exec.Command("ping", "-c", "4", host)
		output, err := cmd.CombinedOutput()

		fmt.Fprintf(w, "Ping Results for %s:\n\n", host)
		fmt.Fprintf(w, "%s\n", string(output))

		if err != nil {
			fmt.Fprintf(w, "Command exited with error: %v\n", err)
		}
	})

	// Traceroute endpoint
	http.HandleFunc("/traceroute", func(w http.ResponseWriter, r *http.Request) {
		host := r.URL.Query().Get("host")
		if host == "" {
			http.Error(w, "Please provide a host as 'host' query parameter", http.StatusBadRequest)
			return
		}

		cmd := exec.Command("traceroute", host)
		output, err := cmd.CombinedOutput()

		fmt.Fprintf(w, "Traceroute Results for %s:\n\n", host)
		fmt.Fprintf(w, "%s\n", string(output))

		if err != nil {
			fmt.Fprintf(w, "Command exited with error: %v\n", err)
		}
	})

	// Raw packet dump endpoint
	http.HandleFunc("/dump", func(w http.ResponseWriter, r *http.Request) {
		duration := 5 * time.Second
		limit := 10

		if dStr := r.URL.Query().Get("duration"); dStr != "" {
			if d, err := time.ParseDuration(dStr); err == nil && d > 0 {
				duration = d
			}
		}

		if lStr := r.URL.Query().Get("limit"); lStr != "" {
			if l, err := fmt.Sscanf(lStr, "%d", &limit); err == nil && l > 0 {
				// Value set from query param
			}
		}

		fmt.Fprintf(w, "Capturing packets for %s (max %d packets):\n\n", duration, limit)

		// Create a temporary handle for this capture
		tempHandle, err := pcap.OpenLive(iface.Name, 65536, true, pcap.BlockForever)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to open capture: %v", err), http.StatusInternalServerError)
			return
		}
		defer tempHandle.Close()

		// Don't filter - get all packets
		packetSource := gopacket.NewPacketSource(tempHandle, tempHandle.LinkType())

		// Set a deadline for the capture
		deadline := time.Now().Add(duration)
		count := 0

		for packet := range packetSource.Packets() {
			if time.Now().After(deadline) || count >= limit {
				break
			}

			fmt.Fprintf(w, "Packet %d:\n", count+1)
			fmt.Fprintf(w, "  Time: %v\n", time.Now())
			fmt.Fprintf(w, "  Length: %d bytes\n", len(packet.Data()))

			// Print layers
			for _, layer := range packet.Layers() {
				fmt.Fprintf(w, "  Layer: %s\n", layer.LayerType())
			}

			// Print detailed info for common layers
			if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
				eth := ethLayer.(*layers.Ethernet)
				fmt.Fprintf(w, "  Ethernet: %s -> %s\n", eth.SrcMAC, eth.DstMAC)
			}

			if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
				ip := ipLayer.(*layers.IPv4)
				fmt.Fprintf(w, "  IPv4: %s -> %s\n", ip.SrcIP, ip.DstIP)
			}

			if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				tcp := tcpLayer.(*layers.TCP)
				fmt.Fprintf(w, "  TCP: %d -> %d\n", tcp.SrcPort, tcp.DstPort)
			}

			if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
				udp := udpLayer.(*layers.UDP)
				fmt.Fprintf(w, "  UDP: %d -> %d\n", udp.SrcPort, udp.DstPort)
			}

			fmt.Fprintf(w, "\n")
			count++
		}

		fmt.Fprintf(w, "Capture complete: %d packets\n", count)
	})

	// Raw ARP packet sender
	http.HandleFunc("/send-arp", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "POST method required", http.StatusMethodNotAllowed)
			return
		}

		targetIP := net.ParseIP(r.FormValue("target_ip"))
		if targetIP == nil {
			http.Error(w, "Invalid target IP", http.StatusBadRequest)
			return
		}

		opStr := r.FormValue("operation")
		var operation uint16 = ARPRequest
		if opStr == "reply" {
			operation = ARPReply
		}

		var targetMAC net.HardwareAddr
		if operation == ARPReply {
			// For reply, we need target MAC
			macStr := r.FormValue("target_mac")
			if macStr == "" {
				// Try to look up in ARP cache
				arpMutex.RLock()
				mac, found := arpCache[targetIP.String()]
				arpMutex.RUnlock()

				if !found {
					http.Error(w, "Target MAC required for ARP reply", http.StatusBadRequest)
					return
				}
				targetMAC = mac
			} else {
				var err error
				targetMAC, err = net.ParseMAC(macStr)
				if err != nil {
					http.Error(w, "Invalid target MAC", http.StatusBadRequest)
					return
				}
			}
		} else {
			// For request, use broadcast
			targetMAC = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
		}

		// Create ethernet layer
		eth := layers.Ethernet{
			SrcMAC:       localMAC,
			DstMAC:       targetMAC,
			EthernetType: layers.EthernetTypeARP,
		}

		// Create ARP layer
		arp := layers.ARP{
			AddrType:          layers.LinkTypeEthernet,
			Protocol:          layers.EthernetTypeIPv4,
			HwAddressSize:     6,
			ProtAddressSize:   4,
			Operation:         operation,
			SourceHwAddress:   localMAC,
			SourceProtAddress: localIP.To4(),
		}

		if operation == ARPReply {
			arp.DstHwAddress = targetMAC
			arp.DstProtAddress = targetIP.To4()
		} else {
			arp.DstHwAddress = []byte{0, 0, 0, 0, 0, 0}
			arp.DstProtAddress = targetIP.To4()
		}

		// Create buffer and serialize layers
		buffer := gopacket.NewSerializeBuffer()
		options := gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		}

		if err := gopacket.SerializeLayers(buffer, options, &eth, &arp); err != nil {
			http.Error(w, fmt.Sprintf("Error serializing ARP packet: %v", err), http.StatusInternalServerError)
			return
		}

		// Send packet
		if err := pcapHandle.WritePacketData(buffer.Bytes()); err != nil {
			http.Error(w, fmt.Sprintf("Error sending ARP packet: %v", err), http.StatusInternalServerError)
			return
		}

		opName := "request"
		if operation == ARPReply {
			opName = "reply"
		}

		fmt.Fprintf(w, "ARP %s sent successfully:\n", opName)
		fmt.Fprintf(w, "  Source: %s (%s)\n", localIP, localMAC)
		fmt.Fprintf(w, "  Target: %s (%s)\n", targetIP, targetMAC)
	})

	// Start server
	port := "8080"
	log.Printf("Starting HTTP server on port %s", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("HTTP server error: %v", err)
	}
}
