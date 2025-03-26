package main

import (
	"fmt"
	"os/exec"
	"strings"
)

func printArpTable() {
	// Read the ARP table from /proc
	cmd := exec.Command("arp", "-a")
	output, err := cmd.Output()
	if err != nil {
		fmt.Println("Error reading ARP cache:", err)
		return
	}

	fmt.Println("Cached ARP Entries (via arp -a):")
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fmt.Println(line)
	}
}

func main() {

	printArpTable()
	// // Get routing handle
	// route, err := netroute.New()
	// if err != nil {
	// 	log.Fatalf("Failed to get network route: %v", err)
	// }

	// // Get default network interface and gateway
	// interfaces, _ := net.Interfaces()

	// for _, iface := range interfaces {

	// 	// Get routes associated with the interface
	// 	_, gateway, src, err := route.Route(iface.Index) // Route to Google's DNS
	// 	if err == nil && gateway != nil {
	// 		fmt.Printf("Interface: %s\n", iface.Name)
	// 		fmt.Printf("Default Gateway: %s\n", gateway)
	// 		fmt.Printf("Source IP: %s\n", src)
	// 		break
	// 	}
	// }
	// // Define network interface to use, e.g., eth0
	// ifaceName := "eth0"

	// // Obtain the network interface
	// iface, err := net.InterfaceByName(ifaceName)
	// if err != nil {
	// 	log.Fatalf("Failed to get interface: %v", err)
	// }

	// // Open raw ARP client
	// client, err := arp.Dial(iface)
	// if err != nil {
	// 	log.Fatalf("Failed to dial ARP client: %v", err)
	// }
	// defer client.Close()

	// // Define the IP address of the gateway (replace with actual gateway IP)
	// gatewayIP := net.ParseIP("192.168.1.1").To4()
	// if gatewayIP == nil {
	// 	log.Fatalf("Invalid gateway IP")
	// }

	// fmt.Printf("Sending ARP request for IP: %s\n", gatewayIP)

	// // Send ARP request and get MAC response
	// hwAddr, err := client.Resolve(gatewayIP)
	// if err != nil {
	// 	log.Fatalf("Failed to get MAC address: %v", err)
	// }

	// fmt.Printf("MAC Address of Gateway (%s): %s\n", gatewayIP, hwAddr)
}
