package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

type ARPEntry struct {
	IP     string
	HWType string
	Flags  string
	MAC    string
	Device string
}

func printArpTable() {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second) // Timeout after 10s
	defer cancel()

	if runtime.GOOS == "linux" {
		file, err := os.Open("/proc/net/arp")
		if err != nil {
			fmt.Printf("Error reading ARP cache: %v\n", err)
			return
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		lineNum := 0
		for scanner.Scan() {
			line := scanner.Text()
			lineNum++
			// Skip header row
			if lineNum == 1 {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) >= 6 {
				entry := ARPEntry{
					IP:     fields[0],
					HWType: fields[1],
					Flags:  fields[2],
					MAC:    fields[3],
					Device: fields[5],
				}
				fmt.Printf("IP: %s, MAC: %s via %s\n", entry.IP, entry.MAC, entry.Device)
			}
		}

		if err := scanner.Err(); err != nil {
			fmt.Printf("Scanner error: %v\n", err)
		}
		return

	}

	// Select the command based on OS
	cmd := exec.CommandContext(ctx, "arp", "-a") // Use "ip neigh show" for Linux

	// Get a pipe to read real-time stdout
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Println("Error creating stdout pipe:", err)
		return
	}

	// Start the command
	if err := cmd.Start(); err != nil {
		fmt.Println("Error starting command:", err)
		return
	}

	// Store printed output in a slice
	var outputLines []string

	// Read output line by line while the command is running
	fmt.Println("Cached ARP Entries:")
	scanner := bufio.NewScanner(stdoutPipe)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			fmt.Println(line)                       // Print each line in real-time
			outputLines = append(outputLines, line) // Save for later use
		}
	}

	// Check for scanning errors
	if err := scanner.Err(); err != nil {
		fmt.Println("Error reading output:", err)
	}

	// Wait for the command to complete
	err = cmd.Wait()

	// Handle timeout separately
	if ctx.Err() == context.DeadlineExceeded {
		fmt.Println("⏳ Info: Command timed out, returning partial output.")
	} else if err != nil {
		fmt.Println("⚠️ Command execution error:", err)
	}

	// ✅ Return the collected ARP cache
	fmt.Println("\n🔹 Final Cached ARP Entries List (collected before timeout):")
	for _, line := range outputLines {
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
