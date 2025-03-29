package net

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strings"
)

func FindDefaultInterface() (*net.Interface, net.IP, error) {
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

func FindDefaultGateway() (net.IP, error) {
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
