package utils

import (
	"fmt"
	"net"
	"strings"

	"github.com/google/gopacket"
)

// Function to parse IP and port into a target string
func ParseIP(ip string, port int) string {
	if net.ParseIP(ip).To4() != nil {
		return fmt.Sprintf("%s:%d", ip, port)
	} else {
		return fmt.Sprintf("[%s]:%d", ip, port)
	}
}

func GetContainerIP() (string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", err
	}

	for _, addr := range addrs {
		// Check if the address is a valid IP address and not a loopback
		if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
			if ipNet.IP.To4() != nil { // Ensure it's an IPv4 address
				return ipNet.IP.String(), nil
			}
		}
	}
	return "", fmt.Errorf("no valid IP address found")
}

// Helper function to increment an IP address
func IncrementIP(ip net.IP) net.IP {
	newIP := make(net.IP, len(ip))
	copy(newIP, ip)

	// Start incrementing from the last byte
	for i := len(newIP) - 1; i >= 0; i-- {
		newIP[i]++
		// If there's no overflow (not rolled over to zero), stop
		if newIP[i] != 0 {
			break
		}
	}
	return newIP
}

// It returns the layers of a packet as a string separated by commas
func GetPacketLayers(packet gopacket.Packet) string {
	var layers []string
	for _, layer := range packet.Layers() {
		layers = append(layers, layer.LayerType().String())
	}
	return strings.Join(layers, ", ")
}
