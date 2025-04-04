package arp

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
)

// ARPEntry represents a single ARP cache entry.
type ARPEntry struct {
	IPAddress       string
	HardwareAddress string
	Interface       string
}

// GetARPTable retrieves the ARP cache and returns it as a slice of ARPEntry.
// It supports Linux, macOS, and Windows.
func GetARPTable(ctx context.Context) ([]ARPEntry, error) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "linux":
		cmd = exec.CommandContext(ctx, "ip", "neigh")
	case "darwin":
		cmd = exec.CommandContext(ctx, "arp", "-a")
	case "windows":
		cmd = exec.CommandContext(ctx, "arp", "-a")
	default:
		return nil, fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}

	output, err := cmd.CombinedOutput()

	if err != nil {
		return nil, fmt.Errorf("failed to execute command: %w, output: %s", err, string(output))
	}

	return parseARPOutput(string(output)), nil
}

// parseARPOutput parses the output of the ARP command and returns a slice of ARPEntry.
func parseARPOutput(output string) []ARPEntry {
	var arpTable []ARPEntry
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		if runtime.GOOS == "linux" {
			parts := strings.Fields(line)
			if len(parts) >= 5 {
				arpTable = append(arpTable, ARPEntry{
					IPAddress:       parts[0],
					HardwareAddress: parts[4],
					Interface:       parts[6],
				})
			}
		} else if runtime.GOOS == "darwin" {
			parts := strings.Fields(line)
			if len(parts) >= 4 && strings.Contains(line, "at") {
				arpTable = append(arpTable, ARPEntry{
					IPAddress:       strings.Trim(parts[1], "()"),
					HardwareAddress: parts[3],
					Interface:       parts[6],
				})
			}
		} else if runtime.GOOS == "windows" {
			parts := strings.Fields(line)
			if len(parts) >= 3 && strings.Contains(line, "dynamic") {
				arpTable = append(arpTable, ARPEntry{
					IPAddress:       parts[0],
					HardwareAddress: parts[1],
					Interface:       parts[2],
				})
			}
		}
	}
	return arpTable
}

// func main() {
// 	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
// 	defer cancel()

// 	arpTable, err := GetARPTable(ctx)
// 	if err != nil {
// 		fmt.Println("Error:", err)
// 		return
// 	}

// 	for _, entry := range arpTable {
// 		fmt.Printf("IP: %s, MAC: %s, Interface: %s\n", entry.IPAddress, entry.HardwareAddress, entry.Interface)
// 	}
// }
