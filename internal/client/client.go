package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/domolitom/netlens/internal/utils"
)

// Worker pool size (to avoid overloading resources)
const MaxWorkers = 1
const ScanTimeout = 200 * time.Millisecond

var counter = 0
var counterLock sync.Mutex

func isPortOpen(ctx context.Context, ip string, port int, wg *sync.WaitGroup, resultChan chan string, cancel context.CancelFunc) {
	defer wg.Done()

	// Stop immediately if another worker found an open port (context is cancelled)
	if ctx.Err() != nil {
		return
	}

	target := utils.ParseIP(ip, port)
	conn, err := net.DialTimeout("tcp", target, ScanTimeout)

	counterLock.Lock()
	counter++
	counterLock.Unlock()

	if err == nil {
		conn.Close()
		select {
		case <-ctx.Done():
			return
		case resultChan <- ip:
			fmt.Printf("✅ IP %s is open, stopping scan.\n", ip)
			cancel() // Cancel all other workers
		}
	} else {
		fmt.Printf("❌ IP %s is closed.\n", ip)
	}
}

// Function to scan the entire Docker subnet in **parallel** while avoiding timeout
// Subnet is in CIDR notation (e.g., "172.18.0.0/16")
func scanDockerNetwork(subnet string, port int) []string {
	var activeIPs []string
	var wg sync.WaitGroup
	resultChan := make(chan string, 1) // Result channel for open IP
	ipChan := make(chan string, 100)   // Channel to queue IPs for scanning

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Parse the subnet and determine the range of IP addresses to scan
	ip, ipNet, err := net.ParseCIDR(subnet)
	if err != nil {
		fmt.Println("Error parsing subnet:", err)
		return activeIPs
	}

	// Worker pool to control concurrency
	for i := 0; i < MaxWorkers; i++ {
		go func() {
			for ip := range ipChan {
				isPortOpen(ctx, ip, port, &wg, resultChan, cancel)
			}
		}()
	}

	// Populate IP list for scanning
	for ip := ip.Mask(ipNet.Mask); ipNet.Contains(ip); ip = utils.IncrementIP(ip) {
		if ip.IsLoopback() {
			continue
		}
		select {
		case <-ctx.Done():
			break
		default:
			ipStr := ip.String()
			wg.Add(1)
			ipChan <- ipStr
		}
	}
	close(ipChan) // Close channel when all IPs are sent to workers

	// Wait for all workers to finish checking
	wg.Wait() // Wait for all workers to finish checking
	close(resultChan)

	// Collect all results
	for ip := range resultChan {
		fmt.Println("Found active container on:", ip)
		activeIPs = append(activeIPs, ip)
	}

	return activeIPs
}

// Find the Docker subnet of the first non-loopback IPv4 interface
func getDockerSubnet() (string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	for _, iface := range interfaces {
		// Ignore loopback and down interfaces
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok || ipNet.IP.IsLoopback() {
				continue
			}

			// Check if it's a private Docker subnet
			ip := ipNet.IP.To4()
			if ip == nil || !isPrivateIP(ip) {
				continue
			}

			// Calculate the network address
			networkIP := ip.Mask(ipNet.Mask)
			ones, _ := ipNet.Mask.Size()
			subnet := fmt.Sprintf("%s/%d", networkIP.String(), ones)
			fmt.Printf("Detected Docker subnet: %s\n", subnet) // Debugging info
			return subnet, nil
		}
	}

	return "", fmt.Errorf("no valid Docker subnet found")
}

// Check if the IP is in a known private subnet block
func isPrivateIP(ip net.IP) bool {
	privateRanges := []string{"10.", "172.16.", "192.168.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22."}
	ipStr := ip.String()
	for _, prefix := range privateRanges {
		if strings.HasPrefix(ipStr, prefix) {
			return true
		}
	}
	return false
}

// Function to repeatedly send HTTP requests
func sendRequest(ip string, port int) {
	url := fmt.Sprintf("http://%s:%d", ip, port)

	for {
		// Send HTTP GET request
		resp, err := http.Get(url)
		if err != nil {
			fmt.Println("Error connecting to container:", err)
			time.Sleep(5 * time.Second) // Retry after 5 seconds
			continue
		}

		// Read the response body
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			fmt.Println("Error reading response:", err)
			resp.Body.Close()
			time.Sleep(5 * time.Second)
			continue
		}
		resp.Body.Close()

		// Print the server's response
		fmt.Printf("✅ Received response from server: %s\n", string(body))

		// Wait for 5 seconds before sending the next request
		time.Sleep(5 * time.Second)
	}
}

func main() {

	//print container IP
	containerIp, err := utils.GetContainerIP()
	if err != nil {
		fmt.Println("Error getting container IP:", err)
	} else {
		//make this print bold
		fmt.Printf("\033[1mContainer IP address: %s\033[0m\n", containerIp)
	}

	// Detect Docker subnet dynamically
	subnet, err := getDockerSubnet()
	if err != nil {
		fmt.Println("Error detecting Docker subnet:", err)
		return
	}

	port := 8888
	fmt.Println("Scanning network for containers with port", port, "open...")
	activeIPs := scanDockerNetwork(subnet, port)

	if len(activeIPs) > 0 {
		fmt.Println("Found the following active containers with port", port, "open:")
		for _, ip := range activeIPs {
			fmt.Println(ip)
		}
	} else {
		fmt.Println("No active containers found with port", port, "open.")
		return
	}

	fmt.Println(counter, " ip addresses scanned")

	// get the first active container IP
	ip := activeIPs[0]

	// Send HTTP requests to the active container
	sendRequest(ip, port)
}
