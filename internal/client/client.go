package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/domolitom/netlens/internal/util"
)

// Worker pool size (to avoid overloading resources)
const MaxWorkers = 50
const ScanTimeout = 200 * time.Millisecond

var counter = 0
var counterLock sync.Mutex

// Function to check if a host:port combination is open
func isPortOpen(ip string, port int, wg *sync.WaitGroup, resultChan chan string) {
	defer wg.Done() // Mark this goroutine as done when finished
	target := util.ParseIP(ip, port)

	// Apply timeout per connection attempt
	conn, err := net.DialTimeout("tcp", target, ScanTimeout)
	if err == nil {
		conn.Close()
		resultChan <- ip // Send found IP to result channel
	}
	counterLock.Lock()
	counter++
	counterLock.Unlock()
}

// Function to scan the entire Docker subnet in **parallel** while avoiding timeout
func scanDockerNetwork(subnet string, port int) []string {
	var activeIPs []string
	var wg sync.WaitGroup
	resultChan := make(chan string, 255) // Buffered channel to hold results
	ipChan := make(chan string, 255)     // Channel to queue IPs for scanning

	// Worker pool to control concurrency
	for i := 0; i < MaxWorkers; i++ {
		go func() {
			for ip := range ipChan {
				isPortOpen(ip, port, &wg, resultChan)
			}
		}()
	}

	// Populate IP list for scanning
	for i := 1; i <= 254; i++ {
		wg.Add(1)
		ip := fmt.Sprintf("%s.%d", subnet, i)
		ipChan <- ip
	}
	close(ipChan) // Close channel when all IPs are sent to workers

	// Wait for all workers to finish checking
	wg.Wait()
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

			// Return the first 3 octets (e.g., "172.18.0")
			ipParts := strings.Split(ip.String(), ".")
			if len(ipParts) == 4 {
				fmt.Println("Detected Docker subnet IP:", ip.String()) // Debugging info
				return fmt.Sprintf("%s.%s.%s", ipParts[0], ipParts[1], ipParts[2]), nil
			}
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
	containerIp, err := util.GetContainerIP()
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
