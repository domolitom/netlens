package main

import (
	"fmt"
	"net"
	"net/http"
)

func getContainerIP() (string, error) {
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

func handler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Received request from:", r.RemoteAddr)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Hello from Traffic Generator!"))
}

func main() {
	ip, err := getContainerIP()
	if err != nil {
		fmt.Println("Error getting container IP:", err)
	} else {
		fmt.Println("Container IP address:", ip)
	}

	http.HandleFunc("/", handler)
	fmt.Println("Starting server on port 8888...")
	if err := http.ListenAndServe(":8888", nil); err != nil {
		fmt.Println("Failed to start server:", err)
	}
}
