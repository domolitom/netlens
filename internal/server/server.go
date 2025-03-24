package main

import (
	"fmt"
	"net/http"

	"github.com/domolitom/netlens/internal/utils"
)

func handler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Received request from:", r.RemoteAddr)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Hello from Traffic Generator!"))
}

func main() {
	//print container IP
	ip, err := utils.GetContainerIP()
	if err != nil {
		fmt.Println("Error getting container IP:", err)
	} else {
		//make this print bold
		fmt.Printf("\033[1mContainer IP address: %s\033[0m\n", ip)
	}

	http.HandleFunc("/", handler)
	fmt.Println("Starting server on port 8888...")
	if err := http.ListenAndServe(":8888", nil); err != nil {
		fmt.Println("Failed to start server:", err)
	}
}
