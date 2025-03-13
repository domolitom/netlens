package main

import (
	"fmt"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Received request from:", r.RemoteAddr)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Hello from Traffic Generator!"))
}

func main() {
	http.HandleFunc("/", handler)
	fmt.Println("Starting traffic generator on port 11111...")

	if err := http.ListenAndServe(":11111", nil); err != nil {
		fmt.Println("Failed to start server:", err)
	}
}
