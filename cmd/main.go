package main

import (
	"fmt"

	"github.com/domolitom/netlens/internal/packet"
	"github.com/domolitom/netlens/internal/utils"
)

func main() {
	//print container IP
	ip, err := utils.GetContainerIP()
	if err != nil {
		fmt.Println("Error getting container IP:", err)
	} else {
		//make this print bold
		fmt.Printf("\033[1mContainer IP address: %s\033[0m\n", ip)
	}
	packet.ListInterfaces()
	var iface string
	fmt.Print("\nEnter the network interface to sniff: ")
	fmt.Scanln(&iface)

	packet.CapturePackets(iface)
}
