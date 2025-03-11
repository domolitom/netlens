package main

import (
	"fmt"

	"github.com/domolitom/netlens/internal/packet"
)

func main() {
	packet.ListInterfaces()
	var iface string
	fmt.Print("\nEnter the network interface to sniff: ")
	fmt.Scanln(&iface)

	packet.CapturePackets(iface)
}
