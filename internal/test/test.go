package main

import (
	"github.com/domolitom/netlens/pkg/netutils"
)

func main() {
	netIP, err := netutils.FindDefaultGateway_()
	if err != nil {
		panic(err)
	}
	subnetMask, err := netutils.GetSubnetMask(netIP)
	if err != nil {
		panic(err)
	}
	println("Subnet Mask:", subnetMask)

	macAddress, err := netutils.GetMACAddress(netIP)
	if err != nil {
		panic(err)
	}
	println("MAC Address:", macAddress)
	println("Default Gateway IP:", netIP)
}
