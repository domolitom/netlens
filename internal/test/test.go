package main

import (
	"github.com/domolitom/netlens/pkg/netutils"
)

func main() {
	netIP, err := netutils.FindDefaultGateway_()
	if err != nil {
		panic(err)
	}

	println("Default Gateway IP:", netIP)
}
