package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"time"
)

// https://www.devdungeon.com/content/packet-capture-injection-and-analysis-gopacket
// https://pkg.go.dev/github.com/google/gopacket?utm_source=godoc

func main() {

	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Devices found:")
	for _, d := range devices {
		go func(device pcap.Interface) {
			if len(device.Addresses) == 0 {
				return
			}

			fmt.Println("\nName: ", device.Name)
			fmt.Println("Description: ", device.Description)
			fmt.Println("Devices addresses: ", device.Description)
			for _, address := range device.Addresses {
				fmt.Println("- IP address: ", address.IP)
				fmt.Println("- Subnet mask: ", address.Netmask)
			}

			handle, err := pcap.OpenLive(device.Name, pcap.MaxBpfInstructions, false, 5*time.Second)
			if err != nil {
				panic(err)
			}
			/*	// Set filter
				var filter string = "tcp and port 80"
				err = handle.SetBPFFilter(filter)
				if err != nil {
					log.Fatal(err)
				}
				fmt.Println("Only capturing TCP port 80 packets.")*/

			packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
			for packet := range packetSource.Packets() {
				// Process packet here
				printPacketInfo(packet)
			}
		}(d)
	}

	select {}
}

func printPacketInfo(packet gopacket.Packet) {
	/*	// Let's see if the packet is an ethernet packet
		ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
		if ethernetLayer != nil {
			fmt.Println("Ethernet layer detected.")
			ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
			fmt.Println("Source MAC: ", ethernetPacket.SrcMAC)
			fmt.Println("Destination MAC: ", ethernetPacket.DstMAC)
			// Ethernet type is typically IPv4 but could be ARP or other
			fmt.Println("Ethernet type: ", ethernetPacket.EthernetType)
			fmt.Println()
		}
	*/
	// Let's see if the packet is IP (even though the ether type told us)
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		fmt.Println("IPv4 layer detected.")
		ip, _ := ipLayer.(*layers.IPv4)

		// IP layer variables:
		// Version (Either 4 or 6)
		// IHL (IP Header Length in 32-bit words)
		// TOS, Length, Id, Flags, FragOffset, TTL, Protocol (TCP?),
		// Checksum, SrcIP, DstIP
		fmt.Printf("From %s to %s\n", ip.SrcIP, ip.DstIP)
		fmt.Println("Protocol: ", ip.Protocol)
		fmt.Println()
	}
	/*
		// Let's see if the packet is TCP
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer != nil {
			fmt.Println("TCP layer detected.")
			tcp, _ := tcpLayer.(*layers.TCP)

			// TCP layer variables:
			// SrcPort, DstPort, Seq, Ack, DataOffset, Window, Checksum, Urgent
			// Bool flags: FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS
			fmt.Printf("From port %d to %d\n", tcp.SrcPort, tcp.DstPort)
			fmt.Println("Sequence number: ", tcp.Seq)
			fmt.Println()
		}

		// Iterate over all layers, printing out each layer type
		fmt.Println("All packet layers:")
		for _, layer := range packet.Layers() {
			fmt.Println("- ", layer.LayerType())
		}

		// When iterating through packet.Layers() above,
		// if it lists Payload layer then that is the same as
		// this applicationLayer. applicationLayer contains the payload
		applicationLayer := packet.ApplicationLayer()
		if applicationLayer != nil {
			fmt.Println("Application layer/Payload found.")
			fmt.Printf("%s\n", applicationLayer.Payload())

			// Search for a string inside the payload
			if strings.Contains(string(applicationLayer.Payload()), "HTTP") {
				fmt.Println("HTTP found!")
				fmt.Printf("%s\n", applicationLayer.Payload())
			}
		}
	*/
	// Check for errors
	if err := packet.ErrorLayer(); err != nil {
		fmt.Println("Error decoding some part of the packet:", err)
	}
}
