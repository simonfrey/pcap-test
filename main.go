package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"pcaptest/pkg/flows"
	"pcaptest/pkg/tcp_packages"
	"strings"
	"time"
)

// https://www.devdungeon.com/content/packet-capture-injection-and-analysis-gopacket
// https://pkg.go.dev/github.com/google/gopacket?utm_source=godoc
// https://learnk8s.io/kubernetes-network-packets
// https://blog.apnic.net/2021/05/12/programmatically-analyse-packet-captures-with-gopacket/

func main() {

	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Devices found:")

	fs := flows.NewFlows()

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
			// Set filter
			//			var filter string = "tcp and port 80"
			var filter string = "tcp"
			err = handle.SetBPFFilter(filter)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Println("Only capturing TCP packets.")

			packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
			for packet := range packetSource.Packets() {
				// Process packet here

				// We are only interested in TCP packets
				tcpLayer := packet.Layer(layers.LayerTypeTCP)
				if tcpLayer == nil {
					// No TCP packet
					continue
				}

				tcp, ok := tcpLayer.(*layers.TCP)
				if !ok {
					fmt.Println("could not cast to tcp layer")
					continue
				}

				netFlow := packet.NetworkLayer().NetworkFlow()
				networkSRC, networkDST := netFlow.Endpoints()

				transportFlow := packet.TransportLayer().TransportFlow()
				transportSRC, transportDST := transportFlow.Endpoints()

				src := fmt.Sprintf("%s:%s", networkSRC, transportSRC)
				dst := fmt.Sprintf("%s:%s", networkDST, transportDST)

				if len(tcp.Payload) != 0 {
					// We are only interested in http packages
					applicationLayer := packet.ApplicationLayer()
					if applicationLayer == nil || !strings.Contains(string(applicationLayer.Payload()), "HTTP") {
						// NO http package
						continue
					}

					// We have a payload, add package
					fs.AddPackage(src, dst, &tcp_packages.Pack{
						Payload:  tcp.Payload,
						Seq:      tcp.Seq,
						Received: time.Now(),
					})
				}
				if tcp.FIN {
					flow := fs.PrintFlow(src, dst)
					fmt.Println(flow)
					continue
				}

			}
		}(d)
	}

	select {}
}
