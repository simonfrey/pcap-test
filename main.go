package main

import (
	"bufio"
	"bytes"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"io"
	"log"
	"net/http"
	"sort"
	"strings"
	"sync"
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

	fs := Flows{
		//	flowsMux: sync.RWMutex{},
		flows: map[string]*Flow{},
	}

	/*go func() {
		for {
			//	fs.flowsMux.Lock()
			for _, flow := range fs.flows {
				fmt.Println("flows")

				if time.Since(flow.LastPackage) > 10*time.Second {
					// Print flow and remove it
					fmt.Println("PRINT FLOW")
					for _, s := range flow.Streams {
						printStream(s)
					}
					//delete(fs.flows, k)
				}
			}
			//	fs.flowsMux.Unlock()

			time.Sleep(5 * time.Second)
		}
	}()*/

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
					fmt.Println("no tcp")
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
					fs.AddPackage(src, dst, &pack{
						Payload: tcp.Payload,
						Seq:     tcp.Seq,
					})
				}
				if tcp.FIN {
					fs.PrintFlow(src, dst)
					continue
				}

			}
		}(d)
	}

	select {}
}

type Flows struct {
	//flowsMux sync.RWMutex
	flows map[string]*Flow
}

func (f *Flows) PrintFlow(src, dst string) {
	key := fmt.Sprintf("%s%s", src, dst)
	//	f.flowsMux.RLock()
	flow, ok := f.flows[key]
	//	f.flowsMux.RLock()
	if !ok {
		// Try reverse key
		key = fmt.Sprintf("%s%s", dst, src)

		//	f.flowsMux.RLock()
		flow, ok = f.flows[key]
		//	f.flowsMux.RLock()
		if !ok {
			// Still not found. Exit
			return
		}
	}

	//flow.muxStream.RLock()
	//defer flow.muxStream.RUnlock()

	fmt.Printf("\n\n%s=>%s\n", flow.Initiator, flow.Target)
	for _, s := range flow.Streams {
		printStream(s)
	}
}

func (f *Flows) AddPackage(src, dst string, p *pack) {
	// Find flow

	fmt.Println("ADD Pacakge to flow", src, dst)
	key := fmt.Sprintf("%s%s", src, dst)
	//	f.flowsMux.RLock()
	flow, ok := f.flows[key]
	//f.flowsMux.RLock()
	if !ok {
		// Try reverse key
		key = fmt.Sprintf("%s%s", dst, src)

		//	f.flowsMux.RLock()
		flow, ok = f.flows[key]
		//	f.flowsMux.RLock()

		if !ok {
			// Still not found, create new one
			//		f.flowsMux.Lock()
			flow = &Flow{
				Initiator: src,
				Target:    dst,
				//		muxStream: sync.RWMutex{},
				Streams: make(streams, 0),
			}
			f.flows[key] = flow
			//	f.flowsMux.Unlock()
		}
	}

	// Append package to flow
	flow.AddPackage(src, dst, p)
	flow.LastPackage = time.Now()
}

type Flow struct {
	Initiator   string
	Target      string
	LastPackage time.Time

	//muxStream sync.RWMutex
	Streams streams
}

type streams []*stream

type stream struct {
	Source      string
	Destination string
	muxPackages sync.RWMutex
	Packages    packages
}

func printStream(s *stream) {
	payload := s.Packages.Bytes()
	if !bytes.Contains(payload, []byte("HTTP")) {
		return
	}

	fmt.Printf("\n%s => %s\n", s.Source, s.Destination)

	if isRequest(string(payload[:20])) {
		// We have a request
		printRequest(payload)
		return
	}

	// We have a response
	printResponse(payload)
}

func printRequest(payload []byte) {
	buf := bufio.NewReader(bytes.NewReader(payload))

	res, err := http.ReadRequest(buf)
	if err != nil {
		log.Println("could not parse request: ", err, string(payload))
		return
	}

	header := ""
	for k, v := range res.Header {
		header = fmt.Sprintf("%s%s=%s\n", header, k, strings.Join(v, `,`))
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		log.Println("could not read body: ", err)
		return
	}
	fmt.Printf("%s %s (%s)\n%s\n%s", res.Method, res.URL.Path, res.Proto, header, string(body))
}
func printResponse(payload []byte) {
	buf := bufio.NewReader(bytes.NewReader(payload))

	res, err := http.ReadResponse(buf, nil)
	if err != nil {
		log.Println("could not parse response: ", err, string(payload))
		return
	}

	header := ""
	for k, v := range res.Header {
		header = fmt.Sprintf("%s%s=%s\n", header, k, strings.Join(v, `,`))
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		log.Println("could not read body: ", err)
		return
	}
	fmt.Printf("%d (%s)\n%s\n%s", res.StatusCode, res.Proto, header, string(body))

}

func isRequest(firstLine string) bool {
	switch {
	case strings.Contains(firstLine, "GET"):
		return true
	case strings.Contains(firstLine, "POST"):
		return true
	case strings.Contains(firstLine, "HEAD"):
		return true
	case strings.Contains(firstLine, "PUT"):
		return true
	case strings.Contains(firstLine, "OPTIONS"):
		return true
	case strings.Contains(firstLine, "DELETE"):
		return true
	case strings.Contains(firstLine, "CONNECT"):
		return true
	case strings.Contains(firstLine, "TRACE"):
		return true
	case strings.Contains(firstLine, "PATCH"):
		return true
	default:
		return false
	}
}

func (f *Flow) AddPackage(src, dst string, p *pack) {
	//f.muxStream.RLock()
	fmt.Println("FLOW POINTER", f)
	i := len(f.Streams) - 1
	if i > -1 && f.Streams[i].Source == src {
		// Add to last stream

		f.Streams[i].muxPackages.Lock()
		defer f.Streams[i].muxPackages.Unlock()

		f.Streams[i].Packages = append(f.Streams[i].Packages, p)
		//f.muxStream.RUnlock()
		return
	}

	if len(f.Streams) > 0 {
		// Log last stream

		//printStream(f.Streams[i])
	}
	//	f.muxStream.RUnlock()

	//	f.muxStream.Lock()
	//	defer f.muxStream.Unlock()

	// Create new stream
	f.Streams = append(f.Streams, &stream{
		Source:      src,
		Destination: dst,
		//muxPackages: sync.RWMutex{},
		Packages: packages{p},
	})
}

type pack struct {
	Payload []byte
	Seq     uint32
}
type packages []*pack

func (p packages) Bytes() []byte {
	sort.Sort(p)
	b := make([]byte, 0)
	for _, v := range p {
		b = append(b, v.Payload...)
	}
	return b
}

func (p packages) Len() int           { return len(p) }
func (p packages) Less(i, j int) bool { return p[i].Seq < p[j].Seq }
func (p packages) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }

var flowsMux sync.RWMutex
var flows = map[string]packages{}

func printPacketInfo(packet gopacket.Packet) {
	// We are only interested in TCP packets
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		// No TCP packet
		return
	}

	applicationLayer := packet.ApplicationLayer()
	if applicationLayer == nil || !strings.Contains(string(applicationLayer.Payload()), "HTTP") {
		// NO http package
		return
	}

	tcp, ok := tcpLayer.(*layers.TCP)
	if !ok {
		fmt.Println("could not cast to tcp layer")
		return
	}
	if len(tcp.Payload) == 0 {
		// We don't care about empty package
		return
	}

	netFlow := packet.NetworkLayer().NetworkFlow()
	networkSRC, networkDST := netFlow.Endpoints()

	transportFlow := packet.TransportLayer().TransportFlow()
	transportSRC, transportDST := transportFlow.Endpoints()

	flowKey := fmt.Sprintf("%s:%s=>%s:%s", networkSRC, transportSRC, networkDST, transportDST)

	flowsMux.Lock()
	newSeq := true
	for _, v := range flows[flowKey] {
		if v.Seq == tcp.Seq {
			// Append to payload
			v.Payload = append(v.Payload, tcp.Payload...)
			newSeq = false
			break
		}
	}
	if newSeq {
		flows[flowKey] = append(flows[flowKey], &pack{
			Payload: tcp.Payload,
			Seq:     tcp.Seq,
		})
	}
	sort.Sort(flows[flowKey])
	flowsMux.Unlock()

	flowsMux.RLock()
	defer flowsMux.RUnlock()
	for _, v := range flows[flowKey] {
		fmt.Printf("%s [%d] %d\n", flowKey, v.Seq, len(v.Payload))
		buf := bufio.NewReader(bytes.NewReader(v.Payload))

		res, err := http.ReadResponse(buf, nil)
		if err != nil {
			log.Println("could not parse request: ", err, string(v.Payload))
			return
		}

		fmt.Println("<HEADER>")
		for k, v := range res.Header {
			fmt.Printf("%s=%s", k, strings.Join(v, ","))
		}

		body, err := io.ReadAll(res.Body)
		if err != nil {
			log.Println("could not read body: ", err)
			return
		}
		fmt.Println("<BODY>")
		fmt.Println(string(body))

	}

	fmt.Println()

	return
	/*
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


		flows := map[gopacket.Endpoint]chan gopacket.Packet{}



		// Send all TCP packets to channels based on their destination port.
		if tcp := packet.Layer(layers.LayerTypeTCP); tcp != nil {
			tcp.
				flows[tcp.TransportFlow().Dst()] <- packet
		}
		// Look for all packets with the same source and destination network address
		if net := packet.NetworkLayer(); net != nil {
			src, dst := net.NetworkFlow().Endpoints()
			if src == dst {
				fmt.Println("Fishy packet has same network source and dst: %s", src)
			}
		}
		// Find all packets coming from UDP port 1000 to UDP port 500
		interestingFlow := gopacket.FlowFromEndpoints(layers.NewUDPPortEndpoint(1000), layers.NewUDPPortEndpoint(500))
		if t := packet.NetworkLayer(); t != nil && t.TransportFlow() == interestingFlow {
			fmt.Println("Found that UDP flow I was looking for!")
		}

		// When iterating through packet.Layers() above,
		// if it lists Payload layer then that is the same as
		// this applicationLayer. applicationLayer contains the payload
		applicationLayer := packet.ApplicationLayer()
		if applicationLayer != nil {
			// Search for a string inside the payload
			if strings.Contains(string(applicationLayer.Payload()), "HTTP") {
				fmt.Println("HTTP found!")

				buf := bufio.NewReader(bytes.NewReader(applicationLayer.Payload()))

				req, err := http.ReadRequest(buf)
				if err != nil {
					log.Println("could not parse request: ", err)
					return
				}

				fmt.Println("<HEADER>")
				for k, v := range req.Header {
					fmt.Printf("%s=%s", k, strings.Join(v, ","))
				}

				body, err := io.ReadAll(req.Body)
				if err != nil {
					log.Println("could not read body: ", err)
					return
				}
				fmt.Println("<BODY>")
				fmt.Println(string(body))

			}
		}

		// Check for errors
		if err := packet.ErrorLayer(); err != nil {
			fmt.Println("Error decoding some part of the packet:", err)
		}*/
}

/*
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
*/
