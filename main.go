package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"log"
	"net/http"
	"pcaptest/pkg/flows"
	"pcaptest/pkg/kube"
	"pcaptest/pkg/streams"
	"pcaptest/pkg/tcp_packages"
	"time"
)

// https://www.devdungeon.com/content/packet-capture-injection-and-analysis-gopacket
// https://pkg.go.dev/github.com/google/gopacket?utm_source=godoc
// https://learnk8s.io/kubernetes-network-packets
// https://blog.apnic.net/2021/05/12/programmatically-analyse-packet-captures-with-gopacket/

var (
	tcpPackagesReceived = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "tcp_packages_received",
		Help: "The total number of tcp packages received",
	}, []string{"app"})
	e2eTime = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "e2e_time",
		Help:    "Time for a tcp connection between initial SYN until FIN package",
		Buckets: prometheus.ExponentialBucketsRange(1, 30000, 15),
	}, []string{"app", "status_code"})
	ttfb = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "ttfb",
		Help:    "Time for a http connection until first response package is send back",
		Buckets: prometheus.ExponentialBucketsRange(1, 30000, 15),
	}, []string{"app", "status_code"})
	responseCodes = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "response_codes",
		Help: "Count the response codes from the anwers",
	}, []string{"app", "status_code"})
)

func init() {
	prometheus.MustRegister(tcpPackagesReceived)
	prometheus.MustRegister(e2eTime)
	prometheus.MustRegister(ttfb)
	prometheus.MustRegister(responseCodes)
}

func main() {
	go func() {
		http.Handle("/metrics", promhttp.Handler())
		err := http.ListenAndServe(":8081", nil)
		if err != nil {
			log.Fatal("could not start prometheus server", err)
		}
	}()

	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Devices found:")

	ipMapper := kube.NewIPMapper()
	fs := flows.NewFlows(ipMapper)

	serviceLoader := kube.NewServiceIPLoader(ipMapper)
	err = serviceLoader.LoadServiceIPsIntoMapper()
	if err != nil {
		log.Fatal("could not load service ips", err)
	}

	packChan := make(chan gopacket.Packet)
	for _, d := range devices {
		go func(device pcap.Interface) {
			if len(device.Addresses) == 0 {
				// We don't want devices without addresses
				return
			}
			fmt.Println("\nName: ", device.Name)
			for _, address := range device.Addresses {
				if address.IP.IsLoopback() {
					// We don't want the loopback device
					return
				}
				fmt.Println("- IP address: ", address.IP)
			}

			handle, err := pcap.OpenLive(device.Name, pcap.MaxBpfInstructions, false, 1*time.Second)
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
				packChan <- packet
			}
		}(d)
	}

	for packet := range packChan {
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

		/*	if false && !strings.Contains(networkSRC.String(), "10.4.") && !strings.Contains(networkDST.String(), "10.4.") {
			// Ignore everything that is not pod network
			continue
		}*/

		transportFlow := packet.TransportLayer().TransportFlow()
		transportSRC, transportDST := transportFlow.Endpoints()

		src := fmt.Sprintf("%s:%s", networkSRC, transportSRC)
		dst := fmt.Sprintf("%s:%s", networkDST, transportDST)

		// Add package to flow (auto generates new flow if non exists)
		fs.AddPackage(src, dst, &tcp_packages.Pack{
			Payload:  tcp.Payload,
			Seq:      tcp.Seq,
			Received: time.Now(),
		})

		flow := fs.GetFlow(src, dst)
		fmt.Println("TARGET", flow.Target)

		if flow == nil || flow.TargetApp == "" {
			fmt.Println("SKIP flow as now target package")
			continue
		}

		tcpPackagesReceived.WithLabelValues(flow.TargetApp).Inc()

		if tcp.FIN {
			// End of connection. Get further metrics

			httpStreams := flow.Streams.HttpStreams()
			statusCode := "-1"
			for _, v := range httpStreams {
				if v.Type == streams.RESPONSE {
					statusCode = v.StatusCode
					break
				}
			}

			if statusCode != "-1" {
				if len(httpStreams) == 2 {
					// Got exactly two start times as we expect it
					ttfb.WithLabelValues(flow.TargetApp, statusCode).
						Observe(float64(httpStreams[1].FirstPackage.Sub(httpStreams[0].FirstPackage).Milliseconds()))
				}

				responseCodes.WithLabelValues(flow.TargetApp, statusCode).Inc()
				e2eTime.WithLabelValues(flow.TargetApp, statusCode).
					Observe(float64(flow.LastPackage.Sub(flow.FirstPackage).Milliseconds()))

			}
			fs.DeleteFlow(src, dst)
		}
	}
}
