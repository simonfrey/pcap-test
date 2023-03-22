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
	"pcaptest/pkg/kube"
	"strings"
	"time"
)

var (
	httpRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "httpRequests",
		Help: "The total number of http request received",
	}, []string{"app"})
	e2eTime = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "e2e_time",
		Help:    "Time for a tcp connection between initial SYN until FIN package",
		Buckets: prometheus.ExponentialBucketsRange(1, 30000, 15),
	}, []string{"app", "status_code"})
	httpTime = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "http_time",
		Help:    "Time for a http connection until first response package is send back",
		Buckets: prometheus.ExponentialBucketsRange(1, 30000, 15),
	}, []string{"app", "status_code"})
	responseCodes = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "response_codes",
		Help: "Count the response codes from the anwers",
	}, []string{"app", "status_code"})
)

func init() {
	prometheus.MustRegister(httpRequests)
	prometheus.MustRegister(e2eTime)
	prometheus.MustRegister(httpTime)
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

	ipMapper := kube.NewIPMapper()
	serviceLoader := kube.NewServiceIPLoader(ipMapper)
	err := serviceLoader.LoadServiceIPsIntoMapper()
	if err != nil {
		log.Fatal("could not load service ips", err)
	}

	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	packageChan := make(chan gopacket.Packet)
	for _, device := range devices {
		if len(device.Addresses) == 0 {
			// We don't want devices without addresses
			continue
		}
		fmt.Println("\nName: ", device.Name)
		var isLo bool
		for _, address := range device.Addresses {
			if address.IP.IsLoopback() {
				// We don't want the loopback device
				fmt.Println("SKIP this device as it is LO")
				isLo = true
				break
			}
			fmt.Println("- IP address: ", address.IP)
		}
		if isLo {
			continue
		}

		handle, err := pcap.OpenLive(device.Name, pcap.MaxBpfInstructions, false, 1*time.Second)
		if err != nil {
			fmt.Println("could not open device:", err)
			return
		}

		go func() {
			packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
			for packet := range packetSource.Packets() {
				packageChan <- packet
			}

		}()
	}

	type Flow struct {
		SourceIP   string
		TargetIP   string
		StatusCode string

		TCPStart time.Time
		TCPEnd   time.Time

		HTTPRequest  time.Time
		HTTPResponse time.Time
	}
	requestFlows := map[string]*Flow{}

	for packet := range packageChan {
		networkLayer := packet.NetworkLayer()
		if networkLayer == nil {
			continue
		}

		transportLayer := packet.TransportLayer()
		if transportLayer == nil {
			continue
		}

		tcpPacket, ok := transportLayer.(*layers.TCP)
		if !ok {
			continue
		}
		srcIP, dstIP := networkLayer.NetworkFlow().Endpoints()
		cacheKey1 := fmt.Sprintf("%s%s", srcIP, dstIP)
		cacheKey2 := fmt.Sprintf("%s%s", dstIP, srcIP)

		if tcpPacket.SYN {
			// This is the start of a connection (quite likely)
			_, exists := requestFlows[cacheKey1]
			if !exists {
				_, exists = requestFlows[cacheKey2]
				if !exists {
					// Create a new flow
					newFlow := &Flow{
						SourceIP: srcIP.String(),
						TargetIP: dstIP.String(),
						TCPStart: time.Now(),
					}
					requestFlows[cacheKey1] = newFlow
					requestFlows[cacheKey2] = newFlow

				}
			}
		}

		flow, exists := requestFlows[cacheKey1]
		if !exists {
			flow, exists = requestFlows[cacheKey2]
			if !exists {
				continue
			}
		}

		if tcpPacket.FIN {
			// This for sure is the end

			flow.TCPEnd = time.Now()

			// TODO: Do something with the values
			if flow.StatusCode != "" {
				app := ipMapper.Get(flow.TargetIP)
				if app != "" {
					httpRequests.WithLabelValues(app).Inc()
					e2eTime.WithLabelValues(app, flow.StatusCode).
						Observe(float64(flow.TCPEnd.Sub(flow.TCPStart).Milliseconds()))
					httpTime.WithLabelValues(app, flow.StatusCode).
						Observe(float64(flow.HTTPResponse.Sub(flow.HTTPRequest)))
					responseCodes.WithLabelValues(app, flow.StatusCode).Inc()
				}
			}
			// Remove to prevent memory explosion
			delete(requestFlows, cacheKey1)
			delete(requestFlows, cacheKey2)
		}

		if len(tcpPacket.Payload) == 0 {
			continue
		}

		lines := strings.Split(string(tcpPacket.Payload), "\n")
		if len(lines) == 0 {
			continue
		}

		if !strings.Contains(lines[0], "HTTP/1.") {
			continue
		}

		var statusCode string

		// Figure out if it is a request or response
		if strings.HasPrefix(lines[0], "HTTP/1.") {
			// We have a response
			parts := strings.Split(lines[0], " ")
			flow.StatusCode = parts[1]
			flow.HTTPResponse = time.Now()
		} else {
			// We have a request
			flow.HTTPRequest = time.Now()
		}

		fmt.Println(statusCode)
	}
}
