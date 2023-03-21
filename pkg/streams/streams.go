package streams

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"pcaptest/pkg/tcp_packages"
	"strings"
	"sync"
	"time"
)

type Streams struct {
	streamsMux sync.RWMutex
	streams    []*Stream
}

func NewStreams() Streams {
	return Streams{
		streamsMux: sync.RWMutex{},
		streams:    make([]*Stream, 0),
	}
}

func (s *Streams) Print() string {
	s.streamsMux.RLock()
	defer s.streamsMux.RUnlock()

	rs := ""
	for _, v := range s.streams {
		vs := v.Print()
		if vs == "" {
			return ""
		}
		rs = fmt.Sprintf("%s%s", rs, vs)
	}

	return rs
}

func (s *Streams) AddPackage(src, dst string, pack *tcp_packages.Pack) {
	s.streamsMux.Lock()
	defer s.streamsMux.Unlock()

	index := len(s.streams) - 1
	if index < 0 || s.streams[index].Source != src {
		// Add new stream as source is not right, so we have differnet direction
		packages := tcp_packages.NewPackages()
		packages.AddPackage(pack)
		s.streams = append(s.streams, &Stream{
			Source:       src,
			Destination:  dst,
			FirstPackage: time.Now(),
			Packages:     packages,
		})
		return
	}

	// Append to current stream
	s.streams[index].AddPackage(pack)
}

type Stream struct {
	Source       string
	FirstPackage time.Time
	Destination  string
	Packages     tcp_packages.Packages
}

func (s *Stream) AddPackage(pack *tcp_packages.Pack) {
	s.Packages.AddPackage(pack)
}

func (s *Stream) Print() string {
	payload := s.Packages.Bytes()
	if !bytes.Contains(payload, []byte("HTTP")) {
		fmt.Println("payload does not contian 'HTTP'", string(payload))
		return ""
	}

	fmt.Printf("%s => %s\n", s.Source, s.Destination)

	if isRequest(string(payload[:20])) {
		// We have a request
		return printRequest(payload)
	}

	// We have a response
	return printResponse(payload)
}

func printRequest(payload []byte) string {
	buf := bufio.NewReader(bytes.NewReader(payload))

	res, err := http.ReadRequest(buf)
	if err != nil {
		log.Println("could not parse request: ", err, string(payload))
		return ""
	}

	// Filter out healthz requests
	if strings.Contains(res.URL.Path, "/healthz") {
		return ""
	}
	// Filter out requests from kubeproxy and google health check
	if userAgent := res.Header.Get("User-Agent"); strings.Contains(userAgent, "GoogleHC") ||
		strings.Contains(userAgent, "kube-probe") {
		return ""
	}

	header := ""
	for k, v := range res.Header {
		header = fmt.Sprintf("%s%s=%s\n", header, k, strings.Join(v, `,`))
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		log.Println("could not read body: ", err)
		return ""
	}
	if len(body) > 0 {
		return fmt.Sprintf("%s %s (%s)\n%s\n%s\n", res.Method, res.URL.Path, res.Proto, header, string(body))
	}

	return fmt.Sprintf("%s %s (%s)\n%s\n", res.Method, res.URL.Path, res.Proto, header)
}
func printResponse(payload []byte) string {
	buf := bufio.NewReader(bytes.NewReader(payload))

	res, err := http.ReadResponse(buf, nil)
	if err != nil {
		log.Println("could not parse response: ", err, string(payload))
		return ""
	}

	header := ""
	for k, v := range res.Header {
		header = fmt.Sprintf("%s%s=%s\n", header, k, strings.Join(v, `,`))
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		log.Println("could not read body: ", err)
		return ""
	}
	if len(body) > 0 {
		return fmt.Sprintf("%d (%s)\n%s\n%s\n", res.StatusCode, res.Proto, header, string(body))

	}
	return fmt.Sprintf("%d (%s)\n%s\n", res.StatusCode, res.Proto, header)

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
