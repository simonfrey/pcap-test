package streams

import (
	"bytes"
	"fmt"
	"net/http"
	"pcaptest/pkg/tcp_packages"
	"regexp"
	"strconv"
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
		rs = fmt.Sprintf("%s%s\n", rs, vs)
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

func (s *Streams) HttpStreams() []*HttpStream {
	s.streamsMux.RLock()
	defer s.streamsMux.RUnlock()

	httpStreams := make([]*HttpStream, 0)
	for _, stream := range s.streams {
		if !stream.IsHTTP() {
			continue
		}
		httpStream := HttpStream{
			Source:       stream.Source,
			FirstPackage: stream.FirstPackage,
			Destination:  stream.Destination,
		}
		data := stream.Packages.Bytes()
		if isRequest(string(data[:20])) {
			// We have a request
			method, path, _, headers := parseRequest(data)
			httpStream.Type = REQUEST
			httpStream.Method = method
			httpStream.Path = path
			httpStream.Headers = headers
		} else {
			// We have a response
			statusCode, _, headers := parseResponse(data)
			httpStream.Type = RESPONSE
			httpStream.StatusCode = statusCode
			httpStream.Headers = headers
		}

		httpStreams = append(httpStreams, &httpStream)
	}
	return httpStreams
}

type HttpStreamType string

var (
	REQUEST  HttpStreamType = "request"
	RESPONSE HttpStreamType = "response"
)

type HttpStream struct {
	Source       string
	FirstPackage time.Time
	Destination  string

	Type HttpStreamType
	// Both
	Headers http.Header
	// Request
	Path   string
	Method string
	// Response
	StatusCode string
	BodyLen    int64
}

type Stream struct {
	Source       string
	FirstPackage time.Time
	Destination  string
	Packages     tcp_packages.Packages
}

func (s *Stream) IsHTTP() bool {
	if s.Packages.Len() == 0 {
		return false
	}
	payload := s.Packages.Bytes()
	return bytes.Contains(payload, []byte("HTTP"))
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

	p := fmt.Sprintf("%s => %s\n", s.Source, s.Destination)
	r := ""
	if isRequest(string(payload[:20])) {
		// We have a request
		r = printRequest(payload)
	} else {
		r = printResponse(payload)
	}

	if r == "" {
		return ""
	}

	// We have a response
	return fmt.Sprintf("%s%s\n", p, r)
}

func printRequest(payload []byte) string {
	lines := strings.Split(string(payload), "\n")

	//First Line contains path and request
	mainInfo := strings.Split(lines[0], " ")
	method := mainInfo[0]
	path := mainInfo[1]
	httpVersion := mainInfo[2]

	if strings.Contains(path, "/healthz") ||
		strings.Contains(path, "/metrics") {
		return ""
	}

	headers := make([]string, 0)
	for _, line := range lines[1:] {
		if strings.TrimSpace(line) == "" {
			break
		}
		if strings.Contains(line, "Prometheus") ||
			strings.Contains(line, "GoogleHC") {
			return ""
		}
		headers = append(headers, line)
	}

	return fmt.Sprintf("%s %s %s\n%s", method, path, httpVersion, strings.Join(headers, "\n"))
}

func parseRequest(payload []byte) (method, path, httpVersion string, headers http.Header) {
	lines := strings.Split(string(payload), "\n")

	//First Line contains path and request
	mainInfo := strings.Split(lines[0], " ")
	method = mainInfo[0]
	path = mainInfo[1]
	httpVersion = mainInfo[2]
	headers = parseHeaders(lines[1:])
	return method, path, httpVersion, headers
}

func parseResponse(payload []byte) (statusCode, httpVersion string, headers http.Header) {
	lines := strings.Split(string(payload), "\n")

	//First Line contains path and request
	mainInfo := strings.Split(lines[0], " ")
	httpVersion = mainInfo[0]
	statusCode = mainInfo[1]

	headers = parseHeaders(lines[1:])
	return statusCode, httpVersion, headers
}

func parseHeaders(lines []string) http.Header {
	headers := make(http.Header)

	chunked := false
	lastHeaderIndex := 0
	for k, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			lastHeaderIndex = k
			break
		}
		if strings.Contains(line, "chunked") {
			chunked = true
		}
		d := strings.Split(line, ":")
		if len(d) != 2 {
			break
		}
		headers.Set(d[0], d[1])
	}

	if chunked {
		var totalBodySize int64 = 0
		// We have a chunked response. Load data
		for _, chunkLine := range lines[lastHeaderIndex:] {
			cleanLine := strings.TrimSpace(strings.ToLower(chunkLine))
			if hexRegex.MatchString(strings.TrimSpace(strings.ToLower(chunkLine))) {
				// We have a hex number
				decimal, err := strconv.ParseInt(cleanLine, 16, 64)
				if err == nil {
					totalBodySize += decimal
				}
				fmt.Println("CHUNK DATA:", chunkLine, "imt", decimal)
			}
		}
		headers.Set("Content-Length", fmt.Sprintf("%d", totalBodySize))
	}

	return headers
}

var hexRegex = regexp.MustCompile(`^[0-9a-f]+$`)

func printResponse(payload []byte) string {
	lines := strings.Split(string(payload), "\n")

	//First Line contains path and request
	mainInfo := strings.Split(lines[0], " ")
	httpVersion := mainInfo[0]
	statusCode := mainInfo[1]
	//status := mainInfo[2]

	headers := make([]string, 0)
	chunked := false
	lastHeaderIndex := 0
	for k, line := range lines[1:] {
		if strings.TrimSpace(line) == "" {
			lastHeaderIndex = k
			break
		}
		if strings.Contains(line, "chunked") {
			chunked = true
		}
		headers = append(headers, line)
	}
	if chunked {
		var totalBodySize int64 = 0
		// We have a chunked response. Load data
		for _, chunkLine := range lines[lastHeaderIndex:] {
			cleanLine := strings.TrimSpace(strings.ToLower(chunkLine))
			if hexRegex.MatchString(strings.TrimSpace(strings.ToLower(chunkLine))) {
				// We have a hex number
				decimal, err := strconv.ParseInt(cleanLine, 16, 64)
				if err == nil {
					totalBodySize += decimal
				}
				fmt.Println("CHUNK DATA:", chunkLine, "imt", decimal)
			}
		}
		headers = append(headers, fmt.Sprintf("Content-Length: %d", totalBodySize))
	}

	return fmt.Sprintf("%s %s\n%s", statusCode, httpVersion, strings.Join(headers, "\n"))

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
