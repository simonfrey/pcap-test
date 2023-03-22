package flows

import (
	"fmt"
	"pcaptest/pkg/kube"
	"pcaptest/pkg/streams"
	"pcaptest/pkg/tcp_packages"
	"strings"
	"sync"
	"time"
)

type Flows struct {
	flowsMux sync.RWMutex
	flows    map[string]*Flow
	ipMapper *kube.IPMapper
}

func NewFlows(ipMapper *kube.IPMapper) *Flows {
	return &Flows{
		flowsMux: sync.RWMutex{},
		flows:    map[string]*Flow{},
		ipMapper: ipMapper,
	}
}

func (f *Flows) SetFlow(src, dst string, flow *Flow) {
	f.flowsMux.Lock()
	defer f.flowsMux.Unlock()

	f.flows[fmt.Sprintf("%s%s", src, dst)] = flow
	f.flows[fmt.Sprintf("%s%s", dst, src)] = flow
}

func (f *Flows) GetFlow(src, dst string) *Flow {
	f.flowsMux.RLock()
	defer f.flowsMux.RUnlock()

	return f.flows[fmt.Sprintf("%s%s", src, dst)]
}

func (f *Flows) PrintFlow(src, dst string) string {
	flow := f.GetFlow(src, dst)
	if flow == nil {
		// Did not get any flow
		return ""
	}
	return flow.Print()
}

func (f *Flows) DeleteFlow(src, dst string) {
	f.flowsMux.Lock()
	defer f.flowsMux.Unlock()
	delete(f.flows, fmt.Sprintf("%s%s", src, dst))
	delete(f.flows, fmt.Sprintf("%s%s", dst, src))
}

func (f *Flows) AddPackage(src, dst string, p *tcp_packages.Pack) {
	// Find flow
	flow := f.GetFlow(src, dst)
	if flow == nil {
		flow = &Flow{
			Initiator: src,
			// TODO: get app name
			InitiatorApp: f.ipMapper.Get(strings.Split(src, ":")[0]),
			Target:       dst,
			TargetApp:    f.ipMapper.Get(strings.Split(dst, ":")[0]),
			FirstPackage: time.Now(),
			LastPackage:  time.Now(),
			Streams:      streams.NewStreams(),
		}
		f.SetFlow(src, dst, flow)
	}

	flow.LastPackage = time.Now()
	flow.Streams.AddPackage(src, dst, p)
}

type Flow struct {
	Initiator    string
	InitiatorApp string
	Target       string
	TargetApp    string
	FirstPackage time.Time
	LastPackage  time.Time

	//muxStream sync.RWMutex
	Streams streams.Streams
}

func (f *Flow) Print() string {
	streamsPrint := f.Streams.Print()
	if streamsPrint == "" {
		return ""
	}
	return fmt.Sprintf("---------------\n%s=>%s\n%s\n---------------",
		f.Initiator, f.Target, streamsPrint)
}
