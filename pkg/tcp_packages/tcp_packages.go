package tcp_packages

import (
	"sort"
	"sync"
	"time"
)

type Pack struct {
	Received time.Time
	Payload  []byte
	Seq      uint32
}
type Packages struct {
	packagesMux sync.Mutex
	packages    []*Pack
}

func (p *Packages) AddPackage(pack *Pack) {
	p.packagesMux.Lock()
	defer p.packagesMux.Unlock()
	p.packages = append(p.packages, pack)
}

func NewPackages() Packages {
	return Packages{
		packagesMux: sync.Mutex{},
		packages:    make([]*Pack, 0),
	}
}
func (p *Packages) Bytes() []byte {
	p.packagesMux.Lock()
	defer p.packagesMux.Unlock()

	sort.Sort(p)
	b := make([]byte, 0)
	for _, v := range p.packages {
		b = append(b, v.Payload...)
	}
	return b
}

func (p *Packages) Len() int           { return len(p.packages) }
func (p *Packages) Less(i, j int) bool { return p.packages[i].Seq < p.packages[j].Seq }
func (p *Packages) Swap(i, j int)      { p.packages[i], p.packages[j] = p.packages[j], p.packages[i] }
