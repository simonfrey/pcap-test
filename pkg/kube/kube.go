package kube

import "sync"

type IPMapper struct {
	ipsMux sync.RWMutex
	ips    map[string]string
}

func NewIPMapper() *IPMapper {
	return &IPMapper{
		ipsMux: sync.RWMutex{},
		ips:    map[string]string{},
	}
}

func (i *IPMapper) Set(ip, name string) {
	i.ipsMux.Lock()
	defer i.ipsMux.Unlock()

	i.ips[ip] = name
}

func (i *IPMapper) Get(ip string) string {
	i.ipsMux.RLock()
	defer i.ipsMux.RUnlock()

	return i.ips[ip]
}
