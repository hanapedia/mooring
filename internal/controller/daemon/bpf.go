package daemon

import (
	"net"

	"github.com/hanapedia/mooring/internal/maps"
)

// TargetCIDRMap abstracts the target_cidrs LPM BPF map.
type TargetCIDRMap interface {
	Add(cidr *net.IPNet) error
	Remove(cidr *net.IPNet) error
}

// ExtIPPoolMap abstracts the ext_ip_pool LPM BPF map.
type ExtIPPoolMap interface {
	Add(cidr *net.IPNet) error
	Remove(cidr *net.IPNet) error
}

// PortRangeLookupMap abstracts the port_range_lookup HASH_OF_MAPS BPF map
// (one outer map per IP protocol: TCP, UDP, ICMP).
type PortRangeLookupMap interface {
	Add(extIP, podIP net.IP, portStart, portEnd uint16, proto uint8) error
	Remove(extIP, podIP net.IP, portStart, portEnd uint16, proto uint8) error
}

// SnatConfigMap abstracts the snat_config BPF map.
// Each entry is keyed by (podIP, targetCIDR) and holds all external-IP allocations
// for that (pod, target-CIDR) pair.
type SnatConfigMap interface {
	Upsert(podIP net.IP, targetCIDR *net.IPNet, extIP net.IP, portStart, portEnd uint16) error
	RemoveAllocs(podIP net.IP, targetCIDR *net.IPNet, extIPs []net.IP) error
}

// RealTargetCIDRMap is the production implementation of TargetCIDRMap.
type RealTargetCIDRMap struct{}

func (RealTargetCIDRMap) Add(cidr *net.IPNet) error    { return maps.AddTargetCIDR(cidr) }
func (RealTargetCIDRMap) Remove(cidr *net.IPNet) error { return maps.RemoveTargetCIDR(cidr) }

// RealExtIPPoolMap is the production implementation of ExtIPPoolMap.
type RealExtIPPoolMap struct{}

func (RealExtIPPoolMap) Add(cidr *net.IPNet) error    { return maps.AddExtIP(cidr) }
func (RealExtIPPoolMap) Remove(cidr *net.IPNet) error { return maps.RemoveExtIP(cidr) }

// RealPortRangeLookupMap is the production implementation of PortRangeLookupMap.
type RealPortRangeLookupMap struct{}

func (RealPortRangeLookupMap) Add(extIP, podIP net.IP, portStart, portEnd uint16, proto uint8) error {
	return maps.AddPortRange(extIP, podIP, portStart, portEnd, proto)
}

func (RealPortRangeLookupMap) Remove(extIP, podIP net.IP, portStart, portEnd uint16, proto uint8) error {
	return maps.RemovePortRange(extIP, podIP, portStart, portEnd, proto)
}

// RealSnatConfigMap is the production implementation of SnatConfigMap.
type RealSnatConfigMap struct{}

func (RealSnatConfigMap) Upsert(podIP net.IP, targetCIDR *net.IPNet, extIP net.IP, portStart, portEnd uint16) error {
	return maps.UpsertSnatEntry(podIP, targetCIDR, extIP, portStart, portEnd)
}

func (RealSnatConfigMap) RemoveAllocs(podIP net.IP, targetCIDR *net.IPNet, extIPs []net.IP) error {
	return maps.RemoveSnatAllocs(podIP, targetCIDR, extIPs)
}
