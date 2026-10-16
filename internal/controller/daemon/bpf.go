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

// ExtIPKindMap abstracts the "mark these CIDR's IPs as DST_KIND_EXT_IP"
// side of the dst_kind BPF map.
type ExtIPKindMap interface {
	Add(cidr *net.IPNet) error
	Remove(cidr *net.IPNet) error
}

// PodIPKindMap abstracts the "mark this pod IP as DST_KIND_POD_IP" side of
// the dst_kind BPF map.
type PodIPKindMap interface {
	Add(podIP net.IP) error
	Remove(podIP net.IP) error
}

// PortRangeLookupMap abstracts the port_range_lookup HASH_OF_MAPS BPF map
// (one outer map per IP protocol: TCP, UDP, ICMP).
type PortRangeLookupMap interface {
	Add(extIP, podIP net.IP, portStart, portEnd uint16, proto uint8) error
	Remove(extIP, podIP net.IP, portStart, portEnd uint16, proto uint8) error
}

// NatConfigMap abstracts the nat_config BPF map.
// Each entry is keyed by (podIP, targetCIDR) and holds all external-IP allocations
// for that (pod, target-CIDR) pair.
type NatConfigMap interface {
	Upsert(podIP net.IP, targetCIDR *net.IPNet, extIP net.IP, portStart, portEnd uint16) error
	RemoveAllocs(podIP net.IP, targetCIDR *net.IPNet, extIPs []net.IP) error
}

// RealTargetCIDRMap is the production implementation of TargetCIDRMap.
type RealTargetCIDRMap struct{}

func (RealTargetCIDRMap) Add(cidr *net.IPNet) error    { return maps.AddTargetCIDR(cidr) }
func (RealTargetCIDRMap) Remove(cidr *net.IPNet) error { return maps.RemoveTargetCIDR(cidr) }

// RealExtIPKindMap is the production implementation of ExtIPKindMap.
type RealExtIPKindMap struct{}

func (RealExtIPKindMap) Add(cidr *net.IPNet) error    { return maps.AddExtIPKind(cidr) }
func (RealExtIPKindMap) Remove(cidr *net.IPNet) error { return maps.RemoveExtIPKind(cidr) }

// RealPodIPKindMap is the production implementation of PodIPKindMap.
type RealPodIPKindMap struct{}

func (RealPodIPKindMap) Add(podIP net.IP) error    { return maps.AddPodIPKind(podIP) }
func (RealPodIPKindMap) Remove(podIP net.IP) error { return maps.RemovePodIPKind(podIP) }

// RealPortRangeLookupMap is the production implementation of PortRangeLookupMap.
type RealPortRangeLookupMap struct{}

func (RealPortRangeLookupMap) Add(extIP, podIP net.IP, portStart, portEnd uint16, proto uint8) error {
	return maps.AddPortRange(extIP, podIP, portStart, portEnd, proto)
}

func (RealPortRangeLookupMap) Remove(extIP, podIP net.IP, portStart, portEnd uint16, proto uint8) error {
	return maps.RemovePortRange(extIP, podIP, portStart, portEnd, proto)
}

// RealNatConfigMap is the production implementation of NatConfigMap.
type RealNatConfigMap struct{}

func (RealNatConfigMap) Upsert(podIP net.IP, targetCIDR *net.IPNet, extIP net.IP, portStart, portEnd uint16) error {
	return maps.UpsertNatConfigEntry(podIP, targetCIDR, extIP, portStart, portEnd)
}

func (RealNatConfigMap) RemoveAllocs(podIP net.IP, targetCIDR *net.IPNet, extIPs []net.IP) error {
	return maps.RemoveNatConfigAllocs(podIP, targetCIDR, extIPs)
}
