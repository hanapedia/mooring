package daemon

import (
	"net"

	"github.com/hanapedia/mooring/internal/maps"
)

// PortRangeBPF abstracts the BPF map operations performed by the NATPortRange
// sync controller. The real implementation delegates to the maps package; tests
// inject a recording stub.
type PortRangeBPF interface {
	AddPortRange(extIP, podIP net.IP, portStart, portEnd uint16, proto uint8) error
	RemovePortRange(extIP, podIP net.IP, portStart, portEnd uint16, proto uint8) error
	// UpsertSnatEntry updates the snat_config entry for (podIP, targetCIDR).
	// Each (podIP, targetCIDR) pair is a separate BPF map entry so a pod matched
	// by multiple NATConfigs gets independent ext-IP pools per target CIDR.
	UpsertSnatEntry(podIP net.IP, targetCIDR *net.IPNet, extIP net.IP, portStart, portEnd uint16) error
	// RemoveSnatAllocs removes allocations for the given extIPs from the
	// (podIP, targetCIDR) snat_config entry.
	RemoveSnatAllocs(podIP net.IP, targetCIDR *net.IPNet, extIPs []net.IP) error
}

// LPMBPF abstracts the LPM map operations performed by the NATConfig
// controller. The real implementation delegates to the maps package; tests
// inject a recording stub.
type LPMBPF interface {
	AddTargetCIDR(cidr *net.IPNet) error
	RemoveTargetCIDR(cidr *net.IPNet) error
	AddExtIP(cidr *net.IPNet) error
	RemoveExtIP(cidr *net.IPNet) error
}

// RealPortRangeBPF is the production implementation of PortRangeBPF.
type RealPortRangeBPF struct{}

func (RealPortRangeBPF) AddPortRange(extIP, podIP net.IP, portStart, portEnd uint16, proto uint8) error {
	return maps.AddPortRange(extIP, podIP, portStart, portEnd, proto)
}
func (RealPortRangeBPF) RemovePortRange(extIP, podIP net.IP, portStart, portEnd uint16, proto uint8) error {
	return maps.RemovePortRange(extIP, podIP, portStart, portEnd, proto)
}
func (RealPortRangeBPF) UpsertSnatEntry(podIP net.IP, targetCIDR *net.IPNet, extIP net.IP, portStart, portEnd uint16) error {
	return maps.UpsertSnatEntry(podIP, targetCIDR, extIP, portStart, portEnd)
}
func (RealPortRangeBPF) RemoveSnatAllocs(podIP net.IP, targetCIDR *net.IPNet, extIPs []net.IP) error {
	return maps.RemoveSnatAllocs(podIP, targetCIDR, extIPs)
}

// RealLPMBPF is the production implementation of LPMBPF.
type RealLPMBPF struct{}

func (RealLPMBPF) AddTargetCIDR(cidr *net.IPNet) error  { return maps.AddTargetCIDR(cidr) }
func (RealLPMBPF) RemoveTargetCIDR(cidr *net.IPNet) error { return maps.RemoveTargetCIDR(cidr) }
func (RealLPMBPF) AddExtIP(cidr *net.IPNet) error        { return maps.AddExtIP(cidr) }
func (RealLPMBPF) RemoveExtIP(cidr *net.IPNet) error     { return maps.RemoveExtIP(cidr) }
