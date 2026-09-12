package operator

import (
	"fmt"
	"net"

	v1alpha1 "github.com/hanapedia/mooring/api/v1alpha1"
	"github.com/hanapedia/mooring/internal/allocator"
)

const (
	finalizerName        = "mooring.hanapedia.link/allocation"
	defaultPortRangeCount = uint16(1)
)

// expandCIDRs expands a list of CIDR strings into individual IP address strings.
// Duplicate IPs across CIDRs are deduplicated.
func expandCIDRs(cidrs []string) ([]string, error) {
	var ips []string
	seen := make(map[string]struct{})
	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %s: %w", cidr, err)
		}
		for ip := cloneIP(network.IP); network.Contains(ip); incrementIP(ip) {
			s := ip.String()
			if _, ok := seen[s]; !ok {
				ips = append(ips, s)
				seen[s] = struct{}{}
			}
		}
	}
	return ips, nil
}

func cloneIP(ip net.IP) net.IP {
	clone := make(net.IP, len(ip))
	copy(clone, ip)
	return clone
}

func incrementIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}

func stringSet(ss []string) map[string]struct{} {
	m := make(map[string]struct{}, len(ss))
	for _, s := range ss {
		m[s] = struct{}{}
	}
	return m
}

// groupAllocsByIP groups a flat PortAllocation slice into a map keyed by ExternalIP.
func groupAllocsByIP(allocs []v1alpha1.PortAllocation) map[string][]v1alpha1.PortAllocation {
	m := make(map[string][]v1alpha1.PortAllocation)
	for _, a := range allocs {
		m[a.ExternalIP] = append(m[a.ExternalIP], a)
	}
	return m
}

// collectPortStarts returns all PortStart values from a PortAllocation slice as uint16.
func collectPortStarts(allocs []v1alpha1.PortAllocation) []uint16 {
	out := make([]uint16, 0, len(allocs))
	for _, a := range allocs {
		out = append(out, uint16(a.PortStart))
	}
	return out
}

// buildPortAllocations converts AllocateForPod output into a PortAllocation slice.
func buildPortAllocations(allocations map[string][]allocator.Allocation) []v1alpha1.PortAllocation {
	var result []v1alpha1.PortAllocation
	for ip, als := range allocations {
		for _, al := range als {
			result = append(result, v1alpha1.PortAllocation{
				ExternalIP: ip,
				PortStart:  int32(al.PortStart),
				PortEnd:    int32(al.PortEnd),
			})
		}
	}
	return result
}

