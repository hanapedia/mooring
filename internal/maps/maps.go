package maps

import (
	"encoding/binary"
	"fmt"
	"net"
	"path/filepath"

	"github.com/cilium/ebpf"
	mooringbpf "github.com/hanapedia/mooring/internal/bpf"
)

const mapsDir = "/sys/fs/bpf/mooring/maps"

// ipToUint32 converts a net.IP to the uint32 that, when stored in
// little-endian (host) memory, produces the correct network-order bytes.
func ipToUint32(ip net.IP) uint32 {
	return binary.LittleEndian.Uint32(ip.To4())
}

// htons swaps the bytes of a port number from host to network byte order.
func htons(p uint16) uint16 {
	return p>>8 | p<<8
}

func openMap(name string) (*ebpf.Map, error) {
	m, err := ebpf.LoadPinnedMap(filepath.Join(mapsDir, name), nil)
	if err != nil {
		return nil, fmt.Errorf("open map %q (is mooring loaded?): %w", name, err)
	}
	return m, nil
}

// AddSnatConfig writes a SNAT config entry for podIP → {extIP, portStart, portEnd}.
func AddSnatConfig(podIP, extIP net.IP, portStart, portEnd uint16) error {
	m, err := openMap("snat_config")
	if err != nil {
		return err
	}
	defer m.Close()

	key := ipToUint32(podIP)
	val := mooringbpf.SnatEgressSnatEntry{
		ExtIp:     ipToUint32(extIP),
		PortStart: portStart,
		PortEnd:   portEnd,
		NextPort:  0,
	}
	return m.Put(key, val)
}

// AddTargetCIDR adds a destination CIDR to the shared target_cidrs map.
// Packets whose destination matches will be considered for SNAT/revNAT.
func AddTargetCIDR(cidr *net.IPNet) error {
	ip4 := cidr.IP.To4()
	if ip4 == nil {
		return fmt.Errorf("only IPv4 CIDRs are supported")
	}
	m, err := openMap("target_cidrs")
	if err != nil {
		return err
	}
	defer m.Close()

	ones, _ := cidr.Mask.Size()
	key := mooringbpf.SnatEgressLpmKey{
		Prefixlen: uint32(ones),
		Addr:      ipToUint32(ip4),
	}
	var val uint8 = 1
	return m.Put(key, val)
}

// AddExtIP adds an external IP CIDR to the ext_ip_pool map used by the
// ingress revNAT program to identify packets destined for our external IPs.
func AddExtIP(cidr *net.IPNet) error {
	ip4 := cidr.IP.To4()
	if ip4 == nil {
		return fmt.Errorf("only IPv4 CIDRs are supported")
	}
	m, err := openMap("ext_ip_pool")
	if err != nil {
		return err
	}
	defer m.Close()

	ones, _ := cidr.Mask.Size()
	key := mooringbpf.RevnatIngressLpmKey{
		Prefixlen: uint32(ones),
		Addr:      ipToUint32(ip4),
	}
	var val uint8 = 1
	return m.Put(key, val)
}

// AddPortRange expands [portStart, portEnd] into port_range_lookup, writing
// one {extIP, natPort} → podIP entry per port number.
func AddPortRange(extIP, podIP net.IP, portStart, portEnd uint16) error {
	m, err := openMap("port_range_lookup")
	if err != nil {
		return err
	}
	defer m.Close()

	extIPVal := ipToUint32(extIP)
	podIPVal := ipToUint32(podIP)

	for port := portStart; port <= portEnd; port++ {
		key := mooringbpf.RevnatIngressPortKey{
			ExtIp:   extIPVal,
			NatPort: htons(port),
		}
		if err := m.Put(key, podIPVal); err != nil {
			return fmt.Errorf("port %d: %w", port, err)
		}
	}
	return nil
}
