package maps

import (
	"encoding/binary"
	"errors"
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

func openMap(name string) (*ebpf.Map, error) {
	m, err := ebpf.LoadPinnedMap(filepath.Join(mapsDir, name), nil)
	if err != nil {
		return nil, fmt.Errorf("open map %q (is mooring loaded?): %w", name, err)
	}
	return m, nil
}

// UpsertSnatEntry adds or updates the snat_config allocation for (podIP, extIP).
// If an entry for extIP already exists it is overwritten with the new range and
// its next_port counter reset to zero; otherwise a new entry is appended.
func UpsertSnatEntry(podIP, extIP net.IP, portStart, portEnd uint16) error {
	m, err := openMap("snat_config")
	if err != nil {
		return err
	}
	defer m.Close()

	key := ipToUint32(podIP)
	extIPVal := ipToUint32(extIP)

	var val mooringbpf.SnatEgressSnatConfigVal
	if err := m.Lookup(key, &val); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("lookup snat_config: %w", err)
	}

	found := false
	for i := range val.Allocations {
		if uint32(i) >= val.Count {
			break
		}
		if val.Allocations[i].ExtIp == extIPVal {
			val.Allocations[i].PortStart = portStart
			val.Allocations[i].PortEnd = portEnd
			val.Allocations[i].NextPort = 0
			found = true
			break
		}
	}
	if !found {
		if val.Count >= uint32(len(val.Allocations)) {
			return fmt.Errorf("snat_config: max allocations (%d) reached for pod %s", len(val.Allocations), podIP)
		}
		idx := val.Count
		val.Allocations[idx].ExtIp = extIPVal
		val.Allocations[idx].PortStart = portStart
		val.Allocations[idx].PortEnd = portEnd
		val.Allocations[idx].NextPort = 0
		val.Count++
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

// innerMapSpec matches the port_range_inner prototype in revnat_ingress.c:
// BPF_MAP_TYPE_ARRAY, 65536 entries, key=u32 (port index), value=u32 (pod ip).
var innerMapSpec = &ebpf.MapSpec{
	Type:       ebpf.Array,
	KeySize:    4,
	ValueSize:  4,
	MaxEntries: 65536,
}

// portRangeMapName returns the pinned map name for the given IP protocol number.
func portRangeMapName(proto uint8) (string, error) {
	switch proto {
	case 6:
		return "port_range_lookup_tcp", nil
	case 17:
		return "port_range_lookup_udp", nil
	case 1:
		return "port_range_lookup_icmp", nil
	default:
		return "", fmt.Errorf("unsupported protocol %d (want 1=icmp, 6=tcp, 17=udp)", proto)
	}
}

// openOrCreateInnerMap returns the inner array map for extIPKey from the outer
// HASH_OF_MAPS, creating a new one if absent. created=true means the caller
// must insert the returned map into the outer map before closing it.
func openOrCreateInnerMap(outer *ebpf.Map, extIPKey uint32) (inner *ebpf.Map, created bool, err error) {
	var innerFD uint32
	if err = outer.Lookup(extIPKey, &innerFD); err == nil {
		inner, err = ebpf.NewMapFromFD(int(innerFD))
		return inner, false, err
	}
	if !errors.Is(err, ebpf.ErrKeyNotExist) {
		return nil, false, fmt.Errorf("lookup inner map: %w", err)
	}
	inner, err = ebpf.NewMap(innerMapSpec)
	return inner, true, err
}

// AddPortRange writes podIP into the per-extIP inner array for every port in
// [portStart, portEnd] for the given IP protocol (1=ICMP, 6=TCP, 17=UDP).
// The inner array is indexed by host-order port number, matching the BPF-side
// bpf_ntohs(nat_port) lookup.
func AddPortRange(extIP, podIP net.IP, portStart, portEnd uint16, proto uint8) error {
	mapName, err := portRangeMapName(proto)
	if err != nil {
		return err
	}
	outer, err := openMap(mapName)
	if err != nil {
		return err
	}
	defer outer.Close()

	extIPKey := ipToUint32(extIP)
	podIPVal := ipToUint32(podIP)

	inner, created, err := openOrCreateInnerMap(outer, extIPKey)
	if err != nil {
		return fmt.Errorf("open inner map for %v: %w", extIP, err)
	}
	defer inner.Close()

	for port := portStart; port <= portEnd; port++ {
		if err := inner.Put(uint32(port), podIPVal); err != nil {
			return fmt.Errorf("port %d: %w", port, err)
		}
	}

	if created {
		if err := outer.Put(extIPKey, uint32(inner.FD())); err != nil {
			return fmt.Errorf("insert inner map for %v: %w", extIP, err)
		}
	}
	return nil
}

// RemovePortRange zeros out the pod_ip entries for [portStart, portEnd] in the
// inner array for extIP, but only where the entry still matches podIP.
func RemovePortRange(extIP, podIP net.IP, portStart, portEnd uint16, proto uint8) error {
	mapName, err := portRangeMapName(proto)
	if err != nil {
		return err
	}
	outer, err := openMap(mapName)
	if err != nil {
		return err
	}
	defer outer.Close()

	extIPKey := ipToUint32(extIP)

	var innerFD uint32
	if err := outer.Lookup(extIPKey, &innerFD); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil
		}
		return fmt.Errorf("lookup inner map: %w", err)
	}
	inner, err := ebpf.NewMapFromFD(int(innerFD))
	if err != nil {
		return fmt.Errorf("open inner map: %w", err)
	}
	defer inner.Close()

	podIPVal := ipToUint32(podIP)
	var zero uint32
	for port := portStart; port <= portEnd; port++ {
		var cur uint32
		if err := inner.Lookup(uint32(port), &cur); err != nil {
			continue
		}
		if cur == podIPVal {
			if err := inner.Put(uint32(port), zero); err != nil {
				return fmt.Errorf("zero port %d: %w", port, err)
			}
		}
	}
	return nil
}
