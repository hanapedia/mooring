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

// UpsertNatConfigEntry adds or updates the nat_config port-range allocation
// for (podIP, targetCIDR, extIP). If an entry for extIP already exists within
// the (podIP, targetCIDR) bucket it is overwritten with the new range;
// otherwise a new entry is appended.
func UpsertNatConfigEntry(podIP net.IP, targetCIDR *net.IPNet, extIP net.IP, portStart, portEnd uint16) error {
	m, err := openMap("nat_config")
	if err != nil {
		return err
	}
	defer m.Close()

	ones, _ := targetCIDR.Mask.Size()
	cidrIP4 := targetCIDR.IP.To4()
	if cidrIP4 == nil {
		return fmt.Errorf("only IPv4 target CIDRs are supported")
	}
	key := mooringbpf.SnatEgressNatConfigKey{
		PodIp:         ipToUint32(podIP.To4()),
		CidrAddr:      ipToUint32(cidrIP4),
		CidrPrefixlen: uint32(ones),
	}
	extIPVal := ipToUint32(extIP)

	var val mooringbpf.SnatEgressNatConfigVal
	if err := m.Lookup(key, &val); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("lookup nat_config: %w", err)
	}

	found := false
	for i := range val.PortRangeAllocs {
		if uint32(i) >= val.Count {
			break
		}
		if val.PortRangeAllocs[i].ExtIp == extIPVal {
			val.PortRangeAllocs[i].PortStart = portStart
			val.PortRangeAllocs[i].PortEnd = portEnd
			found = true
			break
		}
	}
	if !found {
		if val.Count >= uint32(len(val.PortRangeAllocs)) {
			return fmt.Errorf("nat_config: max allocations (%d) reached for pod %s", len(val.PortRangeAllocs), podIP)
		}
		idx := val.Count
		val.PortRangeAllocs[idx].ExtIp = extIPVal
		val.PortRangeAllocs[idx].PortStart = portStart
		val.PortRangeAllocs[idx].PortEnd = portEnd
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
	val := mooringbpf.SnatEgressTargetCidrVal{
		Addr:      ipToUint32(ip4),
		Prefixlen: uint32(ones),
	}
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
//
// HASH_OF_MAPS lookup returns the inner map's ID (not an fd); passing **Map
// lets cilium/ebpf call NewMapFromID internally via unmarshalMap.
func openOrCreateInnerMap(outer *ebpf.Map, extIPKey uint32) (inner *ebpf.Map, created bool, err error) {
	err = outer.Lookup(extIPKey, &inner)
	if err == nil {
		return inner, false, nil
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
		if err := outer.Put(extIPKey, inner); err != nil {
			return fmt.Errorf("insert inner map for %v: %w", extIP, err)
		}
	}
	return nil
}

// RemoveNatConfigAllocs removes the nat_config allocations for the given
// extIPs from the (podIP, targetCIDR) entry. Slots for ext-IPs not in the
// list are left intact. If all allocations are removed, the entry is deleted
// entirely.
func RemoveNatConfigAllocs(podIP net.IP, targetCIDR *net.IPNet, extIPs []net.IP) error {
	m, err := openMap("nat_config")
	if err != nil {
		return err
	}
	defer m.Close()

	ones, _ := targetCIDR.Mask.Size()
	cidrIP4 := targetCIDR.IP.To4()
	if cidrIP4 == nil {
		return fmt.Errorf("only IPv4 target CIDRs are supported")
	}
	key := mooringbpf.SnatEgressNatConfigKey{
		PodIp:         ipToUint32(podIP.To4()),
		CidrAddr:      ipToUint32(cidrIP4),
		CidrPrefixlen: uint32(ones),
	}

	var val mooringbpf.SnatEgressNatConfigVal
	if err := m.Lookup(key, &val); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil
		}
		return fmt.Errorf("lookup nat_config for %s/%s: %w", podIP, targetCIDR, err)
	}

	toRemove := make(map[uint32]struct{}, len(extIPs))
	for _, ip := range extIPs {
		toRemove[ipToUint32(ip)] = struct{}{}
	}

	newCount := uint32(0)
	for i := uint32(0); i < val.Count; i++ {
		if _, ok := toRemove[val.PortRangeAllocs[i].ExtIp]; ok {
			continue
		}
		val.PortRangeAllocs[newCount] = val.PortRangeAllocs[i]
		newCount++
	}
	if newCount == val.Count {
		return nil
	}
	for i := newCount; i < val.Count; i++ {
		val.PortRangeAllocs[i].ExtIp = 0
		val.PortRangeAllocs[i].PortStart = 0
		val.PortRangeAllocs[i].PortEnd = 0
	}
	val.Count = newCount

	if newCount == 0 {
		if err := m.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("delete nat_config for %s/%s: %w", podIP, targetCIDR, err)
		}
		return nil
	}
	return m.Put(key, val)
}

// RemoveTargetCIDR deletes a destination CIDR from the target_cidrs LPM map.
func RemoveTargetCIDR(cidr *net.IPNet) error {
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
	if err := m.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("remove target CIDR %s: %w", cidr, err)
	}
	return nil
}

// RemoveExtIP deletes an external IP CIDR from the ext_ip_pool LPM map.
func RemoveExtIP(cidr *net.IPNet) error {
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
	if err := m.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("remove ext IP %s: %w", cidr, err)
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

	var inner *ebpf.Map
	if err := outer.Lookup(extIPKey, &inner); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil
		}
		return fmt.Errorf("lookup inner map: %w", err)
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
