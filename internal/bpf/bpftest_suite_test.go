//go:build bpftest

// Datapath tests for snat_egress and revnat_ingress load the compiled BPF
// objects and drive them directly via BPF_PROG_TEST_RUN (cilium/ebpf's
// Program.Run). Loading BPF programs and maps requires CAP_BPF/CAP_SYS_ADMIN,
// so these tests are gated behind the "bpftest" build tag and must run as
// root — see `task test-bpf`. They also require internal/bpf/*_bpfel.o to
// exist (`task generate`).
package bpf_test

import (
	"encoding/binary"
	"net"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/cilium/ebpf"
	"github.com/hanapedia/mooring/internal/bpf"
)

func TestBPFDatapath(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "BPF Datapath Suite")
}

const (
	natEntrySNAT   uint8 = 0
	natEntryREVNAT uint8 = 1

	protoTCP  uint8 = 6
	protoUDP  uint8 = 17
	protoICMP uint8 = 1

	tcxNext uint32 = 0xffffffff // TCX_NEXT (-1), as returned by Program.Run

	tcpFIN = 0x01
	tcpSYN = 0x02
	tcpRST = 0x04
	tcpACK = 0x10
)

// beU32 packs an IPv4 address into the little-endian uint32 that
// structs.HostLayout marshaling writes as the raw big-endian (network order)
// bytes a BPF __be32 map field expects — mirrors internal/maps.ipToUint32.
func beU32(ip net.IP) uint32 {
	return binary.LittleEndian.Uint32(ip.To4())
}

// beU16 packs a host-order port number the same way, for __be16 map fields.
// nat_config's port_start/port_end are plain __u16 (host order) and must NOT
// go through this — see addSinglePortNatConfig.
func beU16(port uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, port)
	return binary.LittleEndian.Uint16(b)
}

type testPrograms struct {
	snat   *bpf.SnatEgressObjects
	revnat *bpf.RevnatIngressObjects
}

// newTestPrograms loads fresh, unpinned copies of both programs with
// revnat_ingress sharing snat_egress's nat_map and target_cidrs, exactly as
// internal/loader.Load wires them in production — except these tests never
// call link.AttachTCX or Pin(), so no tc/TCX attachment or /sys/fs/bpf entry
// is ever created for the kernel or a later test run to clean up. Programs
// run only via Program.Run (BPF_PROG_TEST_RUN). Close (called from AfterEach)
// closes every loaded FD; since nothing pins or attaches them, the kernel
// frees the maps and programs the moment those FDs close, so each spec
// already starts from empty maps with no teardown step needed beyond that.
func newTestPrograms() *testPrograms {
	snat := &bpf.SnatEgressObjects{}
	ExpectWithOffset(1, bpf.LoadSnatEgressObjects(snat, nil)).
		To(Succeed(), "load snat_egress objects (run as root with CAP_BPF, e.g. `task test-bpf`)")

	revnatSpec, err := bpf.LoadRevnatIngress()
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "load revnat_ingress spec")

	revnat := &bpf.RevnatIngressObjects{}
	ExpectWithOffset(1, revnatSpec.LoadAndAssign(revnat, &ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{
			"nat_map":      snat.NatMap,
			"target_cidrs": snat.TargetCidrs,
		},
	})).To(Succeed(), "load revnat_ingress objects")

	return &testPrograms{snat: snat, revnat: revnat}
}

func (p *testPrograms) Close() {
	ExpectWithOffset(1, p.revnat.Close()).To(Succeed())
	ExpectWithOffset(1, p.snat.Close()).To(Succeed())
}

// addTargetCIDR seeds target_cidrs with a /32 for ip, as moorctl's
// AddTargetCIDR does for a real NATConfig's destination CIDR.
func (p *testPrograms) addTargetCIDR(ip net.IP) {
	key := bpf.SnatEgressLpmKey{Prefixlen: 32, Addr: beU32(ip)}
	val := bpf.SnatEgressTargetCidrVal{Addr: beU32(ip), Prefixlen: 32}
	ExpectWithOffset(1, p.snat.TargetCidrs.Put(key, val)).To(Succeed(), "seed target_cidrs")
}

// addSinglePortNatConfig seeds one port_range_alloc covering exactly extPort
// (port_start == port_end), so allocate_snat_port's clamp-to-range always
// lands on extPort regardless of pod_port — keeping expected allocations
// deterministic in tests.
func (p *testPrograms) addSinglePortNatConfig(podIP, cidrAddr net.IP, cidrPrefixlen uint32, extIP net.IP, extPort uint16) {
	key := bpf.SnatEgressNatConfigKey{
		PodIp:         beU32(podIP),
		CidrAddr:      beU32(cidrAddr),
		CidrPrefixlen: cidrPrefixlen,
	}
	var val bpf.SnatEgressNatConfigVal
	val.PortRangeAllocs[0].ExtIp = beU32(extIP)
	val.PortRangeAllocs[0].PortStart = extPort // host-order __u16, not beU16
	val.PortRangeAllocs[0].PortEnd = extPort
	val.Count = 1
	ExpectWithOffset(1, p.snat.NatConfig.Put(key, val)).To(Succeed(), "seed nat_config")
}

func natMapKey(ipA, ipB net.IP, portA, portB uint16, proto, kind uint8) bpf.SnatEgressNatMapKey {
	return bpf.SnatEgressNatMapKey{
		IpA: beU32(ipA), IpB: beU32(ipB),
		PortA: beU16(portA), PortB: beU16(portB),
		Proto: proto, Kind: kind,
	}
}

// ipChecksum computes the Internet checksum (RFC 1071) one's-complement sum
// over b. Used both to fill in a checksum field (with that field zeroed) and
// to validate one already filled in — a correct checksum makes the sum come
// out to zero.
func ipChecksum(b []byte) uint16 {
	var sum uint32
	n := len(b)
	for i := 0; i+1 < n; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if n%2 == 1 {
		sum += uint32(b[n-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

// pseudoHeaderChecksum computes the TCP/UDP checksum over the IPv4 pseudo
// header plus the L4 segment (header+payload).
func pseudoHeaderChecksum(src, dst net.IP, proto uint8, l4 []byte) uint16 {
	pseudo := make([]byte, 12+len(l4))
	copy(pseudo[0:4], src.To4())
	copy(pseudo[4:8], dst.To4())
	pseudo[9] = proto
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(l4)))
	copy(pseudo[12:], l4)
	return ipChecksum(pseudo)
}

// buildEthIPv4 wraps an already-checksummed L4 segment in an IPv4 (no
// options) + Ethernet frame, filling in and checksumming the IP header.
func buildEthIPv4(proto uint8, src, dst net.IP, l4 []byte) []byte {
	total := 20 + len(l4)
	pkt := make([]byte, 14+total)
	binary.BigEndian.PutUint16(pkt[12:14], 0x0800) // ETH_P_IP

	ipHdr := pkt[14 : 14+20]
	ipHdr[0] = 0x45 // version 4, IHL 5
	binary.BigEndian.PutUint16(ipHdr[2:4], uint16(total))
	ipHdr[8] = 64 // ttl
	ipHdr[9] = proto
	copy(ipHdr[12:16], src.To4())
	copy(ipHdr[16:20], dst.To4())
	binary.BigEndian.PutUint16(ipHdr[10:12], ipChecksum(ipHdr))

	copy(pkt[34:], l4)
	return pkt
}

func buildTCP(src, dst net.IP, sport, dport uint16, flags uint8) []byte {
	l4 := make([]byte, 20)
	binary.BigEndian.PutUint16(l4[0:2], sport)
	binary.BigEndian.PutUint16(l4[2:4], dport)
	l4[12] = 5 << 4 // data offset: 5 words, no options
	l4[13] = flags
	binary.BigEndian.PutUint16(l4[14:16], 65535) // window
	binary.BigEndian.PutUint16(l4[16:18], pseudoHeaderChecksum(src, dst, protoTCP, l4))
	return buildEthIPv4(protoTCP, src, dst, l4)
}

func buildUDP(src, dst net.IP, sport, dport uint16) []byte {
	l4 := make([]byte, 8)
	binary.BigEndian.PutUint16(l4[0:2], sport)
	binary.BigEndian.PutUint16(l4[2:4], dport)
	binary.BigEndian.PutUint16(l4[4:6], uint16(len(l4)))
	binary.BigEndian.PutUint16(l4[6:8], pseudoHeaderChecksum(src, dst, protoUDP, l4))
	return buildEthIPv4(protoUDP, src, dst, l4)
}

func buildICMPEcho(src, dst net.IP, icmpType uint8, id, seq uint16) []byte {
	l4 := make([]byte, 8)
	l4[0] = icmpType
	binary.BigEndian.PutUint16(l4[4:6], id)
	binary.BigEndian.PutUint16(l4[6:8], seq)
	binary.BigEndian.PutUint16(l4[2:4], ipChecksum(l4))
	return buildEthIPv4(protoICMP, src, dst, l4)
}

// parseEthIPv4 splits a no-options IPv4 packet (as produced by buildEthIPv4)
// into its IP header and L4 segment.
func parseEthIPv4(pkt []byte) (ipHdr, l4 []byte) {
	ExpectWithOffset(1, len(pkt)).To(BeNumerically(">=", 34), "packet too short")
	return pkt[14:34], pkt[34:]
}
