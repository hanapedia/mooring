//go:build bpftest

package bpf_test

import (
	"encoding/binary"
	"net"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/cilium/ebpf"
	"github.com/hanapedia/mooring/internal/bpf"
)

// xdpPass is XDP_PASS, as returned by Program.Run for the xdp revnat program.
const xdpPass uint32 = 2

// xdpDrop is XDP_DROP, as returned by Program.Run for a dropped packet.
const xdpDrop uint32 = 1

// testProgramsXDP mirrors testPrograms (bpftest_suite_test.go) but loads
// revnat_xdp instead of revnat_ingress, to exercise the same stage1/stage2
// logic through the XDP entry point (bpf/revnat_xdp.c, sharing
// bpf/revnat_core.h with the TC entry point via bpf/headers/ctx/xdp.h).
type testProgramsXDP struct {
	snat   *bpf.SnatEgressObjects
	revnat *bpf.RevnatXdpObjects
}

func newTestProgramsXDP() *testProgramsXDP {
	snat := &bpf.SnatEgressObjects{}
	ExpectWithOffset(1, bpf.LoadSnatEgressObjects(snat, nil)).
		To(Succeed(), "load snat_egress objects (run as root with CAP_BPF, e.g. `task test-bpf`)")

	revnatSpec, err := bpf.LoadRevnatXdp()
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "load revnat_xdp spec")

	revnat := &bpf.RevnatXdpObjects{}
	ExpectWithOffset(1, revnatSpec.LoadAndAssign(revnat, &ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{
			"nat_map":      snat.NatMap,
			"target_cidrs": snat.TargetCidrs,
		},
	})).To(Succeed(), "load revnat_xdp objects")

	return &testProgramsXDP{snat: snat, revnat: revnat}
}

func (p *testProgramsXDP) Close() {
	ExpectWithOffset(1, p.revnat.Close()).To(Succeed())
	ExpectWithOffset(1, p.snat.Close()).To(Succeed())
}

func (p *testProgramsXDP) addTargetCIDR(ip net.IP) {
	key := bpf.SnatEgressLpmKey{Prefixlen: 32, Addr: beU32(ip)}
	val := bpf.SnatEgressTargetCidrVal{Addr: beU32(ip), Prefixlen: 32}
	ExpectWithOffset(1, p.snat.TargetCidrs.Put(key, val)).To(Succeed(), "seed target_cidrs")
}

// addDstKindExtIP / addDstKindPodIP mirror testPrograms' helpers of the same
// name (bpftest_suite_test.go), for the XDP entry point.
func (p *testProgramsXDP) addDstKindExtIP(ip net.IP) {
	ExpectWithOffset(1, p.revnat.DstKind.Put(beU32(ip), dstKindExtIP)).To(Succeed(), "seed dst_kind (ext ip)")
}

func (p *testProgramsXDP) addDstKindPodIP(ip net.IP) {
	ExpectWithOffset(1, p.revnat.DstKind.Put(beU32(ip), dstKindPodIP)).To(Succeed(), "seed dst_kind (pod ip)")
}

// addPodNatPorts mirrors testPrograms' helper of the same name
// (bpftest_suite_test.go), for the XDP entry point.
func (p *testProgramsXDP) addPodNatPorts(podIP net.IP, portStart, portEnd uint16) {
	for port := portStart; port <= portEnd; port++ {
		key := bpf.RevnatXdpPodPortKey{PodIp: beU32(podIP), Port: port}
		ExpectWithOffset(1, p.revnat.PodNatPorts.Put(key, uint8(1))).To(Succeed(), "seed pod_nat_ports")
	}
}

var _ = Describe("revnat_xdp", func() {
	var p *testProgramsXDP

	BeforeEach(func() {
		p = newTestProgramsXDP()
	})

	AfterEach(func() {
		p.Close()
	})

	Context("known local connection", func() {
		It("rewrites the destination port back to the pod port", func() {
			podIP := net.ParseIP("10.0.0.5")
			serverIP := net.ParseIP("93.184.216.34")
			extIP := net.ParseIP("203.0.113.9")
			const podPort, serverPort, natPort uint16 = 53421, 80, 40000

			p.addTargetCIDR(serverIP)
			p.addDstKindPodIP(podIP)
			p.addPodNatPorts(podIP, natPort, natPort)

			revnatVal := bpf.SnatEgressNatMapVal{NatIp: beU32(extIP), Port: beU16(podPort)}
			Expect(p.snat.NatMap.Put(natMapKey(serverIP, podIP, serverPort, natPort, protoTCP, natEntryREVNAT), revnatVal)).
				To(Succeed(), "seed revnat entry")

			in := buildTCP(serverIP, podIP, serverPort, natPort, tcpACK)
			out := make([]byte, len(in))
			ret, err := p.revnat.RevnatXdp.Run(&ebpf.RunOptions{Data: in, DataOut: out})
			Expect(err).NotTo(HaveOccurred())
			Expect(ret).To(Equal(xdpPass))

			ipHdr, l4 := parseEthIPv4(out)
			Expect(net.IP(ipHdr[16:20])).To(Equal(podIP.To4()), "dst IP should be unchanged")
			Expect(binary.BigEndian.Uint16(l4[2:4])).To(Equal(podPort), "dst port")
			Expect(pseudoHeaderChecksum(serverIP, podIP, protoTCP, l4)).To(BeZero(), "TCP checksum invalid after rewrite")
		})
	})

	Context("source not in target_cidrs", func() {
		It("passes the packet through unmodified even when dst matches dst_kind", func() {
			podIP := net.ParseIP("10.0.0.5")
			serverIP := net.ParseIP("93.184.216.34") // never added to target_cidrs

			p.addDstKindPodIP(podIP)

			in := buildTCP(serverIP, podIP, 80, 40000, tcpACK)
			out := make([]byte, len(in))
			ret, err := p.revnat.RevnatXdp.Run(&ebpf.RunOptions{Data: in, DataOut: out})
			Expect(err).NotTo(HaveOccurred())
			Expect(ret).To(Equal(xdpPass))
			Expect(out).To(Equal(in), "packet was modified despite no target_cidrs match")
		})
	})

	Context("dst is not a known mooring IP at all", func() {
		It("passes the packet through unmodified", func() {
			unrelatedPodIP := net.ParseIP("10.0.0.99") // never added to dst_kind
			serverIP := net.ParseIP("93.184.216.34")

			p.addTargetCIDR(serverIP)

			in := buildTCP(serverIP, unrelatedPodIP, 80, 40000, tcpACK)
			out := make([]byte, len(in))
			ret, err := p.revnat.RevnatXdp.Run(&ebpf.RunOptions{Data: in, DataOut: out})
			Expect(err).NotTo(HaveOccurred())
			Expect(ret).To(Equal(xdpPass), "should pass through, not drop/redirect")
			Expect(out).To(Equal(in), "packet was modified despite no dst_kind match")
		})
	})

	Context("dst_kind is POD_IP but nat_map misses, dst port inside the pod's own NAT block", func() {
		It("drops the packet instead of passing it through to the pod", func() {
			podIP := net.ParseIP("10.0.0.5")
			serverIP := net.ParseIP("93.184.216.34")
			const natPort uint16 = 40000

			p.addTargetCIDR(serverIP)
			p.addDstKindPodIP(podIP)
			p.addPodNatPorts(podIP, 40000, 40099)

			in := buildTCP(serverIP, podIP, 80, natPort, tcpACK)
			out := make([]byte, len(in))
			ret, err := p.revnat.RevnatXdp.Run(&ebpf.RunOptions{Data: in, DataOut: out})
			Expect(err).NotTo(HaveOccurred())
			Expect(ret).To(Equal(xdpDrop), "a nat_map miss on a port the pod's own NAT block owns is never a real reply")
		})
	})

	Context("dst_kind is POD_IP but nat_map misses, dst port outside the pod's own NAT block", func() {
		It("passes the packet through, leaving it to whatever else legitimately delivers to that port", func() {
			podIP := net.ParseIP("10.0.0.5")
			serverIP := net.ParseIP("93.184.216.34")
			const servicePort uint16 = 8080

			p.addTargetCIDR(serverIP)
			p.addDstKindPodIP(podIP)
			p.addPodNatPorts(podIP, 40000, 40099) // pod's own NAT block -- doesn't cover servicePort

			in := buildTCP(serverIP, podIP, 80, servicePort, tcpACK)
			out := make([]byte, len(in))
			ret, err := p.revnat.RevnatXdp.Run(&ebpf.RunOptions{Data: in, DataOut: out})
			Expect(err).NotTo(HaveOccurred())
			Expect(ret).To(Equal(xdpPass), "a port mooring doesn't manage for this pod is not mooring's concern")
			Expect(out).To(Equal(in), "packet should be unmodified")
		})
	})

	Context("stage1: dst is a known external IP with an active allocation", func() {
		It("rewrites the destination IP and port in one pass", func() {
			podIP := net.ParseIP("10.0.0.6")
			serverIP := net.ParseIP("93.184.216.35")
			extIP := net.ParseIP("203.0.113.10")
			const podPort, serverPort, natPort uint16 = 53422, 80, 40001

			p.addTargetCIDR(serverIP)
			p.addDstKindExtIP(extIP)
			addPortRangeLookup(p.revnat.PortRangeLookupTcp, extIP, natPort, podIP)

			revnatVal := bpf.SnatEgressNatMapVal{NatIp: beU32(extIP), Port: beU16(podPort)}
			Expect(p.snat.NatMap.Put(natMapKey(serverIP, podIP, serverPort, natPort, protoTCP, natEntryREVNAT), revnatVal)).
				To(Succeed(), "seed revnat entry")

			in := buildTCP(serverIP, extIP, serverPort, natPort, tcpACK)
			out := make([]byte, len(in))
			ret, err := p.revnat.RevnatXdp.Run(&ebpf.RunOptions{Data: in, DataOut: out})
			Expect(err).NotTo(HaveOccurred())
			Expect(ret).To(Equal(xdpPass))

			ipHdr, l4 := parseEthIPv4(out)
			Expect(net.IP(ipHdr[16:20])).To(Equal(podIP.To4()), "dst IP should be rewritten ext_ip -> pod_ip")
			Expect(binary.BigEndian.Uint16(l4[2:4])).To(Equal(podPort), "dst port should be rewritten nat_port -> pod_port")
			Expect(pseudoHeaderChecksum(serverIP, podIP, protoTCP, l4)).To(BeZero(), "TCP checksum invalid after rewrite")
		})
	})

	Context("stage1: resolved pod is not local to this node", func() {
		It("does not silently pass the packet through unmodified", func() {
			podIP := net.ParseIP("10.0.0.7")
			serverIP := net.ParseIP("93.184.216.36")
			extIP := net.ParseIP("203.0.113.11")
			const serverPort, natPort uint16 = 80, 40002

			p.addTargetCIDR(serverIP)
			p.addDstKindExtIP(extIP)
			addPortRangeLookup(p.revnat.PortRangeLookupTcp, extIP, natPort, podIP)

			in := buildTCP(serverIP, extIP, serverPort, natPort, tcpACK)
			out := make([]byte, len(in))
			ret, err := p.revnat.RevnatXdp.Run(&ebpf.RunOptions{Data: in, DataOut: out})
			Expect(err).NotTo(HaveOccurred())

			// bpf_fib_lookup resolves against the real host FIB here, not a
			// synthetic one, so whether this ends in XDP_REDIRECT or XDP_DROP
			// depends on the test machine's routing table -- the only
			// deterministic assertion is that it's not XDP_PASS.
			Expect(ret).NotTo(Equal(xdpPass), "a stage1 nat_map miss must attempt the fib-based redirect, not fall through to a plain pass")
		})
	})

	Context("bare TCP SYN (no ACK) on ingress", func() {
		It("is dropped instead of being passed through to a pod", func() {
			podIP := net.ParseIP("10.0.0.51")
			serverIP := net.ParseIP("93.184.216.51")

			p.addTargetCIDR(serverIP)
			p.addDstKindPodIP(podIP)

			in := buildTCP(serverIP, podIP, 80, 40000, tcpSYN)
			out := make([]byte, len(in))
			ret, err := p.revnat.RevnatXdp.Run(&ebpf.RunOptions{Data: in, DataOut: out})
			Expect(err).NotTo(HaveOccurred())
			Expect(ret).To(Equal(xdpDrop), "a bare SYN is never a legitimate reply and must be dropped")
		})
	})
})
