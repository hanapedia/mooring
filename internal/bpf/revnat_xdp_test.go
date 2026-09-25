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

var _ = Describe("revnat_xdp", func() {
	var p *testProgramsXDP

	BeforeEach(func() {
		p = newTestProgramsXDP()
	})

	AfterEach(func() {
		p.Close()
	})

	// Same "stage2 direct" scenario as revnat_ingress_test.go's "known local
	// connection": dst is already pod_ip (stage 1 having run on another
	// node), so ext_ip_pool is deliberately left empty and revnat_core calls
	// do_port_revnat directly. This is the part of stage2 that stays on the
	// same node -- it does not exercise ctx_redirect_transit's
	// bpf_fib_lookup-based path (the "not local" branch), which needs a real
	// routable neighbor to test meaningfully rather than BPF_PROG_TEST_RUN's
	// synthetic context.
	Context("known local connection", func() {
		It("rewrites the destination port back to the pod port", func() {
			podIP := net.ParseIP("10.0.0.5")
			serverIP := net.ParseIP("93.184.216.34")
			extIP := net.ParseIP("203.0.113.9")
			const podPort, serverPort, natPort uint16 = 53421, 80, 40000

			p.addTargetCIDR(serverIP)

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
		It("passes the packet through unmodified", func() {
			podIP := net.ParseIP("10.0.0.5")
			serverIP := net.ParseIP("93.184.216.34") // never added to target_cidrs

			in := buildTCP(serverIP, podIP, 80, 40000, tcpACK)
			out := make([]byte, len(in))
			ret, err := p.revnat.RevnatXdp.Run(&ebpf.RunOptions{Data: in, DataOut: out})
			Expect(err).NotTo(HaveOccurred())
			Expect(ret).To(Equal(xdpPass))
			Expect(out).To(Equal(in), "packet was modified despite no target_cidrs match")
		})
	})
})
