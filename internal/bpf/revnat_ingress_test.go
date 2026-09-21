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

var _ = Describe("revnat_ingress", func() {
	var p *testPrograms

	BeforeEach(func() {
		p = newTestPrograms()
	})

	AfterEach(func() {
		p.Close()
	})

	// The "stage2 direct" path: dst is already pod_ip (stage 1 having run on
	// another node), so ext_ip_pool is deliberately left empty and
	// revnat_ingress calls do_port_revnat directly. Full stage1
	// (ext_ip_pool + port_range_lookup_*) and the "not local" bpf_redirect_neigh
	// branch are not yet covered by this scaffold.
	Context("known local connection", func() {
		It("rewrites the destination port back to the pod port", func() {
			podIP := net.ParseIP("10.0.0.5")
			serverIP := net.ParseIP("93.184.216.34")
			extIP := net.ParseIP("203.0.113.9")
			const podPort, serverPort, natPort uint16 = 53421, 80, 40000

			// revnat_ingress checks the packet's *source* against
			// target_cidrs — the server is the peer that must be a
			// recognized NAT target.
			p.addTargetCIDR(serverIP)

			// Seed the revnat entry snat_egress would have written for this
			// connection.
			revnatVal := bpf.SnatEgressNatMapVal{NatIp: beU32(extIP), Port: beU16(podPort)}
			Expect(p.snat.NatMap.Put(natMapKey(serverIP, podIP, serverPort, natPort, protoTCP, natEntryREVNAT), revnatVal)).
				To(Succeed(), "seed revnat entry")

			in := buildTCP(serverIP, podIP, serverPort, natPort, tcpACK)
			out := make([]byte, len(in))
			ret, err := p.revnat.RevnatIngress.Run(&ebpf.RunOptions{Data: in, DataOut: out})
			Expect(err).NotTo(HaveOccurred())
			Expect(ret).To(Equal(tcxNext))

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
			ret, err := p.revnat.RevnatIngress.Run(&ebpf.RunOptions{Data: in, DataOut: out})
			Expect(err).NotTo(HaveOccurred())
			Expect(ret).To(Equal(tcxNext))
			Expect(out).To(Equal(in), "packet was modified despite no target_cidrs match")
		})
	})
})
