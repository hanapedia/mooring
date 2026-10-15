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

	Context("known local connection", func() {
		It("rewrites the destination port back to the pod port", func() {
			podIP := net.ParseIP("10.0.0.5")
			serverIP := net.ParseIP("93.184.216.34")
			extIP := net.ParseIP("203.0.113.9")
			const podPort, serverPort, natPort uint16 = 53421, 80, 40000

			p.addTargetCIDR(serverIP)
			p.addDstKindPodIP(podIP)

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
		It("passes the packet through unmodified even when dst matches dst_kind", func() {
			podIP := net.ParseIP("10.0.0.5")
			serverIP := net.ParseIP("93.184.216.34") // never added to target_cidrs

			p.addDstKindPodIP(podIP)

			in := buildTCP(serverIP, podIP, 80, 40000, tcpACK)
			out := make([]byte, len(in))
			ret, err := p.revnat.RevnatIngress.Run(&ebpf.RunOptions{Data: in, DataOut: out})
			Expect(err).NotTo(HaveOccurred())
			Expect(ret).To(Equal(tcxNext))
			Expect(out).To(Equal(in), "packet was modified despite no target_cidrs match")
		})
	})

	Context("dst is not a known mooring IP at all", func() {
		It("passes the packet through unmodified, without touching nat_map", func() {
			unrelatedPodIP := net.ParseIP("10.0.0.99") // never added to dst_kind
			serverIP := net.ParseIP("93.184.216.34")

			p.addTargetCIDR(serverIP)

			in := buildTCP(serverIP, unrelatedPodIP, 80, 40000, tcpACK)
			out := make([]byte, len(in))
			ret, err := p.revnat.RevnatIngress.Run(&ebpf.RunOptions{Data: in, DataOut: out})
			Expect(err).NotTo(HaveOccurred())
			Expect(ret).To(Equal(tcxNext), "should pass through, not redirect")
			Expect(out).To(Equal(in), "packet was modified despite no dst_kind match")
		})
	})

	Context("dst_kind is POD_IP but nat_map misses", func() {
		It("passes the packet through unmodified, not redirected", func() {
			podIP := net.ParseIP("10.0.0.5")
			serverIP := net.ParseIP("93.184.216.34")

			p.addTargetCIDR(serverIP)
			p.addDstKindPodIP(podIP)

			in := buildTCP(serverIP, podIP, 80, 40000, tcpACK)
			out := make([]byte, len(in))
			ret, err := p.revnat.RevnatIngress.Run(&ebpf.RunOptions{Data: in, DataOut: out})
			Expect(err).NotTo(HaveOccurred())
			Expect(ret).To(Equal(tcxNext), "should pass through, not redirect")
			Expect(out).To(Equal(in), "packet should be unmodified on a nat_map miss")
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
			ret, err := p.revnat.RevnatIngress.Run(&ebpf.RunOptions{Data: in, DataOut: out})
			Expect(err).NotTo(HaveOccurred())
			Expect(ret).To(Equal(tcxNext))

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
			ret, err := p.revnat.RevnatIngress.Run(&ebpf.RunOptions{Data: in, DataOut: out})
			Expect(err).NotTo(HaveOccurred())

			// bpf_redirect_neigh has no real neighbor to resolve here, so this
			// can only assert the redirect was attempted, not that it succeeded.
			Expect(ret).NotTo(Equal(tcxNext), "a stage1 nat_map miss must not fall through to a plain pass")
			ipHdr, _ := parseEthIPv4(out)
			Expect(net.IP(ipHdr[16:20])).To(Equal(podIP.To4()), "dst IP should have been rewritten ext_ip -> pod_ip before the redirect attempt")
		})
	})

	Context("TCP connection close tracking", func() {
		It("marks both entries closing on the first FIN+ACK, then reclaims them on the second", func() {
			podIP := net.ParseIP("10.0.0.8")
			serverIP := net.ParseIP("93.184.216.37")
			extIP := net.ParseIP("203.0.113.12")
			const podPort, serverPort, natPort uint16 = 53423, 80, 40003

			p.addTargetCIDR(serverIP)
			p.addDstKindPodIP(podIP)

			snatKey := natMapKey(podIP, serverIP, podPort, serverPort, protoTCP, natEntrySNAT)
			revnatKey := natMapKey(serverIP, podIP, serverPort, natPort, protoTCP, natEntryREVNAT)

			Expect(p.snat.NatMap.Put(snatKey, bpf.SnatEgressNatMapVal{NatIp: beU32(extIP), Port: beU16(natPort)})).
				To(Succeed(), "seed snat entry")
			Expect(p.snat.NatMap.Put(revnatKey, bpf.SnatEgressNatMapVal{NatIp: beU32(extIP), Port: beU16(podPort)})).
				To(Succeed(), "seed revnat entry")

			run := func(flags uint8) []byte {
				in := buildTCP(serverIP, podIP, serverPort, natPort, flags)
				out := make([]byte, len(in))
				ret, err := p.revnat.RevnatIngress.Run(&ebpf.RunOptions{Data: in, DataOut: out})
				Expect(err).NotTo(HaveOccurred())
				Expect(ret).To(Equal(tcxNext))
				return out
			}

			out := run(tcpFIN | tcpACK)
			_, l4 := parseEthIPv4(out)
			Expect(binary.BigEndian.Uint16(l4[2:4])).To(Equal(podPort), "dst port on the marking packet")

			var revnatVal bpf.SnatEgressNatMapVal
			Expect(p.snat.NatMap.Lookup(revnatKey, &revnatVal)).To(Succeed(), "revnat entry missing after first FIN")
			Expect(revnatVal.ClosingNs).NotTo(BeZero(), "revnat entry not marked closing after first FIN")

			var snatVal bpf.SnatEgressNatMapVal
			Expect(p.snat.NatMap.Lookup(snatKey, &snatVal)).To(Succeed(), "snat entry missing after first FIN")
			Expect(snatVal.ClosingNs).NotTo(BeZero(), "snat entry not marked closing after first FIN")

			out = run(tcpFIN | tcpACK)
			_, l4 = parseEthIPv4(out)
			Expect(binary.BigEndian.Uint16(l4[2:4])).To(Equal(podPort), "dst port on the confirming/deleting packet")

			Expect(p.snat.NatMap.Lookup(revnatKey, &bpf.SnatEgressNatMapVal{})).
				NotTo(Succeed(), "revnat entry still present after confirmed close")
			Expect(p.snat.NatMap.Lookup(snatKey, &bpf.SnatEgressNatMapVal{})).
				NotTo(Succeed(), "snat entry still present after confirmed close")
		})
	})
})
