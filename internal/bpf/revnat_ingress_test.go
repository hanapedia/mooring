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
			p.addPodNatPorts(podIP, natPort, natPort)

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
			ret, err := p.revnat.RevnatIngress.Run(&ebpf.RunOptions{Data: in, DataOut: out})
			Expect(err).NotTo(HaveOccurred())
			Expect(ret).To(Equal(tcDrop), "a nat_map miss on a port the pod's own NAT block owns is never a real reply")
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
			ret, err := p.revnat.RevnatIngress.Run(&ebpf.RunOptions{Data: in, DataOut: out})
			Expect(err).NotTo(HaveOccurred())
			Expect(ret).To(Equal(tcxNext), "a port mooring doesn't manage for this pod is not mooring's concern")
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
		It("requires a FIN from each direction before reclaiming, not just a second terminating segment from one side", func() {
			podIP := net.ParseIP("10.0.0.8")
			serverIP := net.ParseIP("93.184.216.37")
			extIP := net.ParseIP("203.0.113.12")
			const podPort, serverPort, natPort uint16 = 53423, 80, 40003

			p.addTargetCIDR(serverIP)
			p.addDstKindPodIP(podIP)
			p.addPodNatPorts(podIP, natPort, natPort)

			snatKey := natMapKey(podIP, serverIP, podPort, serverPort, protoTCP, natEntrySNAT)
			revnatKey := natMapKey(serverIP, podIP, serverPort, natPort, protoTCP, natEntryREVNAT)

			Expect(p.snat.NatMap.Put(snatKey, bpf.SnatEgressNatMapVal{NatIp: beU32(extIP), Port: beU16(natPort)})).
				To(Succeed(), "seed snat entry")
			Expect(p.snat.NatMap.Put(revnatKey, bpf.SnatEgressNatMapVal{NatIp: beU32(extIP), Port: beU16(podPort)})).
				To(Succeed(), "seed revnat entry")

			runIngress := func(flags uint8) []byte {
				in := buildTCP(serverIP, podIP, serverPort, natPort, flags)
				out := make([]byte, len(in))
				ret, err := p.revnat.RevnatIngress.Run(&ebpf.RunOptions{Data: in, DataOut: out})
				Expect(err).NotTo(HaveOccurred())
				Expect(ret).To(Equal(tcxNext))
				return out
			}

			// First FIN from the server side marks only the revnat entry --
			// closing_ns is never mirrored onto the peer (snat) entry.
			out := runIngress(tcpFIN | tcpACK)
			_, l4 := parseEthIPv4(out)
			Expect(binary.BigEndian.Uint16(l4[2:4])).To(Equal(podPort), "dst port on the marking packet")

			var revnatVal bpf.SnatEgressNatMapVal
			Expect(p.snat.NatMap.Lookup(revnatKey, &revnatVal)).To(Succeed(), "revnat entry missing after first FIN")
			Expect(revnatVal.ClosingNs).NotTo(BeZero(), "revnat entry not marked closing after first FIN")

			var snatVal bpf.SnatEgressNatMapVal
			Expect(p.snat.NatMap.Lookup(snatKey, &snatVal)).To(Succeed(), "snat entry missing after first FIN")
			Expect(snatVal.ClosingNs).To(BeZero(), "closing_ns must not be mirrored onto the peer entry")

			// A second FIN from the SAME direction (e.g. a retransmit) must
			// NOT delete anything -- only a FIN from the pod's own side can
			// confirm the close.
			runIngress(tcpFIN | tcpACK)

			Expect(p.snat.NatMap.Lookup(revnatKey, &bpf.SnatEgressNatMapVal{})).
				To(Succeed(), "revnat entry deleted by a second same-direction FIN -- should require both directions")
			Expect(p.snat.NatMap.Lookup(snatKey, &bpf.SnatEgressNatMapVal{})).
				To(Succeed(), "snat entry deleted by a second same-direction FIN -- should require both directions")

			// Now the pod's own side sends a FIN too, via snat_egress
			// reusing the already-seeded snat entry. A FIN observed from
			// both directions confirms a clean close, so both entries are
			// deleted immediately.
			podFIN := buildTCP(podIP, serverIP, podPort, serverPort, tcpFIN|tcpACK)
			_, err := p.snat.SnatEgress.Run(&ebpf.RunOptions{Data: podFIN, DataOut: make([]byte, len(podFIN))})
			Expect(err).NotTo(HaveOccurred())

			Expect(p.snat.NatMap.Lookup(revnatKey, &bpf.SnatEgressNatMapVal{})).
				NotTo(Succeed(), "revnat entry still present after a FIN from both directions")
			Expect(p.snat.NatMap.Lookup(snatKey, &bpf.SnatEgressNatMapVal{})).
				NotTo(Succeed(), "snat entry still present after a FIN from both directions")
		})

		It("clears the closing mark as soon as the same (marked) side sends ordinary traffic again", func() {
			podIP := net.ParseIP("10.0.0.9")
			serverIP := net.ParseIP("93.184.216.38")
			extIP := net.ParseIP("203.0.113.13")
			const podPort, serverPort, natPort uint16 = 53424, 80, 40004

			p.addTargetCIDR(serverIP)
			p.addDstKindPodIP(podIP)
			p.addPodNatPorts(podIP, natPort, natPort)

			snatKey := natMapKey(podIP, serverIP, podPort, serverPort, protoTCP, natEntrySNAT)
			revnatKey := natMapKey(serverIP, podIP, serverPort, natPort, protoTCP, natEntryREVNAT)

			Expect(p.snat.NatMap.Put(snatKey, bpf.SnatEgressNatMapVal{NatIp: beU32(extIP), Port: beU16(natPort)})).
				To(Succeed(), "seed snat entry")
			Expect(p.snat.NatMap.Put(revnatKey, bpf.SnatEgressNatMapVal{NatIp: beU32(extIP), Port: beU16(podPort)})).
				To(Succeed(), "seed revnat entry")

			// An RST from the server side marks the revnat entry closing.
			// The paired snat entry is untouched -- closing_ns is never
			// mirrored onto the peer, only ever set from traffic in that
			// entry's own direction.
			rst := buildTCP(serverIP, podIP, serverPort, natPort, tcpRST)
			_, err := p.revnat.RevnatIngress.Run(&ebpf.RunOptions{Data: rst, DataOut: make([]byte, len(rst))})
			Expect(err).NotTo(HaveOccurred())

			var revnatVal bpf.SnatEgressNatMapVal
			Expect(p.snat.NatMap.Lookup(revnatKey, &revnatVal)).To(Succeed())
			Expect(revnatVal.ClosingNs).NotTo(BeZero(), "entry not marked closing after RST")

			var snatVal bpf.SnatEgressNatMapVal
			Expect(p.snat.NatMap.Lookup(snatKey, &snatVal)).To(Succeed())
			Expect(snatVal.ClosingNs).To(BeZero(), "closing_ns must not be mirrored onto the peer entry")

			// Ordinary (non-FIN/RST) traffic from the SAME (server) side --
			// the one that sent the RST -- is enough to clear its own mark,
			// with no need for the pod side to do anything at all.
			serverData := buildTCP(serverIP, podIP, serverPort, natPort, tcpACK)
			_, err = p.revnat.RevnatIngress.Run(&ebpf.RunOptions{Data: serverData, DataOut: make([]byte, len(serverData))})
			Expect(err).NotTo(HaveOccurred())

			Expect(p.snat.NatMap.Lookup(revnatKey, &revnatVal)).To(Succeed())
			Expect(revnatVal.ClosingNs).To(BeZero(), "closing mark should clear once the marked side resumes ordinary traffic")
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
			ret, err := p.revnat.RevnatIngress.Run(&ebpf.RunOptions{Data: in, DataOut: out})
			Expect(err).NotTo(HaveOccurred())
			Expect(ret).To(Equal(tcDrop), "a bare SYN is never a legitimate reply and must be dropped")
		})
	})

	Context("IP header with options (ihl > 5)", func() {
		It("still parses the real TCP header correctly, past the options", func() {
			podIP := net.ParseIP("10.0.0.52")
			serverIP := net.ParseIP("93.184.216.52")
			extIP := net.ParseIP("203.0.113.52")
			const podPort, serverPort, natPort uint16 = 53425, 80, 40005
			const ihl = 8 // 5 + 3 option words, e.g. mirroring Cilium's DSR "opt" dispatch

			p.addTargetCIDR(serverIP)
			p.addDstKindPodIP(podIP)
			p.addPodNatPorts(podIP, natPort, natPort)

			revnatVal := bpf.SnatEgressNatMapVal{NatIp: beU32(extIP), Port: beU16(podPort)}
			Expect(p.snat.NatMap.Put(natMapKey(serverIP, podIP, serverPort, natPort, protoTCP, natEntryREVNAT), revnatVal)).
				To(Succeed(), "seed revnat entry")

			in := buildTCPWithIHL(serverIP, podIP, serverPort, natPort, tcpACK, ihl, 0)
			out := make([]byte, len(in))
			ret, err := p.revnat.RevnatIngress.Run(&ebpf.RunOptions{Data: in, DataOut: out})
			Expect(err).NotTo(HaveOccurred())
			Expect(ret).To(Equal(tcxNext))

			_, l4 := parseEthIPv4WithIHL(out, ihl)
			Expect(binary.BigEndian.Uint16(l4[2:4])).To(Equal(podPort), "dst port, past the IP options, should be rewritten")
		})
	})

	Context("malformed IP header (ihl < 5)", func() {
		It("is dropped rather than parsed at a bogus offset", func() {
			podIP := net.ParseIP("10.0.0.53")
			serverIP := net.ParseIP("93.184.216.53")

			p.addTargetCIDR(serverIP)
			p.addDstKindPodIP(podIP)

			in := buildTCPWithIHL(serverIP, podIP, 80, 40000, tcpACK, 4, 0)
			out := make([]byte, len(in))
			ret, err := p.revnat.RevnatIngress.Run(&ebpf.RunOptions{Data: in, DataOut: out})
			Expect(err).NotTo(HaveOccurred())
			Expect(ret).To(Equal(tcDrop), "ihl < 5 is not a valid IP header")
		})
	})

	Context("non-first IP fragment", func() {
		It("is dropped rather than its payload bytes read as a port", func() {
			podIP := net.ParseIP("10.0.0.54")
			serverIP := net.ParseIP("93.184.216.54")

			p.addTargetCIDR(serverIP)
			p.addDstKindPodIP(podIP)

			// Non-zero fragment offset: a later fragment of some larger
			// datagram, carrying no L4 header of its own.
			in := buildTCPWithIHL(serverIP, podIP, 80, 40000, tcpACK, 5, 185)
			out := make([]byte, len(in))
			ret, err := p.revnat.RevnatIngress.Run(&ebpf.RunOptions{Data: in, DataOut: out})
			Expect(err).NotTo(HaveOccurred())
			Expect(ret).To(Equal(tcDrop), "a non-first fragment has no real L4 header to parse")
		})
	})
})
