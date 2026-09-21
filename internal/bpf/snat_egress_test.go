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

var _ = Describe("snat_egress", func() {
	var p *testPrograms

	BeforeEach(func() {
		p = newTestPrograms()
	})

	AfterEach(func() {
		p.Close()
	})

	Context("new TCP connection", func() {
		It("allocates a NAT port/IP and rewrites the packet", func() {
			podIP := net.ParseIP("10.0.0.5")
			serverIP := net.ParseIP("93.184.216.34")
			extIP := net.ParseIP("203.0.113.9")
			const podPort, serverPort, extPort uint16 = 53421, 80, 40000

			p.addTargetCIDR(serverIP)
			p.addSinglePortNatConfig(podIP, serverIP, 32, extIP, extPort)

			in := buildTCP(podIP, serverIP, podPort, serverPort, tcpSYN)
			out := make([]byte, len(in))
			ret, err := p.snat.SnatEgress.Run(&ebpf.RunOptions{Data: in, DataOut: out})
			Expect(err).NotTo(HaveOccurred())
			Expect(ret).To(Equal(tcxNext))

			ipHdr, l4 := parseEthIPv4(out)
			Expect(net.IP(ipHdr[12:16])).To(Equal(extIP.To4()), "rewritten src IP")
			Expect(binary.BigEndian.Uint16(l4[0:2])).To(Equal(extPort), "rewritten src port")
			Expect(ipChecksum(ipHdr)).To(BeZero(), "IP checksum invalid after rewrite")
			Expect(pseudoHeaderChecksum(extIP, serverIP, protoTCP, l4)).To(BeZero(), "TCP checksum invalid after rewrite")

			var snatVal bpf.SnatEgressNatMapVal
			Expect(p.snat.NatMap.Lookup(natMapKey(podIP, serverIP, podPort, serverPort, protoTCP, natEntrySNAT), &snatVal)).
				To(Succeed(), "snat entry not recorded")
			Expect(snatVal.NatIp).To(Equal(beU32(extIP)))
			Expect(snatVal.Port).To(Equal(beU16(extPort)))

			var revnatVal bpf.SnatEgressNatMapVal
			Expect(p.snat.NatMap.Lookup(natMapKey(serverIP, podIP, serverPort, extPort, protoTCP, natEntryREVNAT), &revnatVal)).
				To(Succeed(), "revnat entry not recorded")
			Expect(revnatVal.NatIp).To(Equal(beU32(extIP)))
			Expect(revnatVal.Port).To(Equal(beU16(podPort)))
		})
	})

	Context("existing connection", func() {
		It("reuses the prior allocation instead of re-running the allocator", func() {
			podIP := net.ParseIP("10.0.0.5")
			serverIP := net.ParseIP("93.184.216.34")
			extIP := net.ParseIP("203.0.113.9")
			const podPort, serverPort, extPort uint16 = 53421, 80, 40000

			p.addTargetCIDR(serverIP)
			p.addSinglePortNatConfig(podIP, serverIP, 32, extIP, extPort)

			syn := buildTCP(podIP, serverIP, podPort, serverPort, tcpSYN)
			_, err := p.snat.SnatEgress.Run(&ebpf.RunOptions{Data: syn, DataOut: make([]byte, len(syn))})
			Expect(err).NotTo(HaveOccurred())

			// A later data packet on the same 4-tuple must reuse the same
			// allocation via the sv-found branch, not re-run the allocator.
			data := buildTCP(podIP, serverIP, podPort, serverPort, tcpACK)
			out := make([]byte, len(data))
			_, err = p.snat.SnatEgress.Run(&ebpf.RunOptions{Data: data, DataOut: out})
			Expect(err).NotTo(HaveOccurred())

			ipHdr, l4 := parseEthIPv4(out)
			Expect(net.IP(ipHdr[12:16])).To(Equal(extIP.To4()), "reused src IP")
			Expect(binary.BigEndian.Uint16(l4[0:2])).To(Equal(extPort), "reused src port")
		})
	})

	Context("no target_cidrs match", func() {
		It("passes the packet through unmodified", func() {
			podIP := net.ParseIP("10.0.0.5")
			serverIP := net.ParseIP("93.184.216.34") // never added to target_cidrs

			in := buildTCP(podIP, serverIP, 53421, 80, tcpSYN)
			out := make([]byte, len(in))
			ret, err := p.snat.SnatEgress.Run(&ebpf.RunOptions{Data: in, DataOut: out})
			Expect(err).NotTo(HaveOccurred())
			Expect(ret).To(Equal(tcxNext))
			Expect(out).To(Equal(in), "packet was modified despite no target_cidrs match")
		})
	})

	Context("no nat_config for the pod", func() {
		It("passes the packet through unmodified", func() {
			podIP := net.ParseIP("10.0.0.5")
			serverIP := net.ParseIP("93.184.216.34")
			p.addTargetCIDR(serverIP) // matches, but no nat_config seeded

			in := buildTCP(podIP, serverIP, 53421, 80, tcpSYN)
			out := make([]byte, len(in))
			ret, err := p.snat.SnatEgress.Run(&ebpf.RunOptions{Data: in, DataOut: out})
			Expect(err).NotTo(HaveOccurred())
			Expect(ret).To(Equal(tcxNext))
			Expect(out).To(Equal(in), "packet was modified despite missing nat_config")
		})
	})

	Context("UDP and ICMP", func() {
		var podIP, serverIP, extIP net.IP
		const extPort uint16 = 40000

		BeforeEach(func() {
			podIP = net.ParseIP("10.0.0.5")
			serverIP = net.ParseIP("93.184.216.34")
			extIP = net.ParseIP("203.0.113.9")
			p.addTargetCIDR(serverIP)
			p.addSinglePortNatConfig(podIP, serverIP, 32, extIP, extPort)
		})

		It("rewrites UDP packets using the same nat_config", func() {
			in := buildUDP(podIP, serverIP, 53421, 53)
			out := make([]byte, len(in))
			_, err := p.snat.SnatEgress.Run(&ebpf.RunOptions{Data: in, DataOut: out})
			Expect(err).NotTo(HaveOccurred())

			ipHdr, l4 := parseEthIPv4(out)
			Expect(net.IP(ipHdr[12:16])).To(Equal(extIP.To4()))
			Expect(binary.BigEndian.Uint16(l4[0:2])).To(Equal(extPort))
			Expect(pseudoHeaderChecksum(extIP, serverIP, protoUDP, l4)).To(BeZero(), "UDP checksum invalid after rewrite")
		})

		It("rewrites ICMP echo packets using the same nat_config", func() {
			const echoID uint16 = 1234
			in := buildICMPEcho(podIP, serverIP, 8 /* ICMP_ECHO */, echoID, 1)
			out := make([]byte, len(in))
			_, err := p.snat.SnatEgress.Run(&ebpf.RunOptions{Data: in, DataOut: out})
			Expect(err).NotTo(HaveOccurred())

			ipHdr, l4 := parseEthIPv4(out)
			Expect(net.IP(ipHdr[12:16])).To(Equal(extIP.To4()))
			Expect(binary.BigEndian.Uint16(l4[4:6])).To(Equal(extPort), "echo id")
			Expect(ipChecksum(l4)).To(BeZero(), "ICMP checksum invalid after rewrite")
		})
	})

	Context("TCP connection close tracking", func() {
		It("marks both entries closing on the first FIN+ACK, then reclaims them on the second", func() {
			podIP := net.ParseIP("10.0.0.5")
			serverIP := net.ParseIP("93.184.216.34")
			extIP := net.ParseIP("203.0.113.9")
			const podPort, serverPort, extPort uint16 = 53421, 80, 40000

			p.addTargetCIDR(serverIP)
			p.addSinglePortNatConfig(podIP, serverIP, 32, extIP, extPort)

			run := func(flags uint8) {
				pkt := buildTCP(podIP, serverIP, podPort, serverPort, flags)
				_, err := p.snat.SnatEgress.Run(&ebpf.RunOptions{Data: pkt, DataOut: make([]byte, len(pkt))})
				Expect(err).NotTo(HaveOccurred())
			}

			snatKey := natMapKey(podIP, serverIP, podPort, serverPort, protoTCP, natEntrySNAT)
			revnatKey := natMapKey(serverIP, podIP, serverPort, extPort, protoTCP, natEntryREVNAT)

			run(tcpSYN)

			// First FIN+ACK marks both entries as closing without deleting
			// them — covers the half-closed case (see snat_egress.c's
			// try_alloc_port doc).
			run(tcpFIN | tcpACK)

			var snatVal bpf.SnatEgressNatMapVal
			Expect(p.snat.NatMap.Lookup(snatKey, &snatVal)).To(Succeed(), "snat entry missing after first FIN")
			Expect(snatVal.ClosingNs).NotTo(BeZero(), "snat entry not marked closing after first FIN")

			var revnatVal bpf.SnatEgressNatMapVal
			Expect(p.snat.NatMap.Lookup(revnatKey, &revnatVal)).To(Succeed(), "revnat entry missing after first FIN")
			Expect(revnatVal.ClosingNs).NotTo(BeZero(), "revnat entry not marked closing after first FIN")

			// A second FIN+ACK confirms the close and reclaims both entries.
			run(tcpFIN | tcpACK)

			Expect(p.snat.NatMap.Lookup(snatKey, &bpf.SnatEgressNatMapVal{})).
				NotTo(Succeed(), "snat entry still present after confirmed close")
			Expect(p.snat.NatMap.Lookup(revnatKey, &bpf.SnatEgressNatMapVal{})).
				NotTo(Succeed(), "revnat entry still present after confirmed close")
		})
	})
})
