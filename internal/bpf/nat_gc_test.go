//go:build bpftest

package bpf_test

import (
	"net"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/cilium/ebpf"
	"github.com/hanapedia/mooring/internal/bpf"
	"golang.org/x/sys/unix"
)

// ktimeNowNs approximates bpf_ktime_get_ns() from userspace: that helper
// resolves to the kernel's ktime_get_ns(), i.e. CLOCK_MONOTONIC.
func ktimeNowNs() uint64 {
	var ts unix.Timespec
	ExpectWithOffset(1, unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)).To(Succeed())
	return uint64(ts.Sec)*1e9 + uint64(ts.Nsec)
}

// gcStats mirrors bpf/nat_gc.c's struct gc_ctx field-for-field, the same way
// internal/gc.Stats does -- defined locally rather than importing
// internal/gc, since these tests drive the GC programs directly via
// Program.Run (unpinned), the same way every other file in this package
// drives its own program under test.
type gcStats struct {
	Scanned, Deleted, Remaining uint64
}

// testProgramsGC loads nat_gc.c sharing nat_map_tcp/nat_map_any with a
// freshly loaded snat_egress, exactly as internal/loader.loadNatGc wires
// them in production -- minus the Pin() calls, same reasoning as
// testPrograms/testProgramsXDP (bpftest_suite_test.go).
type testProgramsGC struct {
	snat *bpf.SnatEgressObjects
	gc   *bpf.NatGcObjects
}

func newTestProgramsGC() *testProgramsGC {
	snat := &bpf.SnatEgressObjects{}
	ExpectWithOffset(1, bpf.LoadSnatEgressObjects(snat, nil)).
		To(Succeed(), "load snat_egress objects (run as root with CAP_BPF, e.g. `task test-bpf`)")

	gcSpec, err := bpf.LoadNatGc()
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "load nat_gc spec")

	gc := &bpf.NatGcObjects{}
	ExpectWithOffset(1, gcSpec.LoadAndAssign(gc, &ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{
			"nat_map_tcp":  snat.NatMapTcp,
			"nat_map_any":  snat.NatMapAny,
			"target_cidrs": snat.TargetCidrs,
		},
	})).To(Succeed(), "load nat_gc objects")

	return &testProgramsGC{snat: snat, gc: gc}
}

func (p *testProgramsGC) Close() {
	ExpectWithOffset(1, p.gc.Close()).To(Succeed())
	ExpectWithOffset(1, p.snat.Close()).To(Succeed())
}

func (p *testProgramsGC) runTCP() gcStats {
	var stats gcStats
	_, err := p.gc.GcNatMapTcp.Run(&ebpf.RunOptions{Context: stats, ContextOut: &stats})
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "run gc_nat_map_tcp")
	return stats
}

func (p *testProgramsGC) runAny() gcStats {
	var stats gcStats
	_, err := p.gc.GcNatMapAny.Run(&ebpf.RunOptions{Context: stats, ContextOut: &stats})
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "run gc_nat_map_any")
	return stats
}

var _ = Describe("nat_gc", func() {
	var p *testProgramsGC

	BeforeEach(func() {
		p = newTestProgramsGC()
	})

	AfterEach(func() {
		p.Close()
	})

	Context("nat_map_tcp", func() {
		var (
			podIP, serverIP, extIP       net.IP
			podPort, serverPort, extPort uint16
			snatKey, revnatKey           bpf.SnatEgressNatMapKey
		)

		BeforeEach(func() {
			podIP = net.ParseIP("10.0.0.5")
			serverIP = net.ParseIP("93.184.216.34")
			extIP = net.ParseIP("203.0.113.9")
			podPort, serverPort, extPort = 53421, 80, 40000
			snatKey = natMapKey(podIP, serverIP, podPort, serverPort, protoTCP, natEntrySNAT)
			revnatKey = natMapKey(serverIP, podIP, serverPort, extPort, protoTCP, natEntryREVNAT)
		})

		It("deletes a TCP entry and its peer once closing_ns is stale", func() {
			Expect(p.snat.NatMapTcp.Put(snatKey, bpf.SnatEgressNatMapVal{
				NatIp: beU32(extIP), Port: beU16(extPort), ClosingNs: closingNsLongAgo,
			})).To(Succeed(), "seed snat entry")
			Expect(p.snat.NatMapTcp.Put(revnatKey, bpf.SnatEgressNatMapVal{
				NatIp: beU32(extIP), Port: beU16(podPort), ClosingNs: closingNsLongAgo,
			})).To(Succeed(), "seed revnat entry")

			stats := p.runTCP()
			Expect(stats.Deleted).To(BeNumerically(">=", 1), "at least the first-visited side should report a deletion")

			Expect(p.snat.NatMapTcp.Lookup(snatKey, &bpf.SnatEgressNatMapVal{})).
				To(MatchError(ebpf.ErrKeyNotExist), "snat entry should be gone")
			Expect(p.snat.NatMapTcp.Lookup(revnatKey, &bpf.SnatEgressNatMapVal{})).
				To(MatchError(ebpf.ErrKeyNotExist), "peer revnat entry should be gone too, even though GC never visited it directly")
		})

		It("leaves a fresh (not closing) TCP entry alone", func() {
			Expect(p.snat.NatMapTcp.Put(snatKey, bpf.SnatEgressNatMapVal{
				NatIp: beU32(extIP), Port: beU16(extPort), ClosingNs: 0,
			})).To(Succeed(), "seed snat entry")

			stats := p.runTCP()
			Expect(stats.Deleted).To(BeZero())
			Expect(stats.Remaining).To(BeNumerically(">=", 1))

			var val bpf.SnatEgressNatMapVal
			Expect(p.snat.NatMapTcp.Lookup(snatKey, &val)).To(Succeed(), "fresh entry must survive the sweep")
		})

		It("leaves a closing-but-not-yet-stale TCP entry alone", func() {
			// closing_ns set to "now" -- well under NAT_CLOSING_STALE_NS
			// (10s) old -- same role as nat_map_track_tcp_close setting
			// closing_ns on a real FIN, just without driving a packet.
			Expect(p.snat.NatMapTcp.Put(snatKey, bpf.SnatEgressNatMapVal{
				NatIp: beU32(extIP), Port: beU16(extPort), ClosingNs: ktimeNowNs(),
			})).To(Succeed(), "seed snat entry")

			stats := p.runTCP()
			Expect(stats.Deleted).To(BeZero(), "a recently-marked entry must not be reclaimed yet")

			Expect(p.snat.NatMapTcp.Lookup(snatKey, &bpf.SnatEgressNatMapVal{})).To(Succeed(), "entry not yet stale must survive")
		})
	})

	Context("nat_map_any", func() {
		var (
			podIP, serverIP, extIP       net.IP
			podPort, serverPort, extPort uint16
			key                          bpf.SnatEgressNatMapKey
		)

		BeforeEach(func() {
			podIP = net.ParseIP("10.0.0.6")
			serverIP = net.ParseIP("93.184.216.35")
			extIP = net.ParseIP("203.0.113.10")
			podPort, serverPort, extPort = 53422, 53, 40001
			key = natMapKey(podIP, serverIP, podPort, serverPort, protoUDP, natEntrySNAT)
		})

		It("marks a fresh entry on the first sweep, then deletes it on the second if still untouched", func() {
			Expect(p.snat.NatMapAny.Put(key, bpf.SnatEgressNatMapVal{
				NatIp: beU32(extIP), Port: beU16(extPort), ClosingNs: 0,
			})).To(Succeed(), "seed udp entry")

			first := p.runAny()
			Expect(first.Deleted).To(BeZero(), "a fresh entry must survive its first sweep")

			var val bpf.SnatEgressNatMapVal
			Expect(p.snat.NatMapAny.Lookup(key, &val)).To(Succeed(), "entry must still exist after being marked")
			Expect(val.ClosingNs).NotTo(BeZero(), "entry should now be marked (closing_ns set to the sweep's own 'now')")

			second := p.runAny()
			Expect(second.Deleted).To(BeNumerically(">=", 1), "an entry still marked on the next sweep must be deleted")
			Expect(p.snat.NatMapAny.Lookup(key, &bpf.SnatEgressNatMapVal{})).
				To(MatchError(ebpf.ErrKeyNotExist), "entry should be gone after the second sweep")
		})

		It("survives indefinitely if touched (closing_ns cleared) between sweeps", func() {
			Expect(p.snat.NatMapAny.Put(key, bpf.SnatEgressNatMapVal{
				NatIp: beU32(extIP), Port: beU16(extPort), ClosingNs: 0,
			})).To(Succeed(), "seed udp entry")

			p.runAny() // marks it

			// Datapath touch: snat_egress.c's reuse branch / revnat_core.h's
			// do_port_revnat clear closing_ns back to 0 on a hit -- simulated
			// here directly rather than driving a packet, since this test is
			// about the GC program's own mark/sweep logic, not the datapath
			// integration (covered separately by snat_egress_test.go /
			// revnat_ingress_test.go once they exercise UDP/ICMP).
			Expect(p.snat.NatMapAny.Put(key, bpf.SnatEgressNatMapVal{
				NatIp: beU32(extIP), Port: beU16(extPort), ClosingNs: 0,
			})).To(Succeed(), "simulate datapath touch clearing the mark")

			second := p.runAny()
			Expect(second.Deleted).To(BeZero(), "a touched entry must survive the sweep that would otherwise delete it")
			Expect(p.snat.NatMapAny.Lookup(key, &bpf.SnatEgressNatMapVal{})).To(Succeed())
		})
	})
})
