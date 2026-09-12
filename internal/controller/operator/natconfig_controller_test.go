package operator_test

import (
	"sort"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	v1alpha1 "github.com/hanapedia/mooring/api/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var _ = Describe("NATConfig controller", func() {
	const blockSize = int32(100)

	// waitForNPRAllocCount polls until the NPR has exactly n allocations or times out.
	waitForNPRAllocCount := func(name string, n int) {
		Eventually(func() int {
			apr := getNPR(name)
			if apr == nil {
				return -1
			}
			return len(apr.Spec.Allocations)
		}, "10s", "100ms").Should(Equal(n),
			"NPR %s should have %d allocations", name, n)
	}

	Describe("new IP added to pool", func() {
		It("adds allocations for the new IP to all existing NPRs", func() {
			nc := makeNATConfig(uniqueName("nc"), []string{"203.0.113.0/30"}, blockSize)
			Expect(k8sClient.Create(ctx, nc)).To(Succeed())

			nprr := makeNPRR(uniqueName("nprr"), nc.Name, ptr32(1))
			Expect(k8sClient.Create(ctx, nprr)).To(Succeed())

			// 203.0.113.0/30 → 4 IPs, 1 block each = 4 allocations.
			waitForNPRAllocCount(nprr.Name, 4)

			// Add a /30 with 4 more IPs.
			Eventually(func() error {
				var current v1alpha1.NATConfig
				if err := k8sClient.Get(ctx, client.ObjectKey{Name: nc.Name}, &current); err != nil {
					return err
				}
				current.Spec.ExternalIPPool = []string{"203.0.113.0/30", "203.0.113.4/30"}
				return k8sClient.Update(ctx, &current)
			}, "5s", "100ms").Should(Succeed())

			// NPR should now have 8 allocations (4 original + 4 new IPs × 1 block each).
			waitForNPRAllocCount(nprr.Name, 8)

			apr := getNPR(nprr.Name)
			checkNonOverlapping(apr.Spec.Allocations)

			// Verify both old and new IPs are represented.
			ipSet := make(map[string]bool)
			for _, a := range apr.Spec.Allocations {
				ipSet[a.ExternalIP] = true
			}
			Expect(ipSet).To(HaveKey("203.0.113.0"))
			Expect(ipSet).To(HaveKey("203.0.113.4"))
		})
	})

	Describe("IP removed from pool", func() {
		It("removes allocations for the dropped IP from all NPRs", func() {
			nc := makeNATConfig(uniqueName("nc"), []string{"203.0.113.8/30", "203.0.113.12/30"}, blockSize)
			Expect(k8sClient.Create(ctx, nc)).To(Succeed())

			nprr := makeNPRR(uniqueName("nprr"), nc.Name, ptr32(1))
			Expect(k8sClient.Create(ctx, nprr)).To(Succeed())

			// 8 IPs total, 1 block each.
			waitForNPRAllocCount(nprr.Name, 8)

			// Remove the second /30.
			Eventually(func() error {
				var current v1alpha1.NATConfig
				if err := k8sClient.Get(ctx, client.ObjectKey{Name: nc.Name}, &current); err != nil {
					return err
				}
				current.Spec.ExternalIPPool = []string{"203.0.113.8/30"}
				return k8sClient.Update(ctx, &current)
			}, "5s", "100ms").Should(Succeed())

			// 4 IPs remain, 1 block each.
			waitForNPRAllocCount(nprr.Name, 4)

			// 203.0.113.12/30 → .12, .13, .14, .15 must all be gone.
			droppedIPs := map[string]bool{
				"203.0.113.12": true, "203.0.113.13": true,
				"203.0.113.14": true, "203.0.113.15": true,
			}
			apr := getNPR(nprr.Name)
			for _, a := range apr.Spec.Allocations {
				Expect(droppedIPs).NotTo(HaveKey(a.ExternalIP),
					"dropped IP %s should not appear in allocations", a.ExternalIP)
			}
		})
	})

	Describe("full pool replacement", func() {
		It("replaces all allocations when the IP pool is completely swapped", func() {
			nc := makeNATConfig(uniqueName("nc"), []string{"203.0.113.16/30"}, blockSize)
			Expect(k8sClient.Create(ctx, nc)).To(Succeed())

			nprr := makeNPRR(uniqueName("nprr"), nc.Name, ptr32(1))
			Expect(k8sClient.Create(ctx, nprr)).To(Succeed())
			waitForNPRAllocCount(nprr.Name, 4)

			// Capture the original IPs.
			originalIPs := make(map[string]bool)
			for _, a := range getNPR(nprr.Name).Spec.Allocations {
				originalIPs[a.ExternalIP] = true
			}

			// Replace pool with a completely different range.
			Eventually(func() error {
				var current v1alpha1.NATConfig
				if err := k8sClient.Get(ctx, client.ObjectKey{Name: nc.Name}, &current); err != nil {
					return err
				}
				current.Spec.ExternalIPPool = []string{"203.0.113.20/30"}
				return k8sClient.Update(ctx, &current)
			}, "5s", "100ms").Should(Succeed())

			// Wait until all original IPs are gone.
			Eventually(func() bool {
				apr := getNPR(nprr.Name)
				if apr == nil || len(apr.Spec.Allocations) != 4 {
					return false
				}
				for _, a := range apr.Spec.Allocations {
					if originalIPs[a.ExternalIP] {
						return false
					}
				}
				return true
			}, "10s", "100ms").Should(BeTrue(),
				"all original IPs should be replaced in the NPR")

			apr := getNPR(nprr.Name)
			checkNonOverlapping(apr.Spec.Allocations)
			for _, a := range apr.Spec.Allocations {
				Expect(a.ExternalIP).To(HavePrefix("203.0.113.2"))
			}
		})
	})

	Describe("multiple NPRs updated consistently", func() {
		It("all NPRs for a NATConfig are updated when IPs change", func() {
			nc := makeNATConfig(uniqueName("nc"), []string{"203.0.113.24/30"}, blockSize)
			Expect(k8sClient.Create(ctx, nc)).To(Succeed())

			nprr1 := makeNPRR(uniqueName("nprr"), nc.Name, ptr32(1))
			nprr2 := makeNPRR(uniqueName("nprr"), nc.Name, ptr32(1))
			Expect(k8sClient.Create(ctx, nprr1)).To(Succeed())
			Expect(k8sClient.Create(ctx, nprr2)).To(Succeed())

			waitForNPRAllocCount(nprr1.Name, 4)
			waitForNPRAllocCount(nprr2.Name, 4)

			// Add 4 more IPs.
			Eventually(func() error {
				var current v1alpha1.NATConfig
				if err := k8sClient.Get(ctx, client.ObjectKey{Name: nc.Name}, &current); err != nil {
					return err
				}
				current.Spec.ExternalIPPool = []string{"203.0.113.24/30", "203.0.113.28/30"}
				return k8sClient.Update(ctx, &current)
			}, "5s", "100ms").Should(Succeed())

			waitForNPRAllocCount(nprr1.Name, 8)
			waitForNPRAllocCount(nprr2.Name, 8)

			apr1 := getNPR(nprr1.Name)
			apr2 := getNPR(nprr2.Name)

			checkNonOverlapping(apr1.Spec.Allocations)
			checkNonOverlapping(apr2.Spec.Allocations)

			// pod1 and pod2 must not share PortStart on the same IP.
			byIP1 := make(map[string][]int32)
			for _, a := range apr1.Spec.Allocations {
				byIP1[a.ExternalIP] = append(byIP1[a.ExternalIP], a.PortStart)
			}
			for _, a := range apr2.Spec.Allocations {
				for _, ps := range byIP1[a.ExternalIP] {
					Expect(a.PortStart).NotTo(Equal(ps),
						"pods share PortStart %d on IP %s", a.PortStart, a.ExternalIP)
				}
			}
		})
	})

	Describe("NATConfig deletion", func() {
		It("does not delete existing NPRs (daemon owns deletion)", func() {
			nc := makeNATConfig(uniqueName("nc"), []string{"203.0.113.32/30"}, blockSize)
			Expect(k8sClient.Create(ctx, nc)).To(Succeed())

			nprr := makeNPRR(uniqueName("nprr"), nc.Name, ptr32(1))
			Expect(k8sClient.Create(ctx, nprr)).To(Succeed())
			waitForNPRAllocCount(nprr.Name, 4)

			// Delete the NATConfig; the operator should only remove the allocator.
			Expect(k8sClient.Delete(ctx, nc)).To(Succeed())

			// NPR should still be present (daemon is responsible for NPRR/NPR deletion).
			Consistently(func() bool { return getNPR(nprr.Name) != nil },
				"3s", "200ms").Should(BeTrue(),
				"NATConfig deletion must not remove existing NPRs")
		})
	})

	Describe("re-reconcile idempotency", func() {
		It("does not duplicate allocations when NATConfig is re-reconciled", func() {
			nc := makeNATConfig(uniqueName("nc"), []string{"203.0.113.36/30"}, blockSize)
			Expect(k8sClient.Create(ctx, nc)).To(Succeed())

			nprr := makeNPRR(uniqueName("nprr"), nc.Name, ptr32(1))
			Expect(k8sClient.Create(ctx, nprr)).To(Succeed())
			waitForNPRAllocCount(nprr.Name, 4)

			snapshot := make([]v1alpha1.PortAllocation, len(getNPR(nprr.Name).Spec.Allocations))
			copy(snapshot, getNPR(nprr.Name).Spec.Allocations)

			// Force a reconcile by touching the NATConfig spec (simulate restart effect).
			Eventually(func() error {
				var current v1alpha1.NATConfig
				if err := k8sClient.Get(ctx, client.ObjectKey{Name: nc.Name}, &current); err != nil {
					return err
				}
				return k8sClient.Update(ctx, &current)
			}, "5s", "100ms").Should(Succeed())

			// Allocation count must remain the same — no duplication.
			Consistently(func() int {
				apr := getNPR(nprr.Name)
				if apr == nil {
					return -1
				}
				return len(apr.Spec.Allocations)
			}, "3s", "200ms").Should(Equal(4),
				"re-reconcile must not add duplicate allocations")

			// The actual allocations should be a permutation of the snapshot.
			apr := getNPR(nprr.Name)
			sortAllocs := func(allocs []v1alpha1.PortAllocation) {
				sort.Slice(allocs, func(i, j int) bool {
					if allocs[i].ExternalIP != allocs[j].ExternalIP {
						return allocs[i].ExternalIP < allocs[j].ExternalIP
					}
					return allocs[i].PortStart < allocs[j].PortStart
				})
			}
			sortAllocs(snapshot)
			actual := make([]v1alpha1.PortAllocation, len(apr.Spec.Allocations))
			copy(actual, apr.Spec.Allocations)
			sortAllocs(actual)
			Expect(actual).To(Equal(snapshot))
		})
	})
})
