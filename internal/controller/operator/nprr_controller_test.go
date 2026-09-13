package operator_test

import (
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	v1alpha1 "github.com/hanapedia/mooring/api/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var _ = Describe("NATPortRangeRequest controller", func() {
	// Each test creates its own NATConfig so the allocators are isolated.
	// Block size 100 keeps port ranges small and predictable in assertions.
	const blockSize = int32(100)

	Describe("NPR creation", func() {
		It("creates an NPR with one block per external IP", func() {
			nc := makeNATConfig(uniqueName("nc"), []string{"192.0.2.0/30"}, blockSize)
			Expect(k8sClient.Create(ctx, nc)).To(Succeed())

			nprr := makeNPRR(uniqueName("nprr"), nc.Name, nil)
			Expect(k8sClient.Create(ctx, nprr)).To(Succeed())

			// Wait for the NPR to appear.
			eventually(func() bool { return getNPR(nprr.Name) != nil })

			npr := getNPR(nprr.Name)
			Expect(npr).NotTo(BeNil())

			// 192.0.2.0/30 → .0, .1, .2, .3 (4 IPs), default portRangeCount=1
			// Each IP gets exactly one block.
			Expect(npr.Spec.Allocations).To(HaveLen(4))
			checkNonOverlapping(npr.Spec.Allocations)
			Expect(npr.Spec.PortRangeCount).To(Equal(int32(1)))

			// NPR must carry the allocation finalizer.
			Expect(npr.Finalizers).To(ContainElement("mooring.hanapedia.link/allocation"))

			// NPR has the same name as the NPRR and no owner reference (operator
			// controls NPR lifecycle directly via StaleSince and BPFCleanupWindow).
			Expect(npr.Name).To(Equal(nprr.Name))
			Expect(npr.OwnerReferences).To(BeEmpty())
		})

		It("respects explicit portRangeCount > 1", func() {
			nc := makeNATConfig(uniqueName("nc"), []string{"192.0.2.4/30"}, blockSize)
			Expect(k8sClient.Create(ctx, nc)).To(Succeed())

			nprr := makeNPRR(uniqueName("nprr"), nc.Name, ptr32(2))
			Expect(k8sClient.Create(ctx, nprr)).To(Succeed())

			eventually(func() bool {
				apr := getNPR(nprr.Name)
				return apr != nil && apr.Spec.PortRangeCount == 2
			})

			npr := getNPR(nprr.Name)
			// 4 IPs × 2 blocks each = 8 allocations
			Expect(npr.Spec.Allocations).To(HaveLen(8))
			checkNonOverlapping(npr.Spec.Allocations)
		})

		It("waits for NATConfig to exist before creating NPR", func() {
			nprr := makeNPRR(uniqueName("nprr"), "nonexistent-nc", nil)
			Expect(k8sClient.Create(ctx, nprr)).To(Succeed())

			// NPR must not appear while the NATConfig is missing.
			Consistently(func() bool { return getNPR(nprr.Name) == nil },
				"2s", "200ms").Should(BeTrue())
		})
	})

	Describe("portRangeCount increase", func() {
		It("adds new blocks when portRangeCount is raised", func() {
			nc := makeNATConfig(uniqueName("nc"), []string{"192.0.2.8/30"}, blockSize)
			Expect(k8sClient.Create(ctx, nc)).To(Succeed())

			nprr := makeNPRR(uniqueName("nprr"), nc.Name, ptr32(1))
			Expect(k8sClient.Create(ctx, nprr)).To(Succeed())

			eventually(func() bool {
				apr := getNPR(nprr.Name)
				return apr != nil && apr.Spec.PortRangeCount == 1
			})

			// Increase portRangeCount to 2.
			Eventually(func() error {
				var current v1alpha1.NATPortRangeRequest
				if err := k8sClient.Get(ctx, client.ObjectKey{Name: nprr.Name}, &current); err != nil {
					return err
				}
				current.Spec.PortRangeCount = ptr32(2)
				return k8sClient.Update(ctx, &current)
			}, "5s", "100ms").Should(Succeed())

			// Wait for NPR to reflect portRangeCount=2.
			eventually(func() bool {
				apr := getNPR(nprr.Name)
				return apr != nil && apr.Spec.PortRangeCount == 2
			})

			npr := getNPR(nprr.Name)
			// 4 IPs × 2 blocks each = 8 allocations; none must overlap.
			Expect(npr.Spec.Allocations).To(HaveLen(8))
			checkNonOverlapping(npr.Spec.Allocations)
		})
	})

	Describe("portRangeCount decrease", func() {
		It("removes allocations when portRangeCount is lowered", func() {
			nc := makeNATConfig(uniqueName("nc"), []string{"192.0.2.12/30"}, blockSize)
			Expect(k8sClient.Create(ctx, nc)).To(Succeed())

			nprr := makeNPRR(uniqueName("nprr"), nc.Name, ptr32(3))
			Expect(k8sClient.Create(ctx, nprr)).To(Succeed())

			eventually(func() bool {
				apr := getNPR(nprr.Name)
				return apr != nil && apr.Spec.PortRangeCount == 3
			})
			Expect(getNPR(nprr.Name).Spec.Allocations).To(HaveLen(12)) // 4 IPs × 3

			// Decrease portRangeCount to 1.
			Eventually(func() error {
				var current v1alpha1.NATPortRangeRequest
				if err := k8sClient.Get(ctx, client.ObjectKey{Name: nprr.Name}, &current); err != nil {
					return err
				}
				current.Spec.PortRangeCount = ptr32(1)
				return k8sClient.Update(ctx, &current)
			}, "5s", "100ms").Should(Succeed())

			eventually(func() bool {
				apr := getNPR(nprr.Name)
				return apr != nil && apr.Spec.PortRangeCount == 1
			})

			npr := getNPR(nprr.Name)
			// 4 IPs × 1 block each = 4 allocations.
			Expect(npr.Spec.Allocations).To(HaveLen(4))
			checkNonOverlapping(npr.Spec.Allocations)
		})
	})

	Describe("freed blocks are reusable", func() {
		It("freed blocks from a decrease can be allocated to a new pod", func() {
			nc := makeNATConfig(uniqueName("nc"), []string{"192.0.2.16/30"}, blockSize)
			Expect(k8sClient.Create(ctx, nc)).To(Succeed())

			// First pod: allocates 2 blocks per IP.
			nprr1 := makeNPRR(uniqueName("nprr"), nc.Name, ptr32(2))
			Expect(k8sClient.Create(ctx, nprr1)).To(Succeed())
			eventually(func() bool {
				apr := getNPR(nprr1.Name)
				return apr != nil && apr.Spec.PortRangeCount == 2
			})

			before := getNPR(nprr1.Name).Spec.Allocations

			// Decrease to 1 block per IP — frees 4 blocks (one per IP).
			Eventually(func() error {
				var current v1alpha1.NATPortRangeRequest
				if err := k8sClient.Get(ctx, client.ObjectKey{Name: nprr1.Name}, &current); err != nil {
					return err
				}
				current.Spec.PortRangeCount = ptr32(1)
				return k8sClient.Update(ctx, &current)
			}, "5s", "100ms").Should(Succeed())

			eventually(func() bool {
				apr := getNPR(nprr1.Name)
				return apr != nil && apr.Spec.PortRangeCount == 1
			})

			// Second pod: should be able to allocate (reusing freed blocks).
			nprr2 := makeNPRR(uniqueName("nprr"), nc.Name, ptr32(1))
			Expect(k8sClient.Create(ctx, nprr2)).To(Succeed())
			eventually(func() bool { return getNPR(nprr2.Name) != nil })

			apr1 := getNPR(nprr1.Name)
			apr2 := getNPR(nprr2.Name)

			// The two pods must not share any PortStart across the same external IP.
			portsByIP := make(map[string]map[int32]string)
			for _, a := range append(apr1.Spec.Allocations, apr2.Spec.Allocations...) {
				if portsByIP[a.ExternalIP] == nil {
					portsByIP[a.ExternalIP] = make(map[int32]string)
				}
				if prev, ok := portsByIP[a.ExternalIP][a.PortStart]; ok {
					Fail(fmt.Sprintf("duplicate PortStart %d on IP %s: NPRs %s and other", a.PortStart, a.ExternalIP, prev))
				}
				portsByIP[a.ExternalIP][a.PortStart] = nprr1.Name
			}
			_ = before // suppress unused warning
		})
	})

	Describe("two pods, same NATConfig — non-overlapping constraint", func() {
		It("assigns non-overlapping port ranges across all IPs for two pods", func() {
			nc := makeNATConfig(uniqueName("nc"), []string{"192.0.2.20/30"}, blockSize)
			Expect(k8sClient.Create(ctx, nc)).To(Succeed())

			nprr1 := makeNPRR(uniqueName("nprr"), nc.Name, ptr32(1))
			nprr2 := makeNPRR(uniqueName("nprr"), nc.Name, ptr32(1))
			Expect(k8sClient.Create(ctx, nprr1)).To(Succeed())
			Expect(k8sClient.Create(ctx, nprr2)).To(Succeed())

			eventually(func() bool { return getNPR(nprr1.Name) != nil })
			eventually(func() bool { return getNPR(nprr2.Name) != nil })

			apr1 := getNPR(nprr1.Name)
			apr2 := getNPR(nprr2.Name)

			// Both NPRs must individually be non-overlapping.
			checkNonOverlapping(apr1.Spec.Allocations)
			checkNonOverlapping(apr2.Spec.Allocations)

			// The two pods must not share any PortStart globally (collision would
			// corrupt the NAT table since it lacks an ext_ip dimension).
			portsByIP := make(map[string]map[int32]bool)
			for _, a := range apr1.Spec.Allocations {
				if portsByIP[a.ExternalIP] == nil {
					portsByIP[a.ExternalIP] = make(map[int32]bool)
				}
				portsByIP[a.ExternalIP][a.PortStart] = true
			}
			for _, a := range apr2.Spec.Allocations {
				if portsByIP[a.ExternalIP] != nil && portsByIP[a.ExternalIP][a.PortStart] {
					Fail(fmt.Sprintf("pods share PortStart %d on IP %s", a.PortStart, a.ExternalIP))
				}
			}
		})
	})
})
