package operator_test

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	v1alpha1 "github.com/hanapedia/mooring/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

var _ = Describe("NATPortRange controller", func() {
	const blockSize = int32(100)
	const finalizerName = "mooring.hanapedia.link/allocation"

	// In envtest, the GC cascade (owner → owned) is not running.  The NPR controller
	// is responsible for removing the finalizer when the NPR itself has a DeletionTimestamp.
	// Tests here set DeletionTimestamp by deleting the NPR directly.

	Describe("finalizer removal on deletion", func() {
		It("removes the finalizer when NPR is deleted", func() {
			nc := makeNATConfig(uniqueName("nc"), []string{"198.51.100.0/30"}, blockSize)
			Expect(k8sClient.Create(ctx, nc)).To(Succeed())

			nprr := makeNPRR(uniqueName("nprr"), nc.Name, ptr32(1))
			Expect(k8sClient.Create(ctx, nprr)).To(Succeed())

			// Wait for NPR to appear with the finalizer.
			eventually(func() bool {
				apr := getNPR(nprr.Name)
				return apr != nil && controllerutil.ContainsFinalizer(apr, finalizerName)
			})

			// Delete the NPR directly — controller must remove the finalizer so GC can complete.
			apr := getNPR(nprr.Name)
			Expect(k8sClient.Delete(ctx, apr)).To(Succeed())

			Eventually(func() bool {
				return getNPR(nprr.Name) == nil
			}, "15s", "200ms").Should(BeTrue(),
				"NPR should be deleted after finalizer is removed")
		})

		It("does not touch an NPR that has no deletion timestamp", func() {
			nc := makeNATConfig(uniqueName("nc"), []string{"198.51.100.4/30"}, blockSize)
			Expect(k8sClient.Create(ctx, nc)).To(Succeed())

			npr := &v1alpha1.NATPortRange{
				ObjectMeta: ctrl.ObjectMeta{Name: uniqueName("npr")},
				Spec: v1alpha1.NATPortRangeSpec{
					PodName:        "pod-x",
					PodNamespace:   "default",
					PodIP:          "10.0.0.99",
					NodeName:       "node-1",
					NATConfig:      nc.Name,
					TargetCIDRs:    nc.Spec.TargetCIDRs,
					PortRangeCount: 0,
					Allocations:    []v1alpha1.PortAllocation{},
				},
			}
			Expect(k8sClient.Create(ctx, npr)).To(Succeed())

			// NPR has no finalizer; controller must leave it untouched.
			Consistently(func() bool { return getNPR(npr.Name) != nil },
				"2s", "200ms").Should(BeTrue())

			Expect(k8sClient.Delete(ctx, npr)).To(Succeed())
		})
	})

	Describe("NPR deleted after NATConfig is gone (allocator missing)", func() {
		It("removes the finalizer even when the NATConfig allocator is gone", func() {
			nc := makeNATConfig(uniqueName("nc"), []string{"198.51.100.8/30"}, blockSize)
			Expect(k8sClient.Create(ctx, nc)).To(Succeed())

			nprr := makeNPRR(uniqueName("nprr"), nc.Name, ptr32(1))
			Expect(k8sClient.Create(ctx, nprr)).To(Succeed())

			eventually(func() bool {
				apr := getNPR(nprr.Name)
				return apr != nil && controllerutil.ContainsFinalizer(apr, finalizerName)
			})

			// Delete the NATConfig first (removes the allocator from registry).
			Expect(k8sClient.Delete(ctx, nc)).To(Succeed())

			// Now delete the NPR directly — controller must still remove the finalizer.
			apr := getNPR(nprr.Name)
			Expect(k8sClient.Delete(ctx, apr)).To(Succeed())

			Eventually(func() bool {
				return getNPR(nprr.Name) == nil
			}, "15s", "200ms").Should(BeTrue(),
				"NPR should be deleted even when allocator is already gone")
		})
	})

	Describe("block reclamation", func() {
		It("frees blocks so a subsequent pod can reuse them", func() {
			nc := makeNATConfig(uniqueName("nc"), []string{"198.51.100.12/30"}, blockSize)
			Expect(k8sClient.Create(ctx, nc)).To(Succeed())

			// Pod 1.
			nprr1 := makeNPRR(uniqueName("nprr"), nc.Name, ptr32(1))
			Expect(k8sClient.Create(ctx, nprr1)).To(Succeed())
			eventually(func() bool { return getNPR(nprr1.Name) != nil })

			portsBefore := getNPR(nprr1.Name).Spec.Allocations

			// Delete pod1's NPR; controller must free the blocks.
			apr1 := getNPR(nprr1.Name)
			Expect(k8sClient.Delete(ctx, apr1)).To(Succeed())
			Eventually(func() bool { return getNPR(nprr1.Name) == nil },
				"15s", "200ms").Should(BeTrue())

			// Pod 2 should be allocatable — the freed blocks must be back in the pool.
			nprr2 := makeNPRR(uniqueName("nprr"), nc.Name, ptr32(1))
			Expect(k8sClient.Create(ctx, nprr2)).To(Succeed())
			eventually(func() bool { return getNPR(nprr2.Name) != nil })

			portsAfter := getNPR(nprr2.Name).Spec.Allocations

			// Must have one allocation per IP and must be non-overlapping.
			Expect(portsAfter).To(HaveLen(len(portsBefore)))
			checkNonOverlapping(portsAfter)

			// Cleanup.
			apr2 := getNPR(nprr2.Name)
			Expect(k8sClient.Delete(ctx, apr2)).To(Succeed())
		})
	})

	Describe("StaleSince and cleanup on NPRR deletion", func() {
		It("sets StaleSince on the NPR when the NPRR is deleted", func() {
			nc := makeNATConfig(uniqueName("nc"), []string{"198.51.100.20/30"}, blockSize)
			Expect(k8sClient.Create(ctx, nc)).To(Succeed())

			nprr := makeNPRR(uniqueName("nprr"), nc.Name, ptr32(1))
			Expect(k8sClient.Create(ctx, nprr)).To(Succeed())

			eventually(func() bool { return getNPR(nprr.Name) != nil })

			Expect(k8sClient.Delete(ctx, nprr)).To(Succeed())

			Eventually(func() bool {
				npr := getNPR(nprr.Name)
				// Either NPR is gone (stale + deleted by cleanup window) or
				// StaleSince is visible — both prove the lifecycle ran correctly.
				return npr == nil || npr.Spec.StaleSince != nil
			}, 10*time.Second, 100*time.Millisecond).Should(BeTrue(),
				"NPR should become stale or be deleted after NPRR is removed")
		})

		It("deletes the NPR after BPFCleanupWindow once StaleSince is set", func() {
			nc := makeNATConfig(uniqueName("nc"), []string{"198.51.100.24/30"}, blockSize)
			Expect(k8sClient.Create(ctx, nc)).To(Succeed())

			nprr := makeNPRR(uniqueName("nprr"), nc.Name, ptr32(1))
			Expect(k8sClient.Create(ctx, nprr)).To(Succeed())

			eventually(func() bool { return getNPR(nprr.Name) != nil })
			nprName := nprr.Name

			Expect(k8sClient.Delete(ctx, nprr)).To(Succeed())

			// After BPFCleanupWindow (500ms in tests), NPR should be fully deleted.
			// We don't assert StaleSince separately because the cleanup window is short
			// enough that the NPR may already be gone by the first poll.
			Eventually(func() bool {
				return getNPR(nprName) == nil
			}, 15*time.Second, 100*time.Millisecond).Should(BeTrue(),
				"NPR should be deleted after BPFCleanupWindow elapses")
		})

		It("frees port blocks after NPRR deletion so a new pod can reuse them", func() {
			nc := makeNATConfig(uniqueName("nc"), []string{"198.51.100.28/30"}, blockSize)
			Expect(k8sClient.Create(ctx, nc)).To(Succeed())

			nprr1 := makeNPRR(uniqueName("nprr"), nc.Name, ptr32(1))
			Expect(k8sClient.Create(ctx, nprr1)).To(Succeed())
			eventually(func() bool { return getNPR(nprr1.Name) != nil })

			Expect(k8sClient.Delete(ctx, nprr1)).To(Succeed())

			// Wait for NPR to be fully deleted (blocks freed).
			Eventually(func() bool {
				return getNPR(nprr1.Name) == nil
			}, 15*time.Second, 200*time.Millisecond).Should(BeTrue())

			// A new pod should be able to get allocations from the freed pool.
			nprr2 := makeNPRR(uniqueName("nprr"), nc.Name, ptr32(1))
			Expect(k8sClient.Create(ctx, nprr2)).To(Succeed())
			eventually(func() bool { return getNPR(nprr2.Name) != nil })

			Expect(getNPR(nprr2.Name).Spec.Allocations).NotTo(BeEmpty())

			// Cleanup.
			Expect(k8sClient.Delete(ctx, nprr2)).To(Succeed())
		})
	})

	Describe("NPR does not become stale without a corresponding NPRR", func() {
		It("does not set StaleSince on a manually-created NPR with no matching NPRR", func() {
			// A manually-created NPR has no corresponding NPRR, so the NPRR
			// controller never fires for its name and StaleSince is never stamped.
			npr := &v1alpha1.NATPortRange{
				ObjectMeta: ctrl.ObjectMeta{
					Name:       uniqueName("npr-manual"),
					Finalizers: []string{finalizerName},
				},
				Spec: v1alpha1.NATPortRangeSpec{
					PodName: "pod-x", PodNamespace: "default",
					PodIP: "10.0.0.88", NodeName: "node-1",
					NATConfig:   "some-nc",
					TargetCIDRs: []string{"0.0.0.0/0"},
					Allocations: []v1alpha1.PortAllocation{},
				},
			}
			Expect(k8sClient.Create(ctx, npr)).To(Succeed())

			Consistently(func() bool {
				cur := getNPR(npr.Name)
				return cur != nil && cur.Spec.StaleSince == nil
			}, 2*time.Second, 200*time.Millisecond).Should(BeTrue(),
				"operator must not stale an NPR that has no corresponding NPRR")

			// Cleanup.
			Eventually(func() error {
				var cur v1alpha1.NATPortRange
				if err := k8sClient.Get(ctx, client.ObjectKey{Name: npr.Name}, &cur); err != nil {
					return err
				}
				return k8sClient.Delete(ctx, &cur)
			}, "5s", "100ms").Should(Succeed())
		})
	})

	Describe("NPR with finalizer but no matching NATConfig at all", func() {
		It("removes finalizer from an orphaned NPR on deletion", func() {
			orphanName := uniqueName("npr-orphan")
			npr := &v1alpha1.NATPortRange{
				ObjectMeta: metav1.ObjectMeta{
					Name:       orphanName,
					Finalizers: []string{finalizerName},
				},
				Spec: v1alpha1.NATPortRangeSpec{
					PodName:        "orphan-pod",
					PodNamespace:   "default",
					PodIP:          "10.0.0.200",
					NodeName:       "node-1",
					NATConfig:      "does-not-exist",
					TargetCIDRs:    []string{"0.0.0.0/0"},
					PortRangeCount: 0,
					Allocations:    []v1alpha1.PortAllocation{},
				},
			}
			Expect(k8sClient.Create(ctx, npr)).To(Succeed())

			Expect(k8sClient.Delete(ctx, npr)).To(Succeed())

			Eventually(func() bool {
				return getNPR(orphanName) == nil
			}, "15s", "200ms").Should(BeTrue(),
				"orphaned NPR should be deleted after finalizer removal")
		})
	})
})
