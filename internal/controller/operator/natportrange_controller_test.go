package operator_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	v1alpha1 "github.com/hanapedia/mooring/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
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
