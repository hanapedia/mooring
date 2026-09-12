package daemon_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	v1alpha1 "github.com/hanapedia/mooring/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const testFinalizer = "test/keep"

// testTargetCIDR is the target CIDR embedded in all NPRs created by makeNPR.
// Tests that check snat_config calls (UpsertSnatEntry, RemoveSnatAllocs) can
// assert against this value.
const testTargetCIDR = "10.99.0.0/24"

func makeNPR(name, nodeName, podIP, extIP string, portStart, portEnd int32) *v1alpha1.NATPortRange {
	return &v1alpha1.NATPortRange{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: v1alpha1.NATPortRangeSpec{
			PodName:        "pod-" + name,
			PodNamespace:   "default",
			PodIP:          podIP,
			NodeName:       nodeName,
			NATConfig:      "some-nc",
			TargetCIDRs:    []string{testTargetCIDR},
			PortRangeCount: 1,
			Allocations: []v1alpha1.PortAllocation{
				{ExternalIP: extIP, PortStart: portStart, PortEnd: portEnd},
			},
		},
	}
}

var _ = Describe("NATPortRange sync controller", func() {

	Describe("AddPortRange on NPR creation", func() {
		It("calls AddPortRange for all three protocols for a local-node NPR", func() {
			extIP := "203.0.115.1"
			podIP := "10.244.4.10"
			var portStart, portEnd uint16 = 1000, 1099
			npr := makeNPR(uniqueName("npr"), testNodeName, podIP, extIP, int32(portStart), int32(portEnd))
			Expect(k8sClient.Create(ctx, npr)).To(Succeed())

			// TCP, UDP, ICMP
			for _, proto := range []uint8{6, 17, 1} {
				proto := proto
				eventually(func() bool {
					return mockPortRange.hasAdded(extIP, podIP, portStart, portEnd, proto)
				})
			}
		})

		It("calls UpsertSnatEntry for a local-node NPR", func() {
			extIP := "203.0.115.2"
			podIP := "10.244.4.11"
			npr := makeNPR(uniqueName("npr"), testNodeName, podIP, extIP, 1100, 1199)
			Expect(k8sClient.Create(ctx, npr)).To(Succeed())

			eventually(func() bool {
				return mockPortRange.hasUpsertedSnat(podIP, extIP)
			})
		})

		It("calls AddPortRange but not UpsertSnatEntry for a remote-node NPR", func() {
			extIP := "203.0.115.3"
			podIP := "10.244.4.12"
			var portStart, portEnd uint16 = 1200, 1299
			npr := makeNPR(uniqueName("npr"), "other-node", podIP, extIP, int32(portStart), int32(portEnd))
			Expect(k8sClient.Create(ctx, npr)).To(Succeed())

			eventually(func() bool {
				return mockPortRange.hasAdded(extIP, podIP, portStart, portEnd, 6)
			})
			// Give the reconciler time to potentially (incorrectly) call UpsertSnat.
			consistently(func() bool {
				return !mockPortRange.hasUpsertedSnat(podIP, extIP)
			})
		})
	})

	Describe("RemovePortRange on NPR deletion", func() {
		It("calls RemovePortRange and RemoveSnatAllocs when a local-node NPR is deleted", func() {
			extIP := "203.0.115.4"
			podIP := "10.244.4.20"
			var portStart, portEnd uint16 = 1300, 1399

			// Add finalizer so we can observe the terminating state.
			npr := makeNPR(uniqueName("npr"), testNodeName, podIP, extIP, int32(portStart), int32(portEnd))
			npr.Finalizers = []string{testFinalizer}
			Expect(k8sClient.Create(ctx, npr)).To(Succeed())

			// Wait for initial sync (AddPortRange).
			eventually(func() bool {
				return mockPortRange.hasAdded(extIP, podIP, portStart, portEnd, 6)
			})

			// Delete → DeletionTimestamp set, finalizer keeps the NPR alive.
			Expect(k8sClient.Delete(ctx, npr)).To(Succeed())

			for _, proto := range []uint8{6, 17, 1} {
				proto := proto
				eventually(func() bool {
					return mockPortRange.hasRemoved(extIP, podIP, portStart, portEnd, proto)
				})
			}
			eventually(func() bool {
				return mockPortRange.hasRemovedSnat(podIP)
			})

			// Cleanup: remove finalizer.
			Eventually(func() error {
				var cur v1alpha1.NATPortRange
				if err := k8sClient.Get(ctx, client.ObjectKey{Name: npr.Name}, &cur); err != nil {
					return err
				}
				cur.Finalizers = nil
				return k8sClient.Update(ctx, &cur)
			}, "5s", "100ms").Should(Succeed())
		})

		It("calls RemovePortRange but not RemoveSnatAllocs for a remote-node NPR deletion", func() {
			extIP := "203.0.115.5"
			podIP := "10.244.4.21"
			var portStart, portEnd uint16 = 1400, 1499

			npr := makeNPR(uniqueName("npr"), "other-node", podIP, extIP, int32(portStart), int32(portEnd))
			npr.Finalizers = []string{testFinalizer}
			Expect(k8sClient.Create(ctx, npr)).To(Succeed())

			eventually(func() bool {
				return mockPortRange.hasAdded(extIP, podIP, portStart, portEnd, 6)
			})

			Expect(k8sClient.Delete(ctx, npr)).To(Succeed())

			for _, proto := range []uint8{6, 17, 1} {
				proto := proto
				eventually(func() bool {
					return mockPortRange.hasRemoved(extIP, podIP, portStart, portEnd, proto)
				})
			}
			consistently(func() bool {
				return !mockPortRange.hasRemovedSnat(podIP)
			})

			// Cleanup.
			Eventually(func() error {
				var cur v1alpha1.NATPortRange
				if err := k8sClient.Get(ctx, client.ObjectKey{Name: npr.Name}, &cur); err != nil {
					return err
				}
				cur.Finalizers = nil
				return k8sClient.Update(ctx, &cur)
			}, "5s", "100ms").Should(Succeed())
		})
	})

	Describe("minimal diff on allocation change", func() {
		It("removes old allocation and adds new one when allocations are updated", func() {
			oldExtIP := "203.0.115.6"
			newExtIP := "203.0.115.7"
			podIP := "10.244.4.30"
			var oldStart, oldEnd uint16 = 1500, 1599
			var newStart, newEnd uint16 = 1600, 1699

			npr := makeNPR(uniqueName("npr"), testNodeName, podIP, oldExtIP, int32(oldStart), int32(oldEnd))
			Expect(k8sClient.Create(ctx, npr)).To(Succeed())

			eventually(func() bool {
				return mockPortRange.hasAdded(oldExtIP, podIP, oldStart, oldEnd, 6)
			})

			// Replace the allocation.
			Eventually(func() error {
				var cur v1alpha1.NATPortRange
				if err := k8sClient.Get(ctx, client.ObjectKey{Name: npr.Name}, &cur); err != nil {
					return err
				}
				cur.Spec.Allocations = []v1alpha1.PortAllocation{
					{ExternalIP: newExtIP, PortStart: int32(newStart), PortEnd: int32(newEnd)},
				}
				return k8sClient.Update(ctx, &cur)
			}, "5s", "100ms").Should(Succeed())

			eventually(func() bool {
				return mockPortRange.hasAdded(newExtIP, podIP, newStart, newEnd, 6)
			})
			eventually(func() bool {
				return mockPortRange.hasRemoved(oldExtIP, podIP, oldStart, oldEnd, 6)
			})
		})
	})
})
