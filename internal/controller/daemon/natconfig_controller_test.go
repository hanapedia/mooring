package daemon_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	v1alpha1 "github.com/hanapedia/mooring/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var _ = Describe("NATConfig controller", func() {

	Describe("BPF LPM map sync", func() {
		It("adds target CIDRs and ext IPs to BPF on NATConfig creation", func() {
			targetCIDR := "10.21.0.0/24"
			extCIDR := "203.0.114.0/30"
			nc := makeNATConfig(uniqueName("nc"), []string{targetCIDR}, []string{extCIDR},
				metav1.LabelSelector{})
			Expect(k8sClient.Create(ctx, nc)).To(Succeed())

			eventually(func() bool { return mockTargetCIDR.hasAdded(targetCIDR) })
			eventually(func() bool { return mockExtIPPool.hasAdded(extCIDR) })
		})

		It("removes target CIDRs and ext IPs from BPF on NATConfig deletion", func() {
			targetCIDR := "10.22.0.0/24"
			extCIDR := "203.0.114.4/30"
			nc := makeNATConfig(uniqueName("nc"), []string{targetCIDR}, []string{extCIDR},
				metav1.LabelSelector{})
			Expect(k8sClient.Create(ctx, nc)).To(Succeed())

			eventually(func() bool { return mockTargetCIDR.hasAdded(targetCIDR) })

			Expect(k8sClient.Delete(ctx, nc)).To(Succeed())

			eventually(func() bool { return mockTargetCIDR.hasRemoved(targetCIDR) })
			eventually(func() bool { return mockExtIPPool.hasRemoved(extCIDR) })
		})

		It("does not remove a CIDR from BPF while another NATConfig still references it", func() {
			sharedTarget := "10.23.0.0/24"
			sentinelTarget := "10.23.1.0/24" // unique to nc1; its removal proves nc1 was reconciled
			extCIDR1 := "203.0.114.8/30"
			extCIDR2 := "203.0.114.12/30"

			nc1 := makeNATConfig(uniqueName("nc"), []string{sharedTarget, sentinelTarget}, []string{extCIDR1},
				metav1.LabelSelector{})
			nc2 := makeNATConfig(uniqueName("nc"), []string{sharedTarget}, []string{extCIDR2},
				metav1.LabelSelector{})
			Expect(k8sClient.Create(ctx, nc1)).To(Succeed())
			Expect(k8sClient.Create(ctx, nc2)).To(Succeed())

			eventually(func() bool { return mockTargetCIDR.hasAdded(sharedTarget) })

			// Delete nc1; wait for its sentinel CIDR to be removed (proves reconcile ran).
			Expect(k8sClient.Delete(ctx, nc1)).To(Succeed())
			eventually(func() bool { return mockTargetCIDR.hasRemoved(sentinelTarget) })

			// sharedTarget must NOT have been removed because nc2 still owns it.
			Expect(mockTargetCIDR.hasRemoved(sharedTarget)).To(BeFalse())

			// Now delete nc2; shared CIDR should be removed.
			Expect(k8sClient.Delete(ctx, nc2)).To(Succeed())
			eventually(func() bool { return mockTargetCIDR.hasRemoved(sharedTarget) })
		})
	})

	Describe("BPF update on spec change", func() {
		It("updates CIDRs in BPF when NATConfig externalIPPool changes", func() {
			oldExtCIDR := "203.0.114.24/30"
			newExtCIDR := "203.0.114.28/30"
			nc := makeNATConfig(uniqueName("nc"), []string{"10.26.0.0/24"}, []string{oldExtCIDR},
				metav1.LabelSelector{})
			Expect(k8sClient.Create(ctx, nc)).To(Succeed())

			eventually(func() bool { return mockExtIPPool.hasAdded(oldExtCIDR) })

			Eventually(func() error {
				var current v1alpha1.NATConfig
				if err := k8sClient.Get(ctx, client.ObjectKey{Name: nc.Name}, &current); err != nil {
					return err
				}
				current.Spec.ExternalIPPool = []string{newExtCIDR}
				return k8sClient.Update(ctx, &current)
			}, "5s", "100ms").Should(Succeed())

			eventually(func() bool { return mockExtIPPool.hasAdded(newExtCIDR) })
			eventually(func() bool { return mockExtIPPool.hasRemoved(oldExtCIDR) })
		})
	})
})
