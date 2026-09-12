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

			eventually(func() bool { return mockLPM.hasAddedTarget(targetCIDR) })
			eventually(func() bool { return mockLPM.hasAddedExtIP(extCIDR) })
		})

		It("removes target CIDRs and ext IPs from BPF on NATConfig deletion", func() {
			targetCIDR := "10.22.0.0/24"
			extCIDR := "203.0.114.4/30"
			nc := makeNATConfig(uniqueName("nc"), []string{targetCIDR}, []string{extCIDR},
				metav1.LabelSelector{})
			Expect(k8sClient.Create(ctx, nc)).To(Succeed())

			eventually(func() bool { return mockLPM.hasAddedTarget(targetCIDR) })

			Expect(k8sClient.Delete(ctx, nc)).To(Succeed())

			eventually(func() bool { return mockLPM.hasRemovedTarget(targetCIDR) })
			eventually(func() bool { return mockLPM.hasRemovedExtIP(extCIDR) })
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

			eventually(func() bool { return mockLPM.hasAddedTarget(sharedTarget) })

			// Delete nc1; wait for its sentinel CIDR to be removed (proves reconcile ran).
			Expect(k8sClient.Delete(ctx, nc1)).To(Succeed())
			eventually(func() bool { return mockLPM.hasRemovedTarget(sentinelTarget) })

			// sharedTarget must NOT have been removed because nc2 still owns it.
			Expect(mockLPM.hasRemovedTarget(sharedTarget)).To(BeFalse())

			// Now delete nc2; shared CIDR should be removed.
			Expect(k8sClient.Delete(ctx, nc2)).To(Succeed())
			eventually(func() bool { return mockLPM.hasRemovedTarget(sharedTarget) })
		})
	})

	Describe("NPRR lifecycle", func() {
		It("creates NPRRs for matching local pods when NATConfig appears", func() {
			// Create pod first, then NATConfig.
			podName := uniqueName("pod")
			pod := makePod(podName, "default", map[string]string{"env": podName})
			Expect(k8sClient.Create(ctx, pod)).To(Succeed())
			setPodIP(pod, "10.244.3.10")

			ncName := uniqueName("nc")
			nc := makeNATConfig(ncName, []string{"10.24.0.0/24"}, []string{"203.0.114.16/30"},
				metav1.LabelSelector{MatchLabels: map[string]string{"env": podName}})
			Expect(k8sClient.Create(ctx, nc)).To(Succeed())

			nprrN := "default-" + podName + "-" + ncName
			eventually(func() bool { return nprrExists(nprrN) })
		})

		It("sets DeletionGracePeriodExpiry on NPRRs when NATConfig is deleted", func() {
			ncName := uniqueName("nc")
			nc := makeNATConfig(ncName, []string{"10.25.0.0/24"}, []string{"203.0.114.20/30"},
				metav1.LabelSelector{MatchLabels: map[string]string{"role": ncName}})
			Expect(k8sClient.Create(ctx, nc)).To(Succeed())

			podName := uniqueName("pod")
			pod := makePod(podName, "default", map[string]string{"role": ncName})
			Expect(k8sClient.Create(ctx, pod)).To(Succeed())
			setPodIP(pod, "10.244.3.20")

			nprrN := "default-" + podName + "-" + ncName
			eventually(func() bool { return nprrExists(nprrN) })

			Expect(k8sClient.Delete(ctx, nc)).To(Succeed())

			eventually(func() bool {
				nprr := getNPRR(nprrN)
				return nprr != nil && nprr.Status.DeletionGracePeriodExpiry != nil
			})
		})

		It("updates CIDRs in BPF when NATConfig externalIPPool changes", func() {
			oldExtCIDR := "203.0.114.24/30"
			newExtCIDR := "203.0.114.28/30"
			nc := makeNATConfig(uniqueName("nc"), []string{"10.26.0.0/24"}, []string{oldExtCIDR},
				metav1.LabelSelector{})
			Expect(k8sClient.Create(ctx, nc)).To(Succeed())

			eventually(func() bool { return mockLPM.hasAddedExtIP(oldExtCIDR) })

			Eventually(func() error {
				var current v1alpha1.NATConfig
				if err := k8sClient.Get(ctx, client.ObjectKey{Name: nc.Name}, &current); err != nil {
					return err
				}
				current.Spec.ExternalIPPool = []string{newExtCIDR}
				return k8sClient.Update(ctx, &current)
			}, "5s", "100ms").Should(Succeed())

			eventually(func() bool { return mockLPM.hasAddedExtIP(newExtCIDR) })
			eventually(func() bool { return mockLPM.hasRemovedExtIP(oldExtCIDR) })
		})
	})
})
