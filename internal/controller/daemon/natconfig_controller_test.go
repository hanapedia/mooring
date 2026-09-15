package daemon_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	v1alpha1 "github.com/hanapedia/mooring/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
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

	Describe("route advertisement", func() {
		It("advertises pool CIDRs on NATConfig creation", func() {
			extCIDR := "203.0.115.0/30"
			nc := makeNATConfig(uniqueName("nc"), []string{"10.30.0.0/24"}, []string{extCIDR},
				metav1.LabelSelector{})
			Expect(k8sClient.Create(ctx, nc)).To(Succeed())

			eventually(func() bool { return mockRouteAdvertiser.hasAdvertised(extCIDR) })
		})

		It("withdraws pool CIDRs on NATConfig deletion", func() {
			extCIDR := "203.0.115.4/30"
			nc := makeNATConfig(uniqueName("nc"), []string{"10.31.0.0/24"}, []string{extCIDR},
				metav1.LabelSelector{})
			Expect(k8sClient.Create(ctx, nc)).To(Succeed())
			eventually(func() bool { return mockRouteAdvertiser.hasAdvertised(extCIDR) })

			Expect(k8sClient.Delete(ctx, nc)).To(Succeed())

			eventually(func() bool { return mockRouteAdvertiser.hasWithdrawn(extCIDR) })
		})

		It("does not withdraw a CIDR while another NATConfig still references it", func() {
			sharedCIDR := "203.0.115.8/30"
			sentinelCIDR := "203.0.115.12/30" // unique to nc1; withdrawal proves nc1 was reconciled

			nc1 := makeNATConfig(uniqueName("nc"), []string{"10.32.0.0/24"}, []string{sharedCIDR, sentinelCIDR},
				metav1.LabelSelector{})
			nc2 := makeNATConfig(uniqueName("nc"), []string{"10.32.1.0/24"}, []string{sharedCIDR},
				metav1.LabelSelector{})
			Expect(k8sClient.Create(ctx, nc1)).To(Succeed())
			Expect(k8sClient.Create(ctx, nc2)).To(Succeed())

			eventually(func() bool { return mockRouteAdvertiser.hasAdvertised(sharedCIDR) })

			Expect(k8sClient.Delete(ctx, nc1)).To(Succeed())
			eventually(func() bool { return mockRouteAdvertiser.hasWithdrawn(sentinelCIDR) })

			Expect(mockRouteAdvertiser.hasWithdrawn(sharedCIDR)).To(BeFalse())

			Expect(k8sClient.Delete(ctx, nc2)).To(Succeed())
			eventually(func() bool { return mockRouteAdvertiser.hasWithdrawn(sharedCIDR) })
		})

		It("advertises new CIDRs and withdraws old ones when externalIPPool changes", func() {
			oldCIDR := "203.0.115.16/30"
			newCIDR := "203.0.115.20/30"
			nc := makeNATConfig(uniqueName("nc"), []string{"10.33.0.0/24"}, []string{oldCIDR},
				metav1.LabelSelector{})
			Expect(k8sClient.Create(ctx, nc)).To(Succeed())
			eventually(func() bool { return mockRouteAdvertiser.hasAdvertised(oldCIDR) })

			Eventually(func() error {
				var current v1alpha1.NATConfig
				if err := k8sClient.Get(ctx, client.ObjectKey{Name: nc.Name}, &current); err != nil {
					return err
				}
				current.Spec.ExternalIPPool = []string{newCIDR}
				return k8sClient.Update(ctx, &current)
			}, "5s", "100ms").Should(Succeed())

			eventually(func() bool { return mockRouteAdvertiser.hasAdvertised(newCIDR) })
			eventually(func() bool { return mockRouteAdvertiser.hasWithdrawn(oldCIDR) })
		})
	})

	Describe("node selector filtering", func() {
		It("does not advertise routes when nodeSelector does not match node labels", func() {
			uniqueKey := uniqueName("ns-key")
			extCIDR := "203.0.120.0/30"
			nc := &v1alpha1.NATConfig{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("nc")},
				Spec: v1alpha1.NATConfigSpec{
					ExternalIPPool: []string{extCIDR},
					PortRangeSize:  100,
					TargetCIDRs:    []string{"10.40.0.0/24"},
					PodSelector:    metav1.LabelSelector{},
					NodeSelector:   &metav1.LabelSelector{MatchLabels: map[string]string{uniqueKey: "true"}},
				},
			}
			Expect(k8sClient.Create(ctx, nc)).To(Succeed())
			eventually(func() bool { return mockExtIPPool.hasAdded(extCIDR) })
			consistently(func() bool { return !mockRouteAdvertiser.hasAdvertised(extCIDR) })
		})

		It("advertises routes when nodeSelector matches node labels", func() {
			uniqueKey := uniqueName("ns-key")

			var node corev1.Node
			Expect(k8sClient.Get(ctx, client.ObjectKey{Name: testNodeName}, &node)).To(Succeed())
			if node.Labels == nil {
				node.Labels = map[string]string{}
			}
			node.Labels[uniqueKey] = "true"
			Expect(k8sClient.Update(ctx, &node)).To(Succeed())

			extCIDR := "203.0.121.0/30"
			nc := &v1alpha1.NATConfig{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("nc")},
				Spec: v1alpha1.NATConfigSpec{
					ExternalIPPool: []string{extCIDR},
					PortRangeSize:  100,
					TargetCIDRs:    []string{"10.41.0.0/24"},
					PodSelector:    metav1.LabelSelector{},
					NodeSelector:   &metav1.LabelSelector{MatchLabels: map[string]string{uniqueKey: "true"}},
				},
			}
			Expect(k8sClient.Create(ctx, nc)).To(Succeed())
			eventually(func() bool { return mockRouteAdvertiser.hasAdvertised(extCIDR) })
		})

		It("advertises routes when node labels are updated to match nodeSelector", func() {
			uniqueKey := uniqueName("ns-key")
			extCIDR := "203.0.122.0/30"
			nc := &v1alpha1.NATConfig{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("nc")},
				Spec: v1alpha1.NATConfigSpec{
					ExternalIPPool: []string{extCIDR},
					PortRangeSize:  100,
					TargetCIDRs:    []string{"10.42.0.0/24"},
					PodSelector:    metav1.LabelSelector{},
					NodeSelector:   &metav1.LabelSelector{MatchLabels: map[string]string{uniqueKey: "true"}},
				},
			}
			Expect(k8sClient.Create(ctx, nc)).To(Succeed())
			eventually(func() bool { return mockExtIPPool.hasAdded(extCIDR) })
			consistently(func() bool { return !mockRouteAdvertiser.hasAdvertised(extCIDR) })

			var node corev1.Node
			Expect(k8sClient.Get(ctx, client.ObjectKey{Name: testNodeName}, &node)).To(Succeed())
			if node.Labels == nil {
				node.Labels = map[string]string{}
			}
			node.Labels[uniqueKey] = "true"
			Expect(k8sClient.Update(ctx, &node)).To(Succeed())

			eventually(func() bool { return mockRouteAdvertiser.hasAdvertised(extCIDR) })
		})
	})
})
