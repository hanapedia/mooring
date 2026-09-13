package daemon_test

import (
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	v1alpha1 "github.com/hanapedia/mooring/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var _ = Describe("Pod controller", func() {

	Describe("NPRR creation", func() {
		It("creates an NPRR when a matching pod appears on this node", func() {
			ncName := uniqueName("nc")
			nc := makeNATConfig(ncName, []string{"10.11.0.0/24"}, []string{"203.0.113.0/30"},
				metav1.LabelSelector{MatchLabels: map[string]string{"app": ncName}})
			Expect(k8sClient.Create(ctx, nc)).To(Succeed())

			podName := uniqueName("pod")
			pod := makePod(podName, "default", map[string]string{"app": ncName})
			Expect(k8sClient.Create(ctx, pod)).To(Succeed())
			setPodIP(pod, "10.244.1.10")

			nprrN := "default-" + podName + "-" + ncName
			eventually(func() bool { return nprrExists(nprrN) })

			nprr := getNPRR(nprrN)
			Expect(nprr.Spec.PodName).To(Equal(podName))
			Expect(nprr.Spec.PodNamespace).To(Equal("default"))
			Expect(nprr.Spec.PodIP).To(Equal("10.244.1.10"))
			Expect(nprr.Spec.NodeName).To(Equal(testNodeName))
			Expect(nprr.Spec.NATConfig).To(Equal(ncName))
		})

		It("does not create an NPRR when no NATConfig matches the pod's labels", func() {
			podName := uniqueName("pod")
			pod := makePod(podName, "default", map[string]string{"app": "unmatched"})
			Expect(k8sClient.Create(ctx, pod)).To(Succeed())
			setPodIP(pod, "10.244.1.20")

			// Create a NC that does NOT match.
			ncName := uniqueName("nc")
			nc := makeNATConfig(ncName, []string{"10.12.0.0/24"}, []string{"203.0.113.4/30"},
				metav1.LabelSelector{MatchLabels: map[string]string{"app": ncName + "-other"}})
			Expect(k8sClient.Create(ctx, nc)).To(Succeed())

			nprrN := "default-" + podName + "-" + ncName
			consistently(func() bool { return !nprrExists(nprrN) })
		})
	})

	Describe("grace period on pod gone", func() {
		It("sets DeletionGracePeriodExpiry on NPRR when pod is fully deleted", func() {
			ncName := uniqueName("nc")
			nc := makeNATConfig(ncName, []string{"10.13.0.0/24"}, []string{"203.0.113.8/30"},
				metav1.LabelSelector{MatchLabels: map[string]string{"app": ncName}})
			Expect(k8sClient.Create(ctx, nc)).To(Succeed())

			podName := uniqueName("pod")
			pod := makePod(podName, "default", map[string]string{"app": ncName})
			Expect(k8sClient.Create(ctx, pod)).To(Succeed())
			setPodIP(pod, "10.244.1.30")

			nprrN := "default-" + podName + "-" + ncName
			eventually(func() bool { return nprrExists(nprrN) })

			Expect(k8sClient.Delete(ctx, pod)).To(Succeed())

			eventually(func() bool {
				nprr := getNPRR(nprrN)
				return nprr != nil && nprr.Status.DeletionGracePeriodExpiry != nil
			})
		})

		It("sets DeletionGracePeriodExpiry on NPRR when pod is terminating", func() {
			ncName := uniqueName("nc")
			nc := makeNATConfig(ncName, []string{"10.14.0.0/24"}, []string{"203.0.113.12/30"},
				metav1.LabelSelector{MatchLabels: map[string]string{"app": ncName}})
			Expect(k8sClient.Create(ctx, nc)).To(Succeed())

			podName := uniqueName("pod")
			pod := makePod(podName, "default", map[string]string{"app": ncName})
			// Finalizer keeps pod alive so DeletionTimestamp is set but pod stays.
			pod.Finalizers = []string{"test/keep"}
			Expect(k8sClient.Create(ctx, pod)).To(Succeed())
			setPodIP(pod, "10.244.1.40")

			nprrN := "default-" + podName + "-" + ncName
			eventually(func() bool { return nprrExists(nprrN) })

			Expect(k8sClient.Delete(ctx, pod)).To(Succeed())

			eventually(func() bool {
				nprr := getNPRR(nprrN)
				return nprr != nil && nprr.Status.DeletionGracePeriodExpiry != nil
			})

			// Remove pod finalizer to allow cleanup.
			Eventually(func() error {
				var cur corev1.Pod
				if err := k8sClient.Get(ctx, client.ObjectKey{Namespace: "default", Name: podName}, &cur); err != nil {
					return err
				}
				cur.Finalizers = nil
				return k8sClient.Update(ctx, &cur)
			}, "5s", "100ms").Should(Succeed())
		})
	})

	Describe("NATConfig selector change", func() {
		It("sets grace period on NPRR when podSelector stops matching", func() {
			ncName := uniqueName("nc")
			nc := makeNATConfig(ncName, []string{"10.15.0.0/24"}, []string{"203.0.113.16/30"},
				metav1.LabelSelector{MatchLabels: map[string]string{"app": ncName}})
			Expect(k8sClient.Create(ctx, nc)).To(Succeed())

			podName := uniqueName("pod")
			pod := makePod(podName, "default", map[string]string{"app": ncName})
			Expect(k8sClient.Create(ctx, pod)).To(Succeed())
			setPodIP(pod, "10.244.1.50")

			nprrN := "default-" + podName + "-" + ncName
			eventually(func() bool { return nprrExists(nprrN) })

			Eventually(func() error {
				var current v1alpha1.NATConfig
				if err := k8sClient.Get(ctx, client.ObjectKey{Name: ncName}, &current); err != nil {
					return err
				}
				current.Spec.PodSelector = metav1.LabelSelector{
					MatchLabels: map[string]string{"app": ncName + "-nomatch"},
				}
				return k8sClient.Update(ctx, &current)
			}, "5s", "100ms").Should(Succeed())

			eventually(func() bool {
				nprr := getNPRR(nprrN)
				return nprr != nil && nprr.Status.DeletionGracePeriodExpiry != nil
			})
		})

		It("clears a stale grace period when pod still matches", func() {
			ncName := uniqueName("nc")
			nc := makeNATConfig(ncName, []string{"10.16.0.0/24"}, []string{"203.0.113.20/30"},
				metav1.LabelSelector{MatchLabels: map[string]string{"team": ncName}})
			Expect(k8sClient.Create(ctx, nc)).To(Succeed())

			podName := uniqueName("pod")
			pod := makePod(podName, "default", map[string]string{"team": ncName})
			Expect(k8sClient.Create(ctx, pod)).To(Succeed())
			setPodIP(pod, "10.244.1.60")

			nprrN := "default-" + podName + "-" + ncName
			eventually(func() bool { return nprrExists(nprrN) })

			// Inject a stale grace period directly via the status subresource.
			staleExpiry := metav1.NewTime(time.Now().Add(10 * time.Minute))
			Eventually(func() error {
				nprr := getNPRR(nprrN)
				if nprr == nil {
					return fmt.Errorf("nprr not found")
				}
				nprr.Status.DeletionGracePeriodExpiry = &staleExpiry
				return k8sClient.Status().Update(ctx, nprr)
			}, "5s", "100ms").Should(Succeed())

			// Trigger reconcile of the pod by touching the NATConfig.
			Eventually(func() error {
				var current v1alpha1.NATConfig
				if err := k8sClient.Get(ctx, client.ObjectKey{Name: ncName}, &current); err != nil {
					return err
				}
				if current.Annotations == nil {
					current.Annotations = map[string]string{}
				}
				current.Annotations["touch"] = time.Now().String()
				return k8sClient.Update(ctx, &current)
			}, "5s", "100ms").Should(Succeed())

			// Pod still matches → grace period cleared.
			eventually(func() bool {
				nprr := getNPRR(nprrN)
				return nprr != nil && nprr.Status.DeletionGracePeriodExpiry == nil
			})
		})
	})
})
