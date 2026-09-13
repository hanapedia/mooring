package daemon_test

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	v1alpha1 "github.com/hanapedia/mooring/api/v1alpha1"
	"github.com/hanapedia/mooring/internal/controller/daemon"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var _ = Describe("NPRR controller", func() {

	makeNPRR := func(name, nodeName string) *v1alpha1.NATPortRangeRequest {
		return &v1alpha1.NATPortRangeRequest{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec: v1alpha1.NATPortRangeRequestSpec{
				PodName:      "pod-" + name,
				PodNamespace: "default",
				PodIP:        "10.244.2.1",
				NodeName:     nodeName,
				NATConfig:    "some-nc",
			},
		}
	}

	Describe("deletion when expiry has passed", func() {
		It("deletes an NPRR whose DeletionGracePeriodExpiry is in the past", func() {
			nprr := makeNPRR(uniqueName("nprr"), testNodeName)
			Expect(k8sClient.Create(ctx, nprr)).To(Succeed())

			past := metav1.NewTime(time.Now().Add(-1 * time.Second))
			nprr.Status.DeletionGracePeriodExpiry = &past
			Expect(k8sClient.Status().Update(ctx, nprr)).To(Succeed())

			Eventually(func() bool {
				var cur v1alpha1.NATPortRangeRequest
				return apierrors.IsNotFound(k8sClient.Get(ctx, client.ObjectKey{Name: nprr.Name}, &cur))
			}, 10*time.Second, 100*time.Millisecond).Should(BeTrue())
		})

		It("requeues and deletes once a future expiry elapses", func() {
			nprr := makeNPRR(uniqueName("nprr"), testNodeName)
			Expect(k8sClient.Create(ctx, nprr)).To(Succeed())

			// metav1.Time serializes to RFC3339 (1s granularity). Add 3s and
			// truncate to seconds so the stored value is at least 2s in the future
			// regardless of when within the current second we run.
			future := metav1.NewTime(time.Now().Truncate(time.Second).Add(3 * time.Second))
			nprr.Status.DeletionGracePeriodExpiry = &future
			Expect(k8sClient.Status().Update(ctx, nprr)).To(Succeed())

			// Should still exist well before the expiry.
			Consistently(func() bool {
				var cur v1alpha1.NATPortRangeRequest
				return k8sClient.Get(ctx, client.ObjectKey{Name: nprr.Name}, &cur) == nil
			}, "1s", "100ms").Should(BeTrue())

			// Should be deleted after the expiry window.
			Eventually(func() bool {
				var cur v1alpha1.NATPortRangeRequest
				return apierrors.IsNotFound(k8sClient.Get(ctx, client.ObjectKey{Name: nprr.Name}, &cur))
			}, 5*time.Second, 100*time.Millisecond).Should(BeTrue())
		})
	})

	Describe("NPRRStartupSyncer", func() {
		It("sets DeletionGracePeriodExpiry on an NPRR whose pod is gone", func() {
			// Create an NPRR directly referencing a pod that does not exist,
			// simulating the orphan-after-restart scenario.
			nprr := makeNPRR("ghost-"+uniqueName("nprr"), testNodeName)
			nprr.Spec.PodName = "ghost-pod"
			nprr.Spec.PodNamespace = "default"
			Expect(k8sClient.Create(ctx, nprr)).To(Succeed())

			syncer := &daemon.NPRRStartupSyncer{Client: k8sClient, NodeName: testNodeName}
			Expect(syncer.Sync(ctx)).To(Succeed())

			var cur v1alpha1.NATPortRangeRequest
			Expect(k8sClient.Get(ctx, client.ObjectKey{Name: nprr.Name}, &cur)).To(Succeed())
			Expect(cur.Status.DeletionGracePeriodExpiry).NotTo(BeNil())
		})

		It("does not touch an NPRR whose pod is still alive", func() {
			// Use a pod that exists in the test namespace.
			pod := makePod(uniqueName("pod"), "default", nil)
			Expect(k8sClient.Create(ctx, pod)).To(Succeed())

			nprr := makeNPRR(uniqueName("nprr"), testNodeName)
			nprr.Spec.PodName = pod.Name
			nprr.Spec.PodNamespace = pod.Namespace
			Expect(k8sClient.Create(ctx, nprr)).To(Succeed())

			syncer := &daemon.NPRRStartupSyncer{Client: k8sClient, NodeName: testNodeName}
			Expect(syncer.Sync(ctx)).To(Succeed())

			var cur v1alpha1.NATPortRangeRequest
			Expect(k8sClient.Get(ctx, client.ObjectKey{Name: nprr.Name}, &cur)).To(Succeed())
			Expect(cur.Status.DeletionGracePeriodExpiry).To(BeNil())
		})

		It("skips NPRRs assigned to a different node", func() {
			nprr := makeNPRR(uniqueName("nprr"), "other-node")
			nprr.Spec.PodName = "ghost-pod"
			nprr.Spec.PodNamespace = "default"
			Expect(k8sClient.Create(ctx, nprr)).To(Succeed())

			syncer := &daemon.NPRRStartupSyncer{Client: k8sClient, NodeName: testNodeName}
			Expect(syncer.Sync(ctx)).To(Succeed())

			var cur v1alpha1.NATPortRangeRequest
			Expect(k8sClient.Get(ctx, client.ObjectKey{Name: nprr.Name}, &cur)).To(Succeed())
			Expect(cur.Status.DeletionGracePeriodExpiry).To(BeNil())

			// Cleanup (other-node NPRRs won't be auto-deleted by the reconciler).
			_ = k8sClient.Delete(ctx, nprr)
		})
	})

	Describe("no deletion when conditions are not met", func() {
		It("does not delete an NPRR on a different node even if expiry has passed", func() {
			nprr := makeNPRR(uniqueName("nprr"), "other-node")
			Expect(k8sClient.Create(ctx, nprr)).To(Succeed())

			past := metav1.NewTime(time.Now().Add(-1 * time.Second))
			nprr.Status.DeletionGracePeriodExpiry = &past
			Expect(k8sClient.Status().Update(ctx, nprr)).To(Succeed())

			Consistently(func() bool {
				var cur v1alpha1.NATPortRangeRequest
				return k8sClient.Get(ctx, client.ObjectKey{Name: nprr.Name}, &cur) == nil
			}, 2*time.Second, 200*time.Millisecond).Should(BeTrue())

			// Cleanup.
			_ = k8sClient.Delete(ctx, nprr)
		})

		It("does not delete an NPRR that has no DeletionGracePeriodExpiry", func() {
			nprr := makeNPRR(uniqueName("nprr"), testNodeName)
			Expect(k8sClient.Create(ctx, nprr)).To(Succeed())

			Consistently(func() bool {
				var cur v1alpha1.NATPortRangeRequest
				return k8sClient.Get(ctx, client.ObjectKey{Name: nprr.Name}, &cur) == nil
			}, 2*time.Second, 200*time.Millisecond).Should(BeTrue())

			// Cleanup.
			_ = k8sClient.Delete(ctx, nprr)
		})
	})
})
