package operator_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/hanapedia/mooring/internal/metrics"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

var _ = Describe("Metrics", func() {
	const blockSize = int32(100)

	It("updates natconfig ports_free/ports_total gauges as allocations happen", func() {
		extIP := "198.51.100.16"
		nc := makeNATConfig(uniqueName("nc-metrics"), []string{extIP + "/32"}, blockSize)
		Expect(k8sClient.Create(ctx, nc)).To(Succeed())

		eventually(func() bool {
			return testutil.ToFloat64(metrics.NATConfigPortsTotal.WithLabelValues(nc.Name, extIP)) == 64500
		})
		eventually(func() bool {
			return testutil.ToFloat64(metrics.NATConfigPortsFree.WithLabelValues(nc.Name, extIP)) == 64500
		})

		nprr := makeNPRR(uniqueName("nprr-metrics"), nc.Name, ptr32(1))
		Expect(k8sClient.Create(ctx, nprr)).To(Succeed())

		eventually(func() bool {
			return testutil.ToFloat64(metrics.NATConfigPortsFree.WithLabelValues(nc.Name, extIP)) == 64400
		})
	})

	It("sets the natportrange ports_allocated gauge and clears it once the NPR is finalized", func() {
		nc := makeNATConfig(uniqueName("nc-metrics"), []string{"198.51.100.20/32"}, blockSize)
		Expect(k8sClient.Create(ctx, nc)).To(Succeed())

		nprr := makeNPRR(uniqueName("nprr-metrics"), nc.Name, ptr32(1))
		Expect(k8sClient.Create(ctx, nprr)).To(Succeed())

		pod, ns, node := "pod-"+nprr.Name, "default", "node-1"

		eventually(func() bool {
			return getNPR(nprr.Name) != nil
		})
		eventually(func() bool {
			return testutil.ToFloat64(metrics.NATPortRangePortsAllocated.WithLabelValues(pod, ns, node, nc.Name)) == float64(blockSize)
		})

		Expect(k8sClient.Delete(ctx, nprr)).To(Succeed())
		Eventually(func() bool {
			return getNPR(nprr.Name) == nil
		}, "15s", "200ms").Should(BeTrue(), "NPR should be fully deleted once the finalizer is removed")

		// WithLabelValues recreates the series if it was deleted (default value 0),
		// or returns the still-live series with its old value if cleanup didn't run.
		Expect(testutil.ToFloat64(metrics.NATPortRangePortsAllocated.WithLabelValues(pod, ns, node, nc.Name))).To(Equal(0.0))
	})

	It("publishes _info rows for live NATConfig/NATPortRange/NATPortRangeRequest objects and clears them once deleted", func() {
		nc := makeNATConfig(uniqueName("nc-metrics"), []string{"198.51.100.28/32"}, blockSize)
		Expect(k8sClient.Create(ctx, nc)).To(Succeed())

		nprr := makeNPRR(uniqueName("nprr-metrics"), nc.Name, ptr32(1))
		Expect(k8sClient.Create(ctx, nprr)).To(Succeed())
		pod, ns, node := "pod-"+nprr.Name, "default", "node-1"

		eventually(func() bool {
			return getNPR(nprr.Name) != nil
		})

		eventually(func() bool {
			return testutil.ToFloat64(metrics.NATConfigInfo.WithLabelValues(nc.Name, "100")) == 1
		})
		eventually(func() bool {
			return testutil.ToFloat64(metrics.NATPortRangeInfo.WithLabelValues(pod, ns, node, nc.Name, "active")) == 1
		})
		eventually(func() bool {
			return testutil.ToFloat64(metrics.NATPortRangeRequestInfo.WithLabelValues(nprr.Name, pod, ns, node, nc.Name)) == 1
		})

		Expect(k8sClient.Delete(ctx, nprr)).To(Succeed())
		Eventually(func() bool {
			return getNPR(nprr.Name) == nil
		}, "15s", "200ms").Should(BeTrue(), "NPR should be fully deleted once the finalizer is removed")
		Expect(k8sClient.Delete(ctx, nc)).To(Succeed())

		// Each reconciler deletes its own row inline as soon as it observes the
		// object is gone (IsNotFound, or releaseAndFinalize for NPR), so
		// WithLabelValues recreating the series fresh at 0 confirms cleanup ran.
		eventually(func() bool {
			return testutil.ToFloat64(metrics.NATConfigInfo.WithLabelValues(nc.Name, "100")) == 0
		})
		eventually(func() bool {
			return testutil.ToFloat64(metrics.NATPortRangeInfo.WithLabelValues(pod, ns, node, nc.Name, "active")) == 0 &&
				testutil.ToFloat64(metrics.NATPortRangeInfo.WithLabelValues(pod, ns, node, nc.Name, "stale_pending_cleanup")) == 0
		})
		eventually(func() bool {
			return testutil.ToFloat64(metrics.NATPortRangeRequestInfo.WithLabelValues(nprr.Name, pod, ns, node, nc.Name)) == 0
		})
	})

	It("increments the port allocation failure counter when a NATConfig's pool is exhausted", func() {
		// PortRangeSize = the full usable port space, so totalBlocks == 1: the
		// second pod's allocation is guaranteed to fail.
		nc := makeNATConfig(uniqueName("nc-metrics"), []string{"198.51.100.24/32"}, 64512)
		Expect(k8sClient.Create(ctx, nc)).To(Succeed())

		first := makeNPRR(uniqueName("nprr-metrics"), nc.Name, ptr32(1))
		Expect(k8sClient.Create(ctx, first)).To(Succeed())
		eventually(func() bool {
			return getNPR(first.Name) != nil
		})

		second := makeNPRR(uniqueName("nprr-metrics"), nc.Name, ptr32(1))
		Expect(k8sClient.Create(ctx, second)).To(Succeed())

		eventually(func() bool {
			return testutil.ToFloat64(metrics.NATConfigPortAllocationFailuresTotal.WithLabelValues(nc.Name)) >= 1
		})
	})
})
