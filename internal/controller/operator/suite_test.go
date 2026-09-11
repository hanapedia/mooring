package operator_test

import (
	"context"
	"fmt"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	v1alpha1 "github.com/hanapedia/mooring/api/v1alpha1"
	"github.com/hanapedia/mooring/internal/controller/operator"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apimruntime "k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

var (
	testEnv   *envtest.Environment
	k8sClient client.Client
	scheme    = apimruntime.NewScheme()
	ctx       context.Context
	cancel    context.CancelFunc
	counter   atomic.Int64
)

func TestControllers(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Operator Controller Suite")
}

var _ = BeforeSuite(func() {
	ctrl.SetLogger(zap.New(zap.WriteTo(GinkgoWriter), zap.UseDevMode(true)))
	ctx, cancel = context.WithCancel(context.Background())

	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(v1alpha1.AddToScheme(scheme))

	_, filename, _, _ := runtime.Caller(0)
	// internal/controller/operator → 3 levels up to project root
	projectRoot := filepath.Join(filepath.Dir(filename), "..", "..", "..")
	crdDir := filepath.Join(projectRoot, "manifests", "crds")

	testEnv = &envtest.Environment{
		CRDDirectoryPaths:     []string{crdDir},
		ErrorIfCRDPathMissing: true,
	}
	cfg, err := testEnv.Start()
	Expect(err).NotTo(HaveOccurred())
	Expect(cfg).NotTo(BeNil())

	k8sClient, err = client.New(cfg, client.Options{Scheme: scheme})
	Expect(err).NotTo(HaveOccurred())

	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:                 scheme,
		LeaderElection:         false,
		Metrics:                metricsserver.Options{BindAddress: "0"},
		HealthProbeBindAddress: "0",
	})
	Expect(err).NotTo(HaveOccurred())

	registry := operator.NewAllocatorRegistry()

	Expect(mgr.Add(&operator.ReconstructionRunnable{
		Client:   mgr.GetClient(),
		Registry: registry,
	})).To(Succeed())

	Expect((&operator.NATPortRangeRequestReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Registry: registry,
	}).SetupWithManager(mgr)).To(Succeed())

	Expect((&operator.NATPortRangeReconciler{
		Client:   mgr.GetClient(),
		Registry: registry,
	}).SetupWithManager(mgr)).To(Succeed())

	Expect((&operator.NATConfigReconciler{
		Client:   mgr.GetClient(),
		Registry: registry,
	}).SetupWithManager(mgr)).To(Succeed())

	go func() {
		defer GinkgoRecover()
		Expect(mgr.Start(ctx)).To(Succeed())
	}()
})

var _ = AfterSuite(func() {
	cancel()
	Expect(testEnv.Stop()).To(Succeed())
})

// uniqueName returns a unique resource name safe for use within a single test run.
func uniqueName(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, counter.Add(1))
}

// makeNATConfig creates a NATConfig with the given name, CIDR pool, and block size.
// TargetCIDRs and PodSelector are set to minimal non-empty values to satisfy CRD validation.
func makeNATConfig(name string, cidrs []string, blockSize int32) *v1alpha1.NATConfig {
	return &v1alpha1.NATConfig{
		ObjectMeta: ctrl.ObjectMeta{Name: name},
		Spec: v1alpha1.NATConfigSpec{
			ExternalIPPool: cidrs,
			PortRangeSize:  blockSize,
			TargetCIDRs:    []string{"0.0.0.0/0"},
			PodSelector:    metav1.LabelSelector{},
		},
	}
}

// makeNPRR creates a NATPortRangeRequest with the given name and NATConfig reference.
// PodIP is derived from the counter embedded in the name so each pod is unique.
func makeNPRR(name, natConfig string, portRangeCount *int32) *v1alpha1.NATPortRangeRequest {
	// Extract the trailing number from "prefix-N" as the last octet (mod 254, 1-based).
	n := counter.Load() % 254
	podIP := fmt.Sprintf("10.0.0.%d", n+1)
	return &v1alpha1.NATPortRangeRequest{
		ObjectMeta: ctrl.ObjectMeta{Name: name},
		Spec: v1alpha1.NATPortRangeRequestSpec{
			PodName:        "pod-" + name,
			PodNamespace:   "default",
			PodIP:          podIP,
			NodeName:       "node-1",
			NATConfig:      natConfig,
			PortRangeCount: portRangeCount,
		},
	}
}

// ptr32 is a convenience helper for *int32 literals.
func ptr32(v int32) *int32 { return &v }

// eventually polls the given function until it returns true or a 10s timeout elapses.
// Uses Gomega's Eventually under the hood so assertion failures are reported properly.
func eventually(fn func() bool) {
	Eventually(fn, 10*time.Second, 100*time.Millisecond).Should(BeTrue())
}

// getNPR fetches the NATPortRange with the given name, returning nil if not found.
func getNPR(name string) *v1alpha1.NATPortRange {
	var npr v1alpha1.NATPortRange
	if err := k8sClient.Get(ctx, client.ObjectKey{Name: name}, &npr); err != nil {
		return nil
	}
	return &npr
}

// checkNonOverlapping verifies that no two PortAllocations in the list share the same
// PortStart value, which would cause a NAT collision for the same pod.
func checkNonOverlapping(allocs []v1alpha1.PortAllocation) {
	seen := make(map[int32]string)
	for _, a := range allocs {
		if prev, ok := seen[a.PortStart]; ok {
			Fail(fmt.Sprintf("duplicate PortStart %d: IPs %s and %s", a.PortStart, prev, a.ExternalIP))
		}
		seen[a.PortStart] = a.ExternalIP
	}
}
