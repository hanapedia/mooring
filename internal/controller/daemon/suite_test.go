package daemon_test

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	v1alpha1 "github.com/hanapedia/mooring/api/v1alpha1"
	"github.com/hanapedia/mooring/internal/controller/daemon"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apimruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/fields"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

const testNodeName = "test-node"

var (
	testEnv       *envtest.Environment
	k8sClient     client.Client
	scheme        = apimruntime.NewScheme()
	ctx           context.Context
	cancel        context.CancelFunc
	counter       atomic.Int64
	mockTargetCIDR      *recordingTargetCIDRMap
	mockExtIPPool       *recordingExtIPPoolMap
	mockPortRangeLookup *recordingPortRangeLookupMap
	mockSnatConfig      *recordingSnatConfigMap
)

func TestControllers(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Daemon Controller Suite")
}

var _ = BeforeSuite(func() {
	ctrl.SetLogger(zap.New(zap.WriteTo(GinkgoWriter), zap.UseDevMode(true)))
	ctx, cancel = context.WithCancel(context.Background())

	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(v1alpha1.AddToScheme(scheme))

	_, filename, _, _ := runtime.Caller(0)
	// internal/controller/daemon → 3 levels up to project root
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

	mockTargetCIDR = &recordingTargetCIDRMap{}
	mockExtIPPool = &recordingExtIPPoolMap{}
	mockPortRangeLookup = &recordingPortRangeLookupMap{}
	mockSnatConfig = &recordingSnatConfigMap{}

	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:                 scheme,
		LeaderElection:         false,
		Metrics:                metricsserver.Options{BindAddress: "0"},
		HealthProbeBindAddress: "0",
		Cache: cache.Options{
			ByObject: map[client.Object]cache.ByObject{
				&corev1.Pod{}: {
					Field: fields.OneTermEqualSelector("spec.nodeName", testNodeName),
				},
				&v1alpha1.NATPortRangeRequest{}: {
					Field: fields.OneTermEqualSelector("spec.nodeName", testNodeName),
				},
			},
		},
	})
	Expect(err).NotTo(HaveOccurred())

	Expect((&daemon.PodReconciler{
		Client:   mgr.GetClient(),
		NodeName: testNodeName,
	}).SetupWithManager(mgr)).To(Succeed())

	Expect((&daemon.NPRRReconciler{
		Client:   mgr.GetClient(),
		NodeName: testNodeName,
	}).SetupWithManager(mgr)).To(Succeed())

	Expect(daemon.NewNATConfigReconciler(mgr.GetClient(), mockTargetCIDR, mockExtIPPool).SetupWithManager(mgr)).To(Succeed())

	Expect(daemon.NewNATPortRangeSyncReconciler(mgr.GetClient(), testNodeName, mockPortRangeLookup, mockSnatConfig).SetupWithManager(mgr)).To(Succeed())

	go func() {
		defer GinkgoRecover()
		Expect(mgr.Start(ctx)).To(Succeed())
	}()
})

var _ = AfterSuite(func() {
	cancel()
	Expect(testEnv.Stop()).To(Succeed())
})

// --- helpers ---

func uniqueName(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, counter.Add(1))
}

func makeNATConfig(name string, targetCIDRs, extPool []string, sel metav1.LabelSelector) *v1alpha1.NATConfig {
	return &v1alpha1.NATConfig{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: v1alpha1.NATConfigSpec{
			ExternalIPPool: extPool,
			PortRangeSize:  100,
			TargetCIDRs:    targetCIDRs,
			PodSelector:    sel,
		},
	}
}

func makePod(name, namespace string, labels map[string]string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    labels,
		},
		Spec: corev1.PodSpec{
			NodeName: testNodeName,
			Containers: []corev1.Container{{
				Name:  "c",
				Image: "pause",
			}},
		},
	}
}

func setPodIP(pod *corev1.Pod, ip string) {
	pod.Status.PodIP = ip
	ExpectWithOffset(1, k8sClient.Status().Update(ctx, pod)).To(Succeed())
}

func getNPRR(name string) *v1alpha1.NATPortRangeRequest {
	var nprr v1alpha1.NATPortRangeRequest
	if err := k8sClient.Get(ctx, client.ObjectKey{Name: name}, &nprr); err != nil {
		return nil
	}
	return &nprr
}

func nprrExists(name string) bool { return getNPRR(name) != nil }

func eventually(fn func() bool) {
	EventuallyWithOffset(1, fn, 10*time.Second, 100*time.Millisecond).Should(BeTrue())
}

func consistently(fn func() bool) {
	ConsistentlyWithOffset(1, fn, 2*time.Second, 200*time.Millisecond).Should(BeTrue())
}

// --- mock BPF implementations (one type per BPF map) ---

type recordingTargetCIDRMap struct {
	mu      sync.Mutex
	added   []string
	removed []string
}

func (m *recordingTargetCIDRMap) Add(cidr *net.IPNet) error {
	m.mu.Lock(); defer m.mu.Unlock()
	m.added = append(m.added, cidr.String())
	return nil
}
func (m *recordingTargetCIDRMap) Remove(cidr *net.IPNet) error {
	m.mu.Lock(); defer m.mu.Unlock()
	m.removed = append(m.removed, cidr.String())
	return nil
}
func (m *recordingTargetCIDRMap) hasAdded(cidr string) bool {
	m.mu.Lock(); defer m.mu.Unlock()
	return slices.Contains(m.added, cidr)
}
func (m *recordingTargetCIDRMap) hasRemoved(cidr string) bool {
	m.mu.Lock(); defer m.mu.Unlock()
	return slices.Contains(m.removed, cidr)
}

type recordingExtIPPoolMap struct {
	mu      sync.Mutex
	added   []string
	removed []string
}

func (m *recordingExtIPPoolMap) Add(cidr *net.IPNet) error {
	m.mu.Lock(); defer m.mu.Unlock()
	m.added = append(m.added, cidr.String())
	return nil
}
func (m *recordingExtIPPoolMap) Remove(cidr *net.IPNet) error {
	m.mu.Lock(); defer m.mu.Unlock()
	m.removed = append(m.removed, cidr.String())
	return nil
}
func (m *recordingExtIPPoolMap) hasAdded(cidr string) bool {
	m.mu.Lock(); defer m.mu.Unlock()
	return slices.Contains(m.added, cidr)
}
func (m *recordingExtIPPoolMap) hasRemoved(cidr string) bool {
	m.mu.Lock(); defer m.mu.Unlock()
	return slices.Contains(m.removed, cidr)
}

type portRangeCall struct {
	extIP, podIP       string
	portStart, portEnd uint16
	proto              uint8
}

type recordingPortRangeLookupMap struct {
	mu          sync.Mutex
	addCalls    []portRangeCall
	removeCalls []portRangeCall
}

func (m *recordingPortRangeLookupMap) Add(extIP, podIP net.IP, portStart, portEnd uint16, proto uint8) error {
	m.mu.Lock(); defer m.mu.Unlock()
	m.addCalls = append(m.addCalls, portRangeCall{extIP.String(), podIP.String(), portStart, portEnd, proto})
	return nil
}
func (m *recordingPortRangeLookupMap) Remove(extIP, podIP net.IP, portStart, portEnd uint16, proto uint8) error {
	m.mu.Lock(); defer m.mu.Unlock()
	m.removeCalls = append(m.removeCalls, portRangeCall{extIP.String(), podIP.String(), portStart, portEnd, proto})
	return nil
}
func (m *recordingPortRangeLookupMap) hasAdded(extIP, podIP string, portStart, portEnd uint16, proto uint8) bool {
	m.mu.Lock(); defer m.mu.Unlock()
	for _, c := range m.addCalls {
		if c.extIP == extIP && c.podIP == podIP && c.portStart == portStart && c.portEnd == portEnd && c.proto == proto {
			return true
		}
	}
	return false
}
func (m *recordingPortRangeLookupMap) hasRemoved(extIP, podIP string, portStart, portEnd uint16, proto uint8) bool {
	m.mu.Lock(); defer m.mu.Unlock()
	for _, c := range m.removeCalls {
		if c.extIP == extIP && c.podIP == podIP && c.portStart == portStart && c.portEnd == portEnd && c.proto == proto {
			return true
		}
	}
	return false
}

type snatCall struct{ podIP, extIP, targetCIDR string }
type removeSnatCall struct{ podIP, targetCIDR string }

type recordingSnatConfigMap struct {
	mu          sync.Mutex
	upsertCalls []snatCall
	removeCalls []removeSnatCall
}

func (m *recordingSnatConfigMap) Upsert(podIP net.IP, targetCIDR *net.IPNet, extIP net.IP, portStart, portEnd uint16) error {
	m.mu.Lock(); defer m.mu.Unlock()
	m.upsertCalls = append(m.upsertCalls, snatCall{podIP.String(), extIP.String(), targetCIDR.String()})
	return nil
}
func (m *recordingSnatConfigMap) RemoveAllocs(podIP net.IP, targetCIDR *net.IPNet, extIPs []net.IP) error {
	m.mu.Lock(); defer m.mu.Unlock()
	m.removeCalls = append(m.removeCalls, removeSnatCall{podIP.String(), targetCIDR.String()})
	return nil
}
func (m *recordingSnatConfigMap) hasUpserted(podIP, extIP string) bool {
	m.mu.Lock(); defer m.mu.Unlock()
	for _, c := range m.upsertCalls {
		if c.podIP == podIP && c.extIP == extIP { return true }
	}
	return false
}
func (m *recordingSnatConfigMap) hasRemoved(podIP string) bool {
	m.mu.Lock(); defer m.mu.Unlock()
	for _, c := range m.removeCalls {
		if c.podIP == podIP { return true }
	}
	return false
}
