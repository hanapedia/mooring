package daemon

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	v1alpha1 "github.com/hanapedia/mooring/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const natConfigIndexField = ".spec.natConfig"

type NATConfigReconciler struct {
	client.Client
	NodeName string
	BPF      LPMBPF

	mu            sync.Mutex
	ncTargetCIDRs map[string][]string // ncName → CIDRs last written to target_cidrs
	ncExtIPCIDRs  map[string][]string // ncName → CIDRs last written to ext_ip_pool
}

func NewNATConfigReconciler(c client.Client, nodeName string, bpf LPMBPF) *NATConfigReconciler {
	return &NATConfigReconciler{
		Client:        c,
		NodeName:      nodeName,
		BPF:           bpf,
		ncTargetCIDRs: make(map[string][]string),
		ncExtIPCIDRs:  make(map[string][]string),
	}
}

func (r *NATConfigReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var nc v1alpha1.NATConfig
	err := r.Get(ctx, req.NamespacedName, &nc)
	deleted := apierrors.IsNotFound(err)
	if err != nil && !deleted {
		return ctrl.Result{}, err
	}

	var desiredTargetCIDRs, desiredExtIPCIDRs []string
	if !deleted {
		desiredTargetCIDRs = nc.Spec.TargetCIDRs
		desiredExtIPCIDRs = nc.Spec.ExternalIPPool
	}

	if err := r.syncBPFMaps(req.Name, desiredTargetCIDRs, desiredExtIPCIDRs); err != nil {
		return ctrl.Result{}, err
	}

	var podSelector *metav1.LabelSelector
	if !deleted {
		podSelector = &nc.Spec.PodSelector
	}
	return r.reconcileNPRRs(ctx, req.Name, deleted, podSelector)
}

func (r *NATConfigReconciler) syncBPFMaps(ncName string, desiredTargetCIDRs, desiredExtIPCIDRs []string) error {
	r.mu.Lock()
	oldTarget := r.ncTargetCIDRs[ncName]
	oldExtIP := r.ncExtIPCIDRs[ncName]
	r.mu.Unlock()

	if err := r.applyLPMDiff(ncName, oldTarget, desiredTargetCIDRs, r.ncTargetCIDRs, r.BPF.AddTargetCIDR, r.BPF.RemoveTargetCIDR); err != nil {
		return fmt.Errorf("target_cidrs: %w", err)
	}
	if err := r.applyLPMDiff(ncName, oldExtIP, desiredExtIPCIDRs, r.ncExtIPCIDRs, r.BPF.AddExtIP, r.BPF.RemoveExtIP); err != nil {
		return fmt.Errorf("ext_ip_pool: %w", err)
	}
	return nil
}

// applyLPMDiff adds newly desired CIDRs, updates the in-memory tracking, then
// removes dropped CIDRs that are no longer referenced by any NATConfig.
func (r *NATConfigReconciler) applyLPMDiff(
	ncName string,
	oldCIDRs, newCIDRs []string,
	tracking map[string][]string,
	add func(*net.IPNet) error,
	remove func(*net.IPNet) error,
) error {
	oldSet := cidrSet(oldCIDRs)
	newSet := cidrSet(newCIDRs)

	for cidr := range newSet {
		if _, ok := oldSet[cidr]; ok {
			continue
		}
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("parse %s: %w", cidr, err)
		}
		if err := add(ipNet); err != nil {
			return err
		}
	}

	r.mu.Lock()
	tracking[ncName] = newCIDRs
	r.mu.Unlock()

	for cidr := range oldSet {
		if _, ok := newSet[cidr]; ok {
			continue
		}
		if r.cidrUsedByOther(ncName, cidr, tracking) {
			continue
		}
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("parse %s: %w", cidr, err)
		}
		if err := remove(ipNet); err != nil {
			return err
		}
	}
	return nil
}

func (r *NATConfigReconciler) cidrUsedByOther(ncName, cidr string, tracking map[string][]string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for name, cidrs := range tracking {
		if name == ncName {
			continue
		}
		for _, c := range cidrs {
			if c == cidr {
				return true
			}
		}
	}
	return false
}

func (r *NATConfigReconciler) reconcileNPRRs(
	ctx context.Context,
	ncName string,
	deleted bool,
	podSelector *metav1.LabelSelector,
) (ctrl.Result, error) {
	var nprrList v1alpha1.NATPortRangeRequestList
	if err := r.List(ctx, &nprrList, client.MatchingFields{natConfigIndexField: ncName}); err != nil {
		return ctrl.Result{}, err
	}

	if deleted {
		for i := range nprrList.Items {
			nprr := &nprrList.Items[i]
			if !nprr.DeletionTimestamp.IsZero() || nprr.Status.DeletionGracePeriodExpiry != nil {
				continue
			}
			expiry := metav1.NewTime(time.Now().Add(deletionGracePeriod))
			nprr.Status.DeletionGracePeriodExpiry = &expiry
			if err := r.Status().Update(ctx, nprr); err != nil && !apierrors.IsConflict(err) {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}

	// Build previously-matching set from existing NPRRs (key: podNamespace/podName).
	prevMatching := make(map[string]*v1alpha1.NATPortRangeRequest, len(nprrList.Items))
	for i := range nprrList.Items {
		nprr := &nprrList.Items[i]
		prevMatching[nprr.Spec.PodNamespace+"/"+nprr.Spec.PodName] = nprr
	}

	sel, err := metav1.LabelSelectorAsSelector(podSelector)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("invalid podSelector: %w", err)
	}

	// List local pods (cache is already field-filtered to this node).
	var pods corev1.PodList
	if err := r.List(ctx, &pods); err != nil {
		return ctrl.Result{}, err
	}

	currMatching := make(map[string]corev1.Pod)
	for _, pod := range pods.Items {
		if pod.Status.PodIP != "" && pod.DeletionTimestamp.IsZero() && sel.Matches(labels.Set(pod.Labels)) {
			currMatching[pod.Namespace+"/"+pod.Name] = pod
		}
	}

	for identity, pod := range currMatching {
		if _, ok := prevMatching[identity]; ok {
			continue
		}
		nprr := &v1alpha1.NATPortRangeRequest{
			ObjectMeta: metav1.ObjectMeta{Name: nprrName(pod.Namespace, pod.Name, ncName)},
			Spec: v1alpha1.NATPortRangeRequestSpec{
				PodName:      pod.Name,
				PodNamespace: pod.Namespace,
				PodIP:        pod.Status.PodIP,
				NodeName:     pod.Spec.NodeName,
				NATConfig:    ncName,
			},
		}
		if err := r.Create(ctx, nprr); err != nil && !apierrors.IsAlreadyExists(err) {
			return ctrl.Result{}, err
		}
	}

	for identity, nprr := range prevMatching {
		if !nprr.DeletionTimestamp.IsZero() || nprr.Status.DeletionGracePeriodExpiry != nil {
			continue
		}
		if _, ok := currMatching[identity]; ok {
			continue
		}
		expiry := metav1.NewTime(time.Now().Add(deletionGracePeriod))
		nprr.Status.DeletionGracePeriodExpiry = &expiry
		if err := r.Status().Update(ctx, nprr); err != nil && !apierrors.IsConflict(err) {
			return ctrl.Result{}, err
		}
	}

	return ctrl.Result{}, nil
}

func (r *NATConfigReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := mgr.GetFieldIndexer().IndexField(
		context.Background(),
		&v1alpha1.NATPortRangeRequest{},
		natConfigIndexField,
		func(obj client.Object) []string {
			nprr := obj.(*v1alpha1.NATPortRangeRequest)
			return []string{nprr.Spec.NATConfig}
		},
	); err != nil {
		return fmt.Errorf("index NATPortRangeRequest %s: %w", natConfigIndexField, err)
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.NATConfig{}).
		Complete(r)
}

func cidrSet(cidrs []string) map[string]struct{} {
	m := make(map[string]struct{}, len(cidrs))
	for _, c := range cidrs {
		m[c] = struct{}{}
	}
	return m
}
