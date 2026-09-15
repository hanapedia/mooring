package daemon

import (
	"context"
	"fmt"
	"net"
	"slices"
	"sync"

	v1alpha1 "github.com/hanapedia/mooring/api/v1alpha1"
	"github.com/hanapedia/mooring/internal/routing"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

type NATConfigReconciler struct {
	client.Client
	NodeName        string
	TargetCIDRs     TargetCIDRMap
	ExtIPPool       ExtIPPoolMap
	RouteAdvertiser routing.RouteAdvertiser

	mu                sync.Mutex
	ncTargetCIDRs     map[string][]string // ncName → CIDRs last written to target_cidrs
	ncExtIPCIDRs      map[string][]string // ncName → CIDRs last written to ext_ip_pool
	ncAdvertisedCIDRs map[string][]string // ncName → CIDRs currently advertised by this node
}

func NewNATConfigReconciler(c client.Client, nodeName string, targetCIDRs TargetCIDRMap, extIPPool ExtIPPoolMap, advertiser routing.RouteAdvertiser) *NATConfigReconciler {
	return &NATConfigReconciler{
		Client:            c,
		NodeName:          nodeName,
		TargetCIDRs:       targetCIDRs,
		ExtIPPool:         extIPPool,
		RouteAdvertiser:   advertiser,
		ncTargetCIDRs:     make(map[string][]string),
		ncExtIPCIDRs:      make(map[string][]string),
		ncAdvertisedCIDRs: make(map[string][]string),
	}
}

// Reconcile target cidr and ext ip cidr bpf maps against NATConfig
func (r *NATConfigReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var nc v1alpha1.NATConfig
	err := r.Get(ctx, req.NamespacedName, &nc)
	deleted := apierrors.IsNotFound(err)
	if err != nil && !deleted {
		return ctrl.Result{}, err
	}

	var desiredTargetCIDRs, desiredExtIPCIDRs, desiredRouteCIDRs []string
	if !deleted {
		desiredTargetCIDRs = nc.Spec.TargetCIDRs
		desiredExtIPCIDRs = nc.Spec.ExternalIPPool
		nodeMatches, err := r.nodeMatchesSelector(ctx, &nc)
		if err != nil {
			return ctrl.Result{}, err
		}
		if nodeMatches {
			desiredRouteCIDRs = nc.Spec.ExternalIPPool
		}
	}

	if err := r.syncBPFMaps(ctx, req.Name, desiredTargetCIDRs, desiredExtIPCIDRs, desiredRouteCIDRs); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

func (r *NATConfigReconciler) syncBPFMaps(ctx context.Context, ncName string, desiredTargetCIDRs, desiredExtIPCIDRs, desiredRouteCIDRs []string) error {
	r.mu.Lock()
	oldTarget := r.ncTargetCIDRs[ncName]
	oldExtIP := r.ncExtIPCIDRs[ncName]
	r.mu.Unlock()

	if err := r.applyLPMDiff(ncName, oldTarget, desiredTargetCIDRs, r.ncTargetCIDRs, r.TargetCIDRs.Add, r.TargetCIDRs.Remove); err != nil {
		return fmt.Errorf("target_cidrs: %w", err)
	}
	if err := r.applyLPMDiff(ncName, oldExtIP, desiredExtIPCIDRs, r.ncExtIPCIDRs, r.ExtIPPool.Add, r.ExtIPPool.Remove); err != nil {
		return fmt.Errorf("ext_ip_pool: %w", err)
	}
	if err := r.syncRoutes(ctx, ncName, desiredRouteCIDRs); err != nil {
		return fmt.Errorf("routes: %w", err)
	}
	return nil
}

// syncRoutes advertises newly added pool CIDRs and withdraws dropped CIDRs
// that are no longer referenced by any NATConfig. Tracking is kept in
// ncAdvertisedCIDRs, separate from the BPF map state, so that nodes excluded
// by NodeSelector can skip advertisement while still updating BPF maps.
func (r *NATConfigReconciler) syncRoutes(ctx context.Context, ncName string, newCIDRs []string) error {
	r.mu.Lock()
	oldCIDRs := r.ncAdvertisedCIDRs[ncName]
	r.mu.Unlock()

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
		if err := r.RouteAdvertiser.AdvertisePrefix(ctx, ipNet); err != nil {
			return fmt.Errorf("advertise %s: %w", cidr, err)
		}
	}

	// Update tracking before the withdrawal check mirrors applyLPMDiff so
	// cidrUsedByOther sees the correct final state.
	r.mu.Lock()
	r.ncAdvertisedCIDRs[ncName] = newCIDRs
	r.mu.Unlock()

	for cidr := range oldSet {
		if _, ok := newSet[cidr]; ok {
			continue
		}
		if r.cidrUsedByOther(ncName, cidr, r.ncAdvertisedCIDRs) {
			continue
		}
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("parse %s: %w", cidr, err)
		}
		if err := r.RouteAdvertiser.WithdrawPrefix(ctx, ipNet); err != nil {
			return fmt.Errorf("withdraw %s: %w", cidr, err)
		}
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
		if slices.Contains(cidrs, cidr) {
			return true
		}
	}
	return false
}

// nodeMatchesSelector returns true if the current node's labels match the
// NATConfig's NodeSelector. A nil NodeSelector matches all nodes.
func (r *NATConfigReconciler) nodeMatchesSelector(ctx context.Context, nc *v1alpha1.NATConfig) (bool, error) {
	if nc.Spec.NodeSelector == nil {
		return true, nil
	}
	var node corev1.Node
	if err := r.Get(ctx, types.NamespacedName{Name: r.NodeName}, &node); err != nil {
		return false, fmt.Errorf("get node %s: %w", r.NodeName, err)
	}
	sel, err := metav1.LabelSelectorAsSelector(nc.Spec.NodeSelector)
	if err != nil {
		return false, fmt.Errorf("parse nodeSelector: %w", err)
	}
	return sel.Matches(labels.Set(node.Labels)), nil
}

// nodeToNATConfigs enqueues all NATConfigs whenever the current node changes,
// so that NodeSelector-based advertisement can react to label updates.
func (r *NATConfigReconciler) nodeToNATConfigs(ctx context.Context, obj client.Object) []reconcile.Request {
	if obj.GetName() != r.NodeName {
		return nil
	}
	var ncList v1alpha1.NATConfigList
	if err := r.List(ctx, &ncList); err != nil {
		return nil
	}
	reqs := make([]reconcile.Request, len(ncList.Items))
	for i, nc := range ncList.Items {
		reqs[i] = reconcile.Request{NamespacedName: types.NamespacedName{Name: nc.Name}}
	}
	return reqs
}

func (r *NATConfigReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.NATConfig{}).
		Watches(
			&corev1.Node{},
			handler.EnqueueRequestsFromMapFunc(r.nodeToNATConfigs),
		).
		Complete(r)
}

func cidrSet(cidrs []string) map[string]struct{} {
	m := make(map[string]struct{}, len(cidrs))
	for _, c := range cidrs {
		m[c] = struct{}{}
	}
	return m
}
