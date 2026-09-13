package daemon

import (
	"context"
	"fmt"
	"net"
	"slices"
	"sync"

	v1alpha1 "github.com/hanapedia/mooring/api/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type NATConfigReconciler struct {
	client.Client
	TargetCIDRs TargetCIDRMap
	ExtIPPool   ExtIPPoolMap

	mu            sync.Mutex
	ncTargetCIDRs map[string][]string // ncName → CIDRs last written to target_cidrs
	ncExtIPCIDRs  map[string][]string // ncName → CIDRs last written to ext_ip_pool
}

func NewNATConfigReconciler(c client.Client, targetCIDRs TargetCIDRMap, extIPPool ExtIPPoolMap) *NATConfigReconciler {
	return &NATConfigReconciler{
		Client:        c,
		TargetCIDRs:   targetCIDRs,
		ExtIPPool:     extIPPool,
		ncTargetCIDRs: make(map[string][]string),
		ncExtIPCIDRs:  make(map[string][]string),
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

	var desiredTargetCIDRs, desiredExtIPCIDRs []string
	if !deleted {
		desiredTargetCIDRs = nc.Spec.TargetCIDRs
		desiredExtIPCIDRs = nc.Spec.ExternalIPPool
	}

	if err := r.syncBPFMaps(req.Name, desiredTargetCIDRs, desiredExtIPCIDRs); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

func (r *NATConfigReconciler) syncBPFMaps(ncName string, desiredTargetCIDRs, desiredExtIPCIDRs []string) error {
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

func (r *NATConfigReconciler) SetupWithManager(mgr ctrl.Manager) error {
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
