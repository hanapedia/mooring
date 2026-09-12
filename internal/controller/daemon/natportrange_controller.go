package daemon

import (
	"context"
	"fmt"
	"net"
	"sync"

	v1alpha1 "github.com/hanapedia/mooring/api/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// syncProtos lists the IP protocols for which port_range_lookup maps are maintained.
var syncProtos = []uint8{6, 17, 1} // TCP, UDP, ICMP

// syncedNPR is the last-known state of an NPR, stored so reconcile can compute
// a minimal diff rather than a full teardown/rebuild on every update.
type syncedNPR struct {
	TargetCIDRs []string
	Allocations []v1alpha1.PortAllocation
}

type NATPortRangeSyncReconciler struct {
	client.Client
	NodeName string
	BPF      PortRangeBPF
	mu       sync.Mutex
	synced   map[string]syncedNPR // key: NPR name
}

func NewNATPortRangeSyncReconciler(c client.Client, nodeName string, bpf PortRangeBPF) *NATPortRangeSyncReconciler {
	return &NATPortRangeSyncReconciler{
		Client: c,
		NodeName: nodeName,
		BPF:    bpf,
		synced: make(map[string]syncedNPR),
	}
}

func (r *NATPortRangeSyncReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var npr v1alpha1.NATPortRange
	if err := r.Get(ctx, req.NamespacedName, &npr); err != nil {
		if apierrors.IsNotFound(err) {
			r.mu.Lock()
			delete(r.synced, req.Name)
			r.mu.Unlock()
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	if !npr.DeletionTimestamp.IsZero() {
		return r.syncDeleted(&npr)
	}
	return r.syncAlive(&npr)
}

func (r *NATPortRangeSyncReconciler) syncDeleted(npr *v1alpha1.NATPortRange) (ctrl.Result, error) {
	podIP := net.ParseIP(npr.Spec.PodIP)

	for _, a := range npr.Spec.Allocations {
		extIP := net.ParseIP(a.ExternalIP)
		for _, proto := range syncProtos {
			if err := r.BPF.RemovePortRange(extIP, podIP, uint16(a.PortStart), uint16(a.PortEnd), proto); err != nil {
				return ctrl.Result{}, fmt.Errorf("remove port range: %w", err)
			}
		}
	}

	if npr.Spec.NodeName == r.NodeName {
		extIPs := uniqueExtIPs(npr.Spec.Allocations)
		for _, cidrStr := range npr.Spec.TargetCIDRs {
			_, cidr, err := net.ParseCIDR(cidrStr)
			if err != nil {
				return ctrl.Result{}, fmt.Errorf("parse target CIDR %s: %w", cidrStr, err)
			}
			if err := r.BPF.RemoveSnatAllocs(podIP, cidr, extIPs); err != nil {
				return ctrl.Result{}, fmt.Errorf("remove snat allocs for CIDR %s: %w", cidrStr, err)
			}
		}
	}

	r.mu.Lock()
	delete(r.synced, npr.Name)
	r.mu.Unlock()
	return ctrl.Result{}, nil
}

func (r *NATPortRangeSyncReconciler) syncAlive(npr *v1alpha1.NATPortRange) (ctrl.Result, error) {
	r.mu.Lock()
	cached := r.synced[npr.Name]
	cachedCIDRsCopy := append([]string(nil), cached.TargetCIDRs...)
	cachedAllocsCopy := append([]v1alpha1.PortAllocation(nil), cached.Allocations...)
	r.mu.Unlock()

	podIP := net.ParseIP(npr.Spec.PodIP)
	toRemove, toAdd := diffAllocations(cachedAllocsCopy, npr.Spec.Allocations)

	// port_range_lookup: all nodes sync port ranges for every NPR
	for _, a := range toRemove {
		extIP := net.ParseIP(a.ExternalIP)
		for _, proto := range syncProtos {
			if err := r.BPF.RemovePortRange(extIP, podIP, uint16(a.PortStart), uint16(a.PortEnd), proto); err != nil {
				return ctrl.Result{}, fmt.Errorf("remove port range: %w", err)
			}
		}
	}
	for _, a := range toAdd {
		extIP := net.ParseIP(a.ExternalIP)
		for _, proto := range syncProtos {
			if err := r.BPF.AddPortRange(extIP, podIP, uint16(a.PortStart), uint16(a.PortEnd), proto); err != nil {
				return ctrl.Result{}, fmt.Errorf("add port range: %w", err)
			}
		}
	}

	if npr.Spec.NodeName == r.NodeName {
		removedCIDRs, addedCIDRs, commonCIDRs := diffStringSlices(cachedCIDRsCopy, npr.Spec.TargetCIDRs)

		// Dropped target CIDRs: remove the entire snat_config entry for that CIDR.
		if len(removedCIDRs) > 0 {
			oldExtIPs := uniqueExtIPs(cachedAllocsCopy)
			for _, cidrStr := range removedCIDRs {
				_, cidr, err := net.ParseCIDR(cidrStr)
				if err != nil {
					return ctrl.Result{}, fmt.Errorf("parse target CIDR %s: %w", cidrStr, err)
				}
				if err := r.BPF.RemoveSnatAllocs(podIP, cidr, oldExtIPs); err != nil {
					return ctrl.Result{}, fmt.Errorf("remove snat allocs for dropped CIDR %s: %w", cidrStr, err)
				}
			}
		}

		// Common target CIDRs: remove dropped allocations.
		if len(toRemove) > 0 {
			removedExtIPs := uniqueExtIPs(toRemove)
			for _, cidrStr := range commonCIDRs {
				_, cidr, err := net.ParseCIDR(cidrStr)
				if err != nil {
					return ctrl.Result{}, fmt.Errorf("parse target CIDR %s: %w", cidrStr, err)
				}
				// See invariant note on RemoveSnatAllocs: correct only when
				// NATConfig pools are non-overlapping (same ext-IP never in two
				// different NPRs for the same pod and the same target CIDR).
				if err := r.BPF.RemoveSnatAllocs(podIP, cidr, removedExtIPs); err != nil {
					return ctrl.Result{}, fmt.Errorf("remove snat allocs: %w", err)
				}
			}
		}

		// Newly added target CIDRs: upsert all current allocations.
		for _, cidrStr := range addedCIDRs {
			_, cidr, err := net.ParseCIDR(cidrStr)
			if err != nil {
				return ctrl.Result{}, fmt.Errorf("parse target CIDR %s: %w", cidrStr, err)
			}
			for _, a := range npr.Spec.Allocations {
				extIP := net.ParseIP(a.ExternalIP)
				if err := r.BPF.UpsertSnatEntry(podIP, cidr, extIP, uint16(a.PortStart), uint16(a.PortEnd)); err != nil {
					return ctrl.Result{}, fmt.Errorf("upsert snat entry: %w", err)
				}
			}
		}

		// Common target CIDRs: upsert newly added allocations.
		for _, a := range toAdd {
			extIP := net.ParseIP(a.ExternalIP)
			for _, cidrStr := range commonCIDRs {
				_, cidr, err := net.ParseCIDR(cidrStr)
				if err != nil {
					return ctrl.Result{}, fmt.Errorf("parse target CIDR %s: %w", cidrStr, err)
				}
				if err := r.BPF.UpsertSnatEntry(podIP, cidr, extIP, uint16(a.PortStart), uint16(a.PortEnd)); err != nil {
					return ctrl.Result{}, fmt.Errorf("upsert snat entry: %w", err)
				}
			}
		}
	}

	r.mu.Lock()
	r.synced[npr.Name] = syncedNPR{
		TargetCIDRs: append([]string(nil), npr.Spec.TargetCIDRs...),
		Allocations: append([]v1alpha1.PortAllocation(nil), npr.Spec.Allocations...),
	}
	r.mu.Unlock()
	return ctrl.Result{}, nil
}

func (r *NATPortRangeSyncReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.NATPortRange{}).
		Complete(r)
}

func diffAllocations(old, curr []v1alpha1.PortAllocation) (toRemove, toAdd []v1alpha1.PortAllocation) {
	oldSet := make(map[string]struct{}, len(old))
	for _, a := range old {
		oldSet[allocKey(a)] = struct{}{}
	}
	currSet := make(map[string]struct{}, len(curr))
	for _, a := range curr {
		currSet[allocKey(a)] = struct{}{}
	}
	for _, a := range old {
		if _, ok := currSet[allocKey(a)]; !ok {
			toRemove = append(toRemove, a)
		}
	}
	for _, a := range curr {
		if _, ok := oldSet[allocKey(a)]; !ok {
			toAdd = append(toAdd, a)
		}
	}
	return
}

// diffStringSlices partitions old and curr into removed, added, and common elements.
func diffStringSlices(old, curr []string) (removed, added, common []string) {
	oldSet := make(map[string]struct{}, len(old))
	for _, s := range old {
		oldSet[s] = struct{}{}
	}
	currSet := make(map[string]struct{}, len(curr))
	for _, s := range curr {
		currSet[s] = struct{}{}
	}
	for _, s := range old {
		if _, ok := currSet[s]; ok {
			common = append(common, s)
		} else {
			removed = append(removed, s)
		}
	}
	for _, s := range curr {
		if _, ok := oldSet[s]; !ok {
			added = append(added, s)
		}
	}
	return
}

// allocKey uniquely identifies a port allocation for diffing purposes.
// Both portStart and portEnd are included so a range resize on the same start
// port is treated as a change (remove old, add new) rather than a no-op.
func allocKey(a v1alpha1.PortAllocation) string {
	return fmt.Sprintf("%s/%d-%d", a.ExternalIP, a.PortStart, a.PortEnd)
}

func uniqueExtIPs(allocs []v1alpha1.PortAllocation) []net.IP {
	seen := make(map[string]struct{})
	var ips []net.IP
	for _, a := range allocs {
		if _, ok := seen[a.ExternalIP]; !ok {
			seen[a.ExternalIP] = struct{}{}
			ips = append(ips, net.ParseIP(a.ExternalIP))
		}
	}
	return ips
}
