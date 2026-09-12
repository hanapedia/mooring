package operator

import (
	"context"
	"fmt"

	v1alpha1 "github.com/hanapedia/mooring/api/v1alpha1"
	"github.com/hanapedia/mooring/internal/allocator"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const natConfigIndexField = ".spec.natConfig"

type NATConfigReconciler struct {
	client.Client
	Registry *AllocatorRegistry
}

func (r *NATConfigReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	select {
	case <-r.Registry.Reconstructed():
	case <-ctx.Done():
		return ctrl.Result{}, ctx.Err()
	}

	var nc v1alpha1.NATConfig
	if err := r.Get(ctx, req.NamespacedName, &nc); err != nil {
		if apierrors.IsNotFound(err) {
			// NATConfig deleted: remove its allocator. The daemon will clean up
			// NATPortRangeRequests; GC cascades to NATPortRanges; the NPR controller
			// finalizer reclaims block indices.
			r.Registry.Remove(req.Name)
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	alloc, err := r.Registry.EnsureAllocator(nc.Name, uint16(nc.Spec.PortRangeSize))
	if err != nil {
		return ctrl.Result{}, err
	}

	desiredIPs, err := expandCIDRs(nc.Spec.ExternalIPPool)
	if err != nil {
		return ctrl.Result{}, err
	}
	desiredSet := stringSet(desiredIPs)

	// Register new IPs before updating NPRs so AllocateForIP can use them.
	for _, ip := range desiredIPs {
		alloc.EnsureIP(ip)
	}

	// Determine which IPs to drop after all NPRs are updated.
	currentIPs := alloc.ListIPs()
	currentSet := stringSet(currentIPs)
	var removedIPs []string
	for ip := range currentSet {
		if _, ok := desiredSet[ip]; !ok {
			removedIPs = append(removedIPs, ip)
		}
	}

	// List all NPRs for this NATConfig via the field index.
	var nprList v1alpha1.NATPortRangeList
	if err := r.List(ctx, &nprList, client.MatchingFields{natConfigIndexField: nc.Name}); err != nil {
		return ctrl.Result{}, err
	}

	for i := range nprList.Items {
		npr := &nprList.Items[i]
		if !npr.DeletionTimestamp.IsZero() {
			continue
		}
		if err := r.reconcileNPRAllocations(ctx, npr, desiredIPs, desiredSet, alloc); err != nil {
			return ctrl.Result{}, err
		}
	}

	// Remove dropped IPs from the allocator only after all NPRs are updated.
	// RemoveIP discards all tracked blocks for the IP; no explicit Free needed.
	for _, ip := range removedIPs {
		alloc.RemoveIP(ip)
	}

	return ctrl.Result{}, nil
}

func (r *NATConfigReconciler) reconcileNPRAllocations(
	ctx context.Context,
	npr *v1alpha1.NATPortRange,
	desiredIPs []string,
	desiredSet map[string]struct{},
	alloc *allocator.BlockAllocator,
) error {
	byIP := groupAllocsByIP(npr.Spec.Allocations)

	var toAdd []string
	for _, ip := range desiredIPs {
		if _, ok := byIP[ip]; !ok {
			toAdd = append(toAdd, ip)
		}
	}
	needsRemoval := false
	for ip := range byIP {
		if _, ok := desiredSet[ip]; !ok {
			needsRemoval = true
			break
		}
	}
	if len(toAdd) == 0 && !needsRemoval {
		return nil
	}

	// Keep allocations for IPs still in the desired set.
	newAllocs := make([]v1alpha1.PortAllocation, 0, len(npr.Spec.Allocations))
	for _, a := range npr.Spec.Allocations {
		if _, ok := desiredSet[a.ExternalIP]; ok {
			newAllocs = append(newAllocs, a)
		}
	}

	existing := collectPortStarts(newAllocs)

	portRangeCount := uint16(npr.Spec.PortRangeCount)
	if portRangeCount == 0 {
		portRangeCount = defaultPortRangeCount
	}

	rollback := make(map[string][]allocator.Allocation)
	for _, ip := range toAdd {
		als, err := alloc.AllocateForIP(ip, portRangeCount, existing)
		if err != nil {
			_ = alloc.Free(rollback)
			return fmt.Errorf("allocate for new IP %s on NPR %s: %w", ip, npr.Name, err)
		}
		for _, al := range als {
			newAllocs = append(newAllocs, v1alpha1.PortAllocation{
				ExternalIP: ip,
				PortStart:  int32(al.PortStart),
				PortEnd:    int32(al.PortEnd),
			})
			existing = append(existing, al.PortStart)
			rollback[ip] = append(rollback[ip], al)
		}
	}

	npr.Spec.Allocations = newAllocs
	if err := r.Update(ctx, npr); err != nil {
		_ = alloc.Free(rollback)
		return err
	}
	return nil
}

func (r *NATConfigReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := mgr.GetFieldIndexer().IndexField(
		context.Background(),
		&v1alpha1.NATPortRange{},
		natConfigIndexField,
		func(obj client.Object) []string {
			return []string{obj.(*v1alpha1.NATPortRange).Spec.NATConfig}
		},
	); err != nil {
		return fmt.Errorf("index NATPortRange .spec.natConfig: %w", err)
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.NATConfig{}).
		Complete(r)
}
