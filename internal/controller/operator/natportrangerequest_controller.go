package operator

import (
	"context"
	"fmt"
	"sort"
	"time"

	v1alpha1 "github.com/hanapedia/mooring/api/v1alpha1"
	"github.com/hanapedia/mooring/internal/allocator"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type NATPortRangeRequestReconciler struct {
	client.Client
	Registry *AllocatorRegistry
}

func (r *NATPortRangeRequestReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	select {
	case <-r.Registry.Reconstructed():
	case <-ctx.Done():
		return ctrl.Result{}, ctx.Err()
	}

	var nprr v1alpha1.NATPortRangeRequest
	if err := r.Get(ctx, req.NamespacedName, &nprr); err != nil {
		if apierrors.IsNotFound(err) {
			// NPRR is gone — mark the paired NPR stale so all daemons clean up BPF maps.
			return r.markNPRStale(ctx, req.Name)
		}
		return ctrl.Result{}, err
	}

	var nc v1alpha1.NATConfig
	if err := r.Get(ctx, types.NamespacedName{Name: nprr.Spec.NATConfig}, &nc); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
		}
		return ctrl.Result{}, err
	}

	alloc, err := r.Registry.EnsureAllocator(nc.Name, uint16(nc.Spec.PortRangeSize))
	if err != nil {
		return ctrl.Result{}, err
	}
	extIPs, err := expandCIDRs(nc.Spec.ExternalIPPool)
	if err != nil {
		return ctrl.Result{}, err
	}
	for _, ip := range extIPs {
		alloc.EnsureIP(ip)
	}

	portRangeCount := defaultPortRangeCount
	if nprr.Spec.PortRangeCount != nil {
		portRangeCount = uint16(*nprr.Spec.PortRangeCount)
	}

	var npr v1alpha1.NATPortRange
	err = r.Get(ctx, types.NamespacedName{Name: req.Name}, &npr)
	if err != nil && !apierrors.IsNotFound(err) {
		return ctrl.Result{}, err
	}

	if apierrors.IsNotFound(err) {
		return r.createNPR(ctx, &nprr, &nc, alloc, extIPs, portRangeCount)
	}

	// NPR exists: drive portRangeCount to match NPRR.
	current := uint16(npr.Spec.PortRangeCount)
	if portRangeCount == current {
		return ctrl.Result{}, nil
	}
	if portRangeCount > current {
		return r.increaseCount(ctx, &npr, alloc, extIPs, portRangeCount-current)
	}
	return r.decreaseCount(ctx, &npr, alloc, extIPs, portRangeCount)
}

func (r *NATPortRangeRequestReconciler) createNPR(
	ctx context.Context,
	nprr *v1alpha1.NATPortRangeRequest,
	nc *v1alpha1.NATConfig,
	alloc *allocator.BlockAllocator,
	extIPs []string,
	portRangeCount uint16,
) (ctrl.Result, error) {
	allocations, err := alloc.AllocateForPod(extIPs, portRangeCount)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("allocate for pod: %w", err)
	}

	npr := v1alpha1.NATPortRange{
		ObjectMeta: metav1.ObjectMeta{
			Name:       nprr.Name,
			Finalizers: []string{finalizerName},
		},
		Spec: v1alpha1.NATPortRangeSpec{
			PodName:        nprr.Spec.PodName,
			PodNamespace:   nprr.Spec.PodNamespace,
			PodIP:          nprr.Spec.PodIP,
			NodeName:       nprr.Spec.NodeName,
			NATConfig:      nprr.Spec.NATConfig,
			TargetCIDRs:    nc.Spec.TargetCIDRs,
			PortRangeCount: int32(portRangeCount),
			Allocations:    buildPortAllocations(allocations),
		},
	}
	if err := r.Create(ctx, &npr); err != nil {
		if apierrors.IsAlreadyExists(err) {
			_ = alloc.Free(allocations)
			return ctrl.Result{}, nil
		}
		_ = alloc.Free(allocations)
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

func (r *NATPortRangeRequestReconciler) increaseCount(
	ctx context.Context,
	npr *v1alpha1.NATPortRange,
	alloc *allocator.BlockAllocator,
	extIPs []string,
	delta uint16,
) (ctrl.Result, error) {
	existing := collectPortStarts(npr.Spec.Allocations)
	rollback := make(map[string][]allocator.Allocation)
	var newAllocs []v1alpha1.PortAllocation

	for _, ip := range extIPs {
		als, err := alloc.AllocateForIP(ip, delta, existing)
		if err != nil {
			_ = alloc.Free(rollback)
			return ctrl.Result{}, fmt.Errorf("allocate additional blocks for IP %s: %w", ip, err)
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

	npr.Spec.Allocations = append(npr.Spec.Allocations, newAllocs...)
	npr.Spec.PortRangeCount += int32(delta)
	if err := r.Update(ctx, npr); err != nil {
		_ = alloc.Free(rollback)
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

func (r *NATPortRangeRequestReconciler) decreaseCount(
	ctx context.Context,
	npr *v1alpha1.NATPortRange,
	alloc *allocator.BlockAllocator,
	extIPs []string,
	desired uint16,
) (ctrl.Result, error) {
	byIP := groupAllocsByIP(npr.Spec.Allocations)
	toFree := make(map[string][]allocator.Allocation)
	var newAllocs []v1alpha1.PortAllocation

	// Only iterate current pool IPs. Allocations for IPs not in extIPs (removed
	// from the pool since the NPR was created) are silently dropped here without
	// being explicitly freed. The NATConfig controller will call RemoveIP for each
	// dropped IP, which atomically wipes its block-index entry from the allocator.
	for _, ip := range extIPs {
		als := byIP[ip]
		sort.Slice(als, func(i, j int) bool { return als[i].PortStart < als[j].PortStart })
		if uint16(len(als)) > desired {
			for _, a := range als[desired:] {
				toFree[ip] = append(toFree[ip], allocator.Allocation{
					PortStart: uint16(a.PortStart),
					PortEnd:   uint16(a.PortEnd),
				})
			}
			als = als[:desired]
		}
		newAllocs = append(newAllocs, als...)
	}

	// Update NPR before freeing: if crashed between Update and Free, reconstruction
	// will not MarkUsed the removed blocks (they're gone from NPR), so they become
	// naturally free on restart.
	npr.Spec.Allocations = newAllocs
	npr.Spec.PortRangeCount = int32(desired)
	if err := r.Update(ctx, npr); err != nil {
		return ctrl.Result{}, err
	}
	_ = alloc.Free(toFree)
	return ctrl.Result{}, nil
}

// markNPRStale finds the NPR whose name matches the deleted NPRR and sets
// StaleSince on it if not already set. This signals all daemons to clean up
// their BPF maps before the operator removes the finalizer and deletes the NPR.
func (r *NATPortRangeRequestReconciler) markNPRStale(ctx context.Context, name string) (ctrl.Result, error) {
	var npr v1alpha1.NATPortRange
	if err := r.Get(ctx, types.NamespacedName{Name: name}, &npr); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if npr.Spec.StaleSince != nil {
		return ctrl.Result{}, nil
	}
	now := metav1.Now()
	npr.Spec.StaleSince = &now
	if err := r.Update(ctx, &npr); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

func (r *NATPortRangeRequestReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.NATPortRangeRequest{}).
		Complete(r)
}
