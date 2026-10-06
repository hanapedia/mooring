package operator

import (
	"context"
	"time"

	v1alpha1 "github.com/hanapedia/mooring/api/v1alpha1"
	"github.com/hanapedia/mooring/internal/allocator"
	"github.com/hanapedia/mooring/internal/metrics"
	"github.com/prometheus/client_golang/prometheus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// sumAllocatedPorts returns the total number of ports across all of an
// NATPortRange's PortAllocations.
func sumAllocatedPorts(allocs []v1alpha1.PortAllocation) int32 {
	var total int32
	for _, a := range allocs {
		total += a.PortEnd - a.PortStart + 1
	}
	return total
}

const (
	// DefaultBPFCleanupWindow is the window given to all daemon instances to
	// clean up their BPF maps after an NPR is marked stale, before the operator
	// removes the allocation finalizer and deletes the NPR.
	DefaultBPFCleanupWindow = 60 * time.Second
)

type NATPortRangeReconciler struct {
	client.Client
	Registry *AllocatorRegistry
	// BPFCleanupWindow overrides DefaultBPFCleanupWindow when non-zero.
	// Set to a short duration in tests.
	BPFCleanupWindow time.Duration
}

func (r *NATPortRangeReconciler) cleanupWindow() time.Duration {
	if r.BPFCleanupWindow > 0 {
		return r.BPFCleanupWindow
	}
	return DefaultBPFCleanupWindow
}

func (r *NATPortRangeReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	select {
	case <-r.Registry.Reconstructed():
	case <-ctx.Done():
		return ctrl.Result{}, ctx.Err()
	}

	var npr v1alpha1.NATPortRange
	if err := r.Get(ctx, req.NamespacedName, &npr); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	metrics.NATPortRangePortsAllocated.
		WithLabelValues(npr.Spec.PodName, npr.Spec.PodNamespace, npr.Spec.NodeName, npr.Spec.NATConfig).
		Set(float64(sumAllocatedPorts(npr.Spec.Allocations)))

	// Info row: exactly one of the two state values is set at a time. The
	// other is explicitly deleted on every reconcile so a state transition
	// (active -> stale_pending_cleanup) doesn't leave the old row lingering.
	state, otherState := "active", "stale_pending_cleanup"
	if npr.Spec.StaleSince != nil {
		state, otherState = otherState, state
	}
	metrics.NATPortRangeInfo.
		WithLabelValues(npr.Spec.PodName, npr.Spec.PodNamespace, npr.Spec.NodeName, npr.Spec.NATConfig, state).
		Set(1)
	metrics.NATPortRangeInfo.DeleteLabelValues(
		npr.Spec.PodName, npr.Spec.PodNamespace, npr.Spec.NodeName, npr.Spec.NATConfig, otherState)

	// NPR is terminating (DeletionTimestamp set by GC cascade or by us below).
	// Ensure StaleSince is stamped so daemons can clean up BPF maps, then
	// wait for BPFCleanupWindow before removing the allocation finalizer.
	if !npr.DeletionTimestamp.IsZero() {
		if npr.Spec.StaleSince == nil {
			now := metav1.Now()
			npr.Spec.StaleSince = &now
			if err := r.Update(ctx, &npr); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{RequeueAfter: r.cleanupWindow()}, nil
		}
		if remaining := time.Until(npr.Spec.StaleSince.Add(r.cleanupWindow())); remaining > 0 {
			return ctrl.Result{RequeueAfter: remaining}, nil
		}
		return r.releaseAndFinalize(ctx, &npr)
	}

	// StaleSince set by the NPRR controller (pod gone, grace period elapsed).
	// Wait for BPFCleanupWindow then trigger deletion.
	if npr.Spec.StaleSince != nil {
		if remaining := time.Until(npr.Spec.StaleSince.Add(r.cleanupWindow())); remaining > 0 {
			return ctrl.Result{RequeueAfter: remaining}, nil
		}
		return ctrl.Result{}, client.IgnoreNotFound(r.Delete(ctx, &npr))
	}

	return ctrl.Result{}, nil
}

// releaseAndFinalize frees the port-block allocations back to the allocator and
// removes the allocation finalizer, allowing the NPR to be fully deleted by GC.
func (r *NATPortRangeReconciler) releaseAndFinalize(ctx context.Context, npr *v1alpha1.NATPortRange) (ctrl.Result, error) {
	if !controllerutil.ContainsFinalizer(npr, finalizerName) {
		return ctrl.Result{}, nil
	}
	if alloc, ok := r.Registry.Get(npr.Spec.NATConfig); ok {
		byIP := make(map[string][]allocator.Allocation, len(npr.Spec.Allocations))
		for _, a := range npr.Spec.Allocations {
			byIP[a.ExternalIP] = append(byIP[a.ExternalIP], allocator.Allocation{
				PortStart: uint16(a.PortStart),
				PortEnd:   uint16(a.PortEnd),
			})
		}
		if err := alloc.Free(byIP); err != nil {
			return ctrl.Result{}, err
		}
	}
	controllerutil.RemoveFinalizer(npr, finalizerName)
	if err := r.Update(ctx, npr); err != nil {
		return ctrl.Result{}, err
	}
	// Delete the ports-allocated series now, while npr.Spec is still populated:
	// once the finalizer is gone the object disappears and this label set can
	// never be reconstructed. The apierrors.IsNotFound branch of Reconcile (hit
	// on a later reconcile after the object is fully gone) relies on this
	// having already run — do not reorder finalizer removal ahead of this.
	metrics.NATPortRangePortsAllocated.DeleteLabelValues(
		npr.Spec.PodName, npr.Spec.PodNamespace, npr.Spec.NodeName, npr.Spec.NATConfig)
	// DeletePartialMatch on everything but "state" removes whichever of the
	// two state rows is currently live, without needing to know which.
	metrics.NATPortRangeInfo.DeletePartialMatch(prometheus.Labels{
		"pod": npr.Spec.PodName, "namespace": npr.Spec.PodNamespace,
		"node": npr.Spec.NodeName, "natconfig": npr.Spec.NATConfig,
	})
	r.Registry.RecordAvailability(npr.Spec.NATConfig)
	return ctrl.Result{}, nil
}

func (r *NATPortRangeReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.NATPortRange{}).
		Complete(r)
}
