package operator

import (
	"context"

	v1alpha1 "github.com/hanapedia/mooring/api/v1alpha1"
	"github.com/hanapedia/mooring/internal/allocator"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

type NATPortRangeReconciler struct {
	client.Client
	Registry *AllocatorRegistry
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

	if npr.DeletionTimestamp.IsZero() || !controllerutil.ContainsFinalizer(&npr, finalizerName) {
		return ctrl.Result{}, nil
	}

	// Free block indices back to the per-IP free sets before deletion.
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
	// If the allocator is missing (NATConfig deleted first), skip Free and just
	// remove the finalizer so GC can complete the deletion.

	controllerutil.RemoveFinalizer(&npr, finalizerName)
	return ctrl.Result{}, r.Update(ctx, &npr)
}

func (r *NATPortRangeReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.NATPortRange{}).
		Complete(r)
}
