package daemon

import (
	"context"
	"time"

	v1alpha1 "github.com/hanapedia/mooring/api/v1alpha1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type NPRRReconciler struct {
	client.Client
	NodeName string
}

func (r *NPRRReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var nprr v1alpha1.NATPortRangeRequest
	if err := r.Get(ctx, req.NamespacedName, &nprr); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if nprr.Spec.NodeName != r.NodeName {
		return ctrl.Result{}, nil
	}

	if nprr.Status.DeletionGracePeriodExpiry == nil {
		return ctrl.Result{}, nil
	}

	remaining := time.Until(nprr.Status.DeletionGracePeriodExpiry.Time)
	if remaining > 0 {
		return ctrl.Result{RequeueAfter: remaining}, nil
	}

	if err := r.Delete(ctx, &nprr); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	return ctrl.Result{}, nil
}

func (r *NPRRReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.NATPortRangeRequest{}).
		Complete(r)
}
