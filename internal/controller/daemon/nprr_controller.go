package daemon

import (
	"context"
	"fmt"
	"time"

	v1alpha1 "github.com/hanapedia/mooring/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type NPRRReconciler struct {
	client.Client
	NodeName string
}

// Reconcile deletes NPRR on DeletionGracePeriodExpiry
// if DeletionGracePeriodExpiry still remains, reque after remaining duration
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

// NPRRStartupSyncer is a one-shot manager Runnable that runs after the cache
// is synced. It scans all NPRRs assigned to this node and sets
// DeletionGracePeriodExpiry on any whose pod no longer exists — covering pods
// that were deleted while the daemon was down.
type NPRRStartupSyncer struct {
	Client   client.Client
	NodeName string
}

func (s *NPRRStartupSyncer) Start(ctx context.Context) error {
	return s.Sync(ctx)
}

func (s *NPRRStartupSyncer) Sync(ctx context.Context) error {
	var nprrList v1alpha1.NATPortRangeRequestList
	if err := s.Client.List(ctx, &nprrList); err != nil {
		return fmt.Errorf("list NPRRs: %w", err)
	}
	for i := range nprrList.Items {
		nprr := &nprrList.Items[i]
		if nprr.Spec.NodeName != s.NodeName {
			continue
		}
		if !nprr.DeletionTimestamp.IsZero() || nprr.Status.DeletionGracePeriodExpiry != nil {
			continue
		}
		var pod corev1.Pod
		err := s.Client.Get(ctx, client.ObjectKey{Namespace: nprr.Spec.PodNamespace, Name: nprr.Spec.PodName}, &pod)
		if err == nil {
			continue
		}
		if !apierrors.IsNotFound(err) {
			return fmt.Errorf("get pod %s/%s: %w", nprr.Spec.PodNamespace, nprr.Spec.PodName, err)
		}
		expiry := metav1.NewTime(time.Now().Add(deletionGracePeriod))
		nprr.Status.DeletionGracePeriodExpiry = &expiry
		if updateErr := s.Client.Status().Update(ctx, nprr); updateErr != nil && !apierrors.IsConflict(updateErr) {
			return fmt.Errorf("update NPRR %s: %w", nprr.Name, updateErr)
		}
	}
	return nil
}
