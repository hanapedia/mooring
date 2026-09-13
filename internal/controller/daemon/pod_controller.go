package daemon

import (
	"context"
	"fmt"
	"time"

	v1alpha1 "github.com/hanapedia/mooring/api/v1alpha1"
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

const (
	deletionGracePeriod   = 240 * time.Second
	podIdentityIndexField = ".spec.podIdentity"
)

// nprrName constructs the NATPortRangeRequest name for a given pod and NATConfig.
// Convention: {podNamespace}-{podName}-{natConfigName}
func nprrName(podNamespace, podName, natConfig string) string {
	return podNamespace + "-" + podName + "-" + natConfig
}

type PodReconciler struct {
	client.Client
	NodeName string
}

// Reconciles NPRR state based on Pod status and NATConfig's label selector
func (r *PodReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var pod corev1.Pod
	if err := r.Get(ctx, req.NamespacedName, &pod); err != nil {
		if apierrors.IsNotFound(err) {
			return r.handlePodGone(ctx, req)
		}
		return ctrl.Result{}, err
	}

	if pod.Status.PodIP == "" {
		return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
	}

	var ncList v1alpha1.NATConfigList
	if err := r.List(ctx, &ncList); err != nil {
		return ctrl.Result{}, err
	}

	matchingNCs := make(map[string]struct{})
	for _, nc := range ncList.Items {
		sel, err := metav1.LabelSelectorAsSelector(&nc.Spec.PodSelector)
		if err != nil {
			continue
		}
		if sel.Matches(labels.Set(pod.Labels)) {
			matchingNCs[nc.Name] = struct{}{}
		}
	}

	identity := pod.Namespace + "/" + pod.Name
	var nprrList v1alpha1.NATPortRangeRequestList
	if err := r.List(ctx, &nprrList, client.MatchingFields{podIdentityIndexField: identity}); err != nil {
		return ctrl.Result{}, err
	}

	existingNCs := make(map[string]*v1alpha1.NATPortRangeRequest, len(nprrList.Items))
	for i := range nprrList.Items {
		existingNCs[nprrList.Items[i].Spec.NATConfig] = &nprrList.Items[i]
	}

	terminating := !pod.DeletionTimestamp.IsZero()

	if !terminating {
		// create NPRR for each NC if missing
		for ncName := range matchingNCs {
			if _, ok := existingNCs[ncName]; ok {
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
	}

	for ncName, nprr := range existingNCs {
		if nprr.DeletionTimestamp != nil && !nprr.DeletionTimestamp.IsZero() {
			continue
		}
		_, stillMatches := matchingNCs[ncName]
		shouldExpire := terminating || !stillMatches
		if shouldExpire {
			// add DeletionGracePeriodExpiry
			if nprr.Status.DeletionGracePeriodExpiry == nil {
				expiry := metav1.NewTime(time.Now().Add(deletionGracePeriod))
				nprr.Status.DeletionGracePeriodExpiry = &expiry
				if err := r.Status().Update(ctx, nprr); err != nil && !apierrors.IsConflict(err) {
					return ctrl.Result{}, err
				}
			}
		} else if nprr.Status.DeletionGracePeriodExpiry != nil {
			// Pod running and NATConfig still matches; clear any stale grace period
			// left over from a previous termination that was superseded by a restart.
			nprr.Status.DeletionGracePeriodExpiry = nil
			if err := r.Status().Update(ctx, nprr); err != nil && !apierrors.IsConflict(err) {
				return ctrl.Result{}, err
			}
		}
	}

	return ctrl.Result{}, nil
}

// handlePodGone handles cases where the Pod resource no longer exists in the cache
func (r *PodReconciler) handlePodGone(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	identity := req.Namespace + "/" + req.Name
	var nprrList v1alpha1.NATPortRangeRequestList
	if err := r.List(ctx, &nprrList, client.MatchingFields{podIdentityIndexField: identity}); err != nil {
		return ctrl.Result{}, err
	}
	for i := range nprrList.Items {
		nprr := &nprrList.Items[i]
		// nprr controller has deleted the nprr after waiting for DeletionGracePeriodExpiry
		if !nprr.DeletionTimestamp.IsZero() {
			continue
		}
		// add DeletionGracePeriodExpiry
		if nprr.Status.DeletionGracePeriodExpiry == nil {
			expiry := metav1.NewTime(time.Now().Add(deletionGracePeriod))
			nprr.Status.DeletionGracePeriodExpiry = &expiry
			if err := r.Status().Update(ctx, nprr); err != nil && !apierrors.IsConflict(err) {
				return ctrl.Result{}, err
			}
		}
	}
	return ctrl.Result{}, nil
}

func (r *PodReconciler) natConfigToPods(ctx context.Context, _ client.Object) []reconcile.Request {
	var pods corev1.PodList
	// lists from cache with only pods on this node
	if err := r.List(ctx, &pods); err != nil {
		return nil
	}
	reqs := make([]reconcile.Request, len(pods.Items))
	for i, pod := range pods.Items {
		reqs[i] = reconcile.Request{NamespacedName: types.NamespacedName{
			Namespace: pod.Namespace,
			Name:      pod.Name,
		}}
	}
	return reqs
}

func (r *PodReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := mgr.GetFieldIndexer().IndexField(
		context.Background(),
		&v1alpha1.NATPortRangeRequest{},
		podIdentityIndexField,
		func(obj client.Object) []string {
			nprr := obj.(*v1alpha1.NATPortRangeRequest)
			return []string{nprr.Spec.PodNamespace + "/" + nprr.Spec.PodName}
		},
	); err != nil {
		return fmt.Errorf("index NATPortRangeRequest %s: %w", podIdentityIndexField, err)
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Pod{}).
		Watches(
			&v1alpha1.NATConfig{},
			handler.EnqueueRequestsFromMapFunc(r.natConfigToPods),
		).
		Complete(r)
}
