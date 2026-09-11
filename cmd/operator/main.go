package main

import (
	"os"

	v1alpha1 "github.com/hanapedia/mooring/api/v1alpha1"
	"github.com/hanapedia/mooring/internal/controller/operator"
	apimruntime "k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

var (
	scheme   = apimruntime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(v1alpha1.AddToScheme(scheme))
}

func main() {
	ctrl.SetLogger(zap.New(zap.UseDevMode(true)))

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		HealthProbeBindAddress: ":8081",
		LeaderElection:         true,
		LeaderElectionID:       "mooring-operator-leader",
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	registry := operator.NewAllocatorRegistry()

	if err := mgr.Add(&operator.ReconstructionRunnable{
		Client:   mgr.GetClient(),
		Registry: registry,
	}); err != nil {
		setupLog.Error(err, "unable to add reconstruction runnable")
		os.Exit(1)
	}

	if err := (&operator.NATPortRangeRequestReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Registry: registry,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create NATPortRangeRequest controller")
		os.Exit(1)
	}

	if err := (&operator.NATPortRangeReconciler{
		Client:   mgr.GetClient(),
		Registry: registry,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create NATPortRange controller")
		os.Exit(1)
	}

	if err := (&operator.NATConfigReconciler{
		Client:   mgr.GetClient(),
		Registry: registry,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create NATConfig controller")
		os.Exit(1)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}
