package main

import (
	"os"

	v1alpha1 "github.com/hanapedia/mooring/api/v1alpha1"
	"github.com/hanapedia/mooring/internal/controller/daemon"
	"github.com/hanapedia/mooring/internal/loader"
	"github.com/hanapedia/mooring/internal/routing/bgp"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	apimruntime "k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
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

	nodeName := os.Getenv("NODE_NAME")
	if nodeName == "" {
		setupLog.Error(nil, "NODE_NAME env var must be set")
		os.Exit(1)
	}
	iface := os.Getenv("NODE_IFACE")
	if iface == "" {
		iface = "eth0"
	}

	bgpCfg, err := bgp.FromEnv()
	if err != nil {
		setupLog.Error(err, "invalid BGP configuration")
		os.Exit(1)
	}
	speaker := bgp.New(bgpCfg)

	if err = loader.EnsureLoaded(iface); err != nil {
		setupLog.Error(err, "unable to load BPF programs")
		os.Exit(1)
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		HealthProbeBindAddress: ":8082",
		Metrics:                metricsserver.Options{BindAddress: "0"},
		Cache: cache.Options{
			ByObject: map[client.Object]cache.ByObject{
				// cache only resources local to this node
				&corev1.Node{}: {
					Field: fields.OneTermEqualSelector("metadata.name", nodeName),
				},
				&corev1.Pod{}: {
					Field: fields.OneTermEqualSelector("spec.nodeName", nodeName),
				},
				&v1alpha1.NATPortRangeRequest{}: {
					Field: fields.OneTermEqualSelector("spec.nodeName", nodeName),
				},
			},
		},
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	if err := (&daemon.PodReconciler{
		Client:   mgr.GetClient(),
		NodeName: nodeName,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create Pod controller")
		os.Exit(1)
	}

	if err := (&daemon.NPRRReconciler{
		Client:   mgr.GetClient(),
		NodeName: nodeName,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create NPRR controller")
		os.Exit(1)
	}

	if err = mgr.Add(speaker); err != nil {
		setupLog.Error(err, "unable to register BGP speaker")
		os.Exit(1)
	}

	if err = daemon.NewNATConfigReconciler(mgr.GetClient(), nodeName, daemon.RealTargetCIDRMap{}, daemon.RealExtIPPoolMap{}, speaker).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create NATConfig controller")
		os.Exit(1)
	}

	if err := daemon.NewNATPortRangeSyncReconciler(mgr.GetClient(), nodeName, daemon.RealPortRangeLookupMap{}, daemon.RealSnatConfigMap{}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create NATPortRange sync controller")
		os.Exit(1)
	}

	if err := mgr.Add(&daemon.NPRRStartupSyncer{Client: mgr.GetClient(), NodeName: nodeName}); err != nil {
		setupLog.Error(err, "unable to register NPRRStartupSyncer")
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

	setupLog.Info("starting daemon", "nodeName", nodeName, "iface", iface)
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}
