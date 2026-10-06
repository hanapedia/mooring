package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

// Operator (control-plane) metrics. See docs/metrics.md for the published
// name/type/description of each.
var (
	NATConfigPortsFree = promauto.With(ctrlmetrics.Registry).NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: "natconfig",
		Name:      "ports_free",
		Help:      "Number of free (unallocated) ports remaining for a NATConfig on a given external IP.",
	}, []string{"natconfig", "external_ip"})

	NATConfigPortsTotal = promauto.With(ctrlmetrics.Registry).NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: "natconfig",
		Name:      "ports_total",
		Help:      "Total number of ports configured for a NATConfig on a given external IP.",
	}, []string{"natconfig", "external_ip"})

	NATConfigPortAllocationFailuresTotal = promauto.With(ctrlmetrics.Registry).NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Subsystem: "natconfig",
		Name:      "port_allocation_failures_total",
		Help:      "Number of times a port-block allocation failed for a NATConfig due to pool exhaustion.",
	}, []string{"natconfig"})

	NATPortRangePortsAllocated = promauto.With(ctrlmetrics.Registry).NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: "natportrange",
		Name:      "ports_allocated",
		Help:      "Number of ports currently allocated to a pod's NATPortRange.",
	}, []string{"pod", "namespace", "node", "natconfig"})

	// Info metrics: always 1, existing purely to carry identifying/descriptive
	// labels for a live object. Object counts are derived by querying
	// (e.g. count(mooring_natconfig_info)) rather than maintained as a
	// separate total gauge.
	NATConfigInfo = promauto.With(ctrlmetrics.Registry).NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: "natconfig",
		Name:      "info",
		Help:      "Always 1 for a live NATConfig; labels carry identifying info. Count objects via count(mooring_natconfig_info).",
	}, []string{"natconfig", "port_range_size"})

	NATPortRangeInfo = promauto.With(ctrlmetrics.Registry).NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: "natportrange",
		Name:      "info",
		Help:      "Always 1 for a live NATPortRange; labels carry identifying info. Count objects via count(mooring_natportrange_info).",
	}, []string{"pod", "namespace", "node", "natconfig", "state"})

	// NATPortRangeRequestInfo carries "name" (the NPRR object's own name) in
	// addition to its spec fields: NATPortRangeRequest has no finalizer, so by
	// the time its deletion is observed (a Get returning NotFound) its Spec is
	// already gone — "name" is the only thing left to delete the row by.
	NATPortRangeRequestInfo = promauto.With(ctrlmetrics.Registry).NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: "natportrangerequest",
		Name:      "info",
		Help:      "Always 1 for a live NATPortRangeRequest; labels carry identifying info. Count objects via count(mooring_natportrangerequest_info).",
	}, []string{"name", "pod", "namespace", "node", "natconfig"})

	OperatorLeader = promauto.With(ctrlmetrics.Registry).NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: "operator",
		Name:      "leader",
		Help:      "1 if this operator replica is the elected leader, 0 otherwise.",
	})
)
