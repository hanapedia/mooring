// Package metrics defines the Prometheus collectors exposed by mooring's
// operator and daemon binaries. All collectors are registered against
// controller-runtime's own metrics registry (sigs.k8s.io/controller-runtime/pkg/metrics.Registry)
// rather than prometheus.DefaultRegisterer, so they are served on the same
// /metrics endpoint controller-runtime's manager already exposes.
package metrics

// namespace is the common Prometheus namespace prefix for every mooring metric.
const namespace = "mooring"
