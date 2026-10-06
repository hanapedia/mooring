# Metrics

Mooring exposes Prometheus metrics from both the operator (control plane) and the daemon (per-node dataplane sync + BPF). Both processes serve `/metrics` via controller-runtime's standard metrics server, so `controller_runtime_*` and `workqueue_*` metrics (reconcile counts/durations, workqueue depth) are available alongside the custom metrics below with no extra setup.

All custom metric names are prefixed `mooring_`.

## Operator metrics

Served by `cmd/operator` on `:8080`.

| Name | Type | Description |
|---|---|---|
| `mooring_natconfig_ports_free` | Gauge | Number of free (unallocated) ports remaining for a NATConfig on a given external IP. Labels: `natconfig`, `external_ip`. |
| `mooring_natconfig_ports_total` | Gauge | Total number of ports configured for a NATConfig on a given external IP. Labels: `natconfig`, `external_ip`. |
| `mooring_natconfig_port_allocation_failures_total` | Counter | Number of times a port-block allocation failed for a NATConfig due to pool exhaustion. Labels: `natconfig`. |
| `mooring_natportrange_ports_allocated` | Gauge | Number of ports currently allocated to a pod's NATPortRange. Labels: `pod`, `namespace`, `node`, `natconfig`. |
| `mooring_natconfig_info` | Gauge | Always 1 for a live NATConfig; labels carry identifying info. Labels: `natconfig`, `port_range_size`. |
| `mooring_natportrange_info` | Gauge | Always 1 for a live NATPortRange; labels carry identifying info. Labels: `pod`, `namespace`, `node`, `natconfig`, `state` (`active`\|`stale_pending_cleanup`). |
| `mooring_natportrangerequest_info` | Gauge | Always 1 for a live NATPortRangeRequest; labels carry identifying info. Labels: `name`, `pod`, `namespace`, `node`, `natconfig`. |
| `mooring_operator_leader` | Gauge | 1 if this operator replica is the elected leader, 0 otherwise. |

## Daemon metrics

Served by `cmd/daemon` on `:8080`, per node.

_None yet — introduced starting with PR2._
