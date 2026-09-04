# mooring

Kubernetes-native egress NAT with connection resiliency. No dedicated NAT pods, no encapsulation, no dropped connections on rollout.

## The Problem

Existing egress NAT solutions (e.g. [cybozu-go/coil](https://github.com/cybozu-go/coil)) bind global IPs to dedicated NAT pods and advertise them via BGP. Any rollout of those pods drops every active connection passing through them — TCP state cannot be handed over.

mooring eliminates this by moving SNAT to the client pod's own node and decoupling external IP identity from any individual pod or node.

## Key Properties

- **No encapsulation** — no MTU overhead, no tunnel management.
- **No dedicated NAT pods** — the client pod's node performs SNAT directly.
- **Shared external IPs** — all nodes advertise every external IP via BGP (ECMP), so any node can handle return traffic.
- **Rollout-resilient** — BPF programs and maps are pinned to bpffs; in-flight connections survive daemon restarts.
- **No NAT table collisions** — port ranges are allocated per `(pod, external IP)` pair, making them non-overlapping by construction.

## Requirements

- **Cilium CNI** with BPF host routing enabled (kernel conntrack is bypassed).
- **BGP underlay** with pod CIDRs advertised natively (overlay networks are not supported).
- **CiliumDatapathPlugin** API available for BPF attachment to pod endpoints.

## How It Works

### Outbound

The client pod's node performs SNAT using a pre-allocated port range. The BPF program hooks into `cil_from_container`, rewrites the source to `externalIP:NAT-port`, and records the mapping in a per-node NAT table.

### Return path (two stages)

Return traffic is distributed across all nodes via BGP ECMP. Processing happens in two hops:

1. **Stage 1 — IP revNAT (any node):** `cil_from_netdev` checks the destination against the external IP pool, resolves the pod IP from the NAT port using a shared port-range lookup map, and rewrites the destination IP. BGP then routes the packet to the pod's node.

2. **Stage 2 — port revNAT (client node):** `cil_to_container` looks up the full NAT table entry and restores the original pod port before delivering to the pod.

This two-stage split works because port ranges are unique per `(pod, external IP)` pair — the NAT port alone identifies both the pod and which external IP was used, without carrying extra state through the network.

## Architecture

```
               ┌──────────────┐
               │  client pod  │
               └──────┬───────┘
                      │ cil_from_container (SNAT: pod-IP:pod-port → extIP:NAT-port)
                      ▼
                BGP routing → external server

     ┌─────────────────────────────────────────────────┐
     │ Return path                                      │
     │                                                  │
     │  external server                                 │
     │    → any node (ECMP)                             │
     │    → cil_from_netdev  [Stage 1: IP revNAT]       │
     │        extIP:NAT-port → pod-IP:NAT-port          │
     │    → BGP routing to pod's node                   │
     │    → cil_to_container [Stage 2: port revNAT]     │
     │        pod-IP:NAT-port → pod-IP:pod-port         │
     │    → client pod ✓                                │
     └─────────────────────────────────────────────────┘
```

## Custom Resources

### Gateway

Cluster-scoped. Defines the egress policy and external IP pool for a set of client pods.

```yaml
apiVersion: mooring.io/v1alpha1
kind: Gateway
metadata:
  name: prod-gateway
spec:
  externalIPPool:
    - "203.0.113.0/28"
  defaultPortRangeSize: 100
  targetCIDRs:
    - "0.0.0.0/0"
  podSelector:
    matchLabels:
      egress: prod
```

| Field | Description |
|---|---|
| `externalIPPool` | CIDR blocks providing the external (SNAT) IPs |
| `defaultPortRangeSize` | Default number of ports per `(pod, external IP)` allocation |
| `targetCIDRs` | Destination CIDRs for which SNAT is applied |
| `podSelector` | Selects client pods this Gateway applies to |

### MasqPortRange

Cluster-scoped. Created by the operator; one per client pod. Records all port range allocations for that pod across every external IP in the pool. All daemon pods watch this resource and sync it into the stage 1 port-range lookup BPF map.

```yaml
apiVersion: mooring.io/v1alpha1
kind: MasqPortRange
metadata:
  name: pod-foo-prod-gateway
spec:
  podName: pod-foo
  podNamespace: default
  podIP: 10.0.0.5
  nodeName: node-1
  gateway: prod-gateway
  allocations:
    - externalIP: 203.0.113.1
      portStart: 1000
      portEnd: 1099
    - externalIP: 203.0.113.2
      portStart: 1100
      portEnd: 1199
status:
  deletionGracePeriodExpiry: ""  # set on pod deletion; range held until expiry
```

### MasqPortRangeRequest

Namespace-scoped. Created by the daemon when a new client pod starts. The operator allocates port ranges, creates the corresponding `MasqPortRange`, and deletes the request.

```yaml
apiVersion: mooring.io/v1alpha1
kind: MasqPortRangeRequest
metadata:
  name: pod-foo-prod-gateway
  namespace: default
spec:
  podName: pod-foo
  podNamespace: default
  podIP: 10.0.0.5
  nodeName: node-1
  gateway: prod-gateway
  portRangeSize: 100  # optional; defaults to Gateway.spec.defaultPortRangeSize
```

## Components

### Operator (Deployment)

- Watches `MasqPortRangeRequest` resources and allocates non-overlapping port ranges.
- Creates `MasqPortRange` resources.
- Enforces a deletion grace period (default 240 s, to cover `TIME_WAIT` expiry) before freeing port ranges.

### Daemon (DaemonSet)

- Watches pods matching Gateway selectors; creates `MasqPortRangeRequest` for new pods.
- Syncs `MasqPortRange` resources into SNAT config and port-range lookup BPF maps.
- Runs a BGP speaker that advertises all external IPs from all Gateways.
- Installs and pins BPF programs (`cil_from_container`, `cil_from_netdev`, `cil_to_container`) via CiliumDatapathPlugin.
- Performs periodic NAT table cleanup for stale entries.

## Update Resiliency

BPF programs and maps are pinned to bpffs at `/sys/fs/bpf/mooring/`. On daemon restart, existing programs keep running and in-flight connections are unaffected. The daemon re-attaches to pinned maps and reconciles state against the API server. Node-level updates (kernel upgrades, etc.) require pod eviction, handled by the normal grace period mechanism.

## Limitations

- **Max concurrent connections** per pod per external IP is bounded by the assigned port range size. High-churn pods should use a dedicated IP pool with a larger `defaultPortRangeSize`.
- **Cilium with BPF host routing is required.** Non-Cilium CNI compatibility is not planned.
- **BGP underlay with native pod routing is required.** Overlay networks are not supported.
