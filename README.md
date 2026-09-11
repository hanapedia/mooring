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
- **CNI-agnostic by default** — works with any veth-based CNI; Cilium is an optional integration.

## Requirements

- **BGP underlay** with pod CIDRs advertised natively (overlay networks are not supported).
- **Veth-based pod networking** — any CNI that creates a veth pair per pod works out of the box.
- **Cilium CNI** with BPF host routing and the CiliumDatapathPlugin API are required only when the Cilium integration feature is enabled.

## How It Works

### Outbound

The client pod's node performs SNAT using a pre-allocated port range. A TC egress BPF program on the node uplink rewrites the source to `externalIP:NAT-port` and records the mapping in a per-node NAT table.

### Return path (two stages)

Return traffic is distributed across all nodes via BGP ECMP. A single TC ingress BPF program on the node uplink handles both revNAT stages:

1. **Stage 1 — IP revNAT:** If the destination is a known external IP, the program resolves the pod IP from the NAT port using the shared port-range lookup map and rewrites the destination IP.

2. **Stage 2 — port revNAT:** The program then looks up the full NAT table entry and restores the original pod port. If the pod is on the same node (**same-node optimization**), both stages complete in a single BPF pass. If the pod is on a different node, BGP routes the packet there and the uplink ingress program on that node handles stage 2.

This two-stage split works because port ranges are unique per `(pod, external IP)` pair — the NAT port alone identifies both the pod and which external IP was used, without carrying extra state through the network.

### Conntrack

On a transit node (stage 1 ran here but the pod lives elsewhere), conntrack would see the stage 1 IP rewrite as an untracked connection and mark the packet INVALID, causing `KUBE-FORWARD` to drop it. mooring avoids this without any iptables rules: the stage 1 not-local path uses `bpf_redirect_neigh` instead of `TC_ACT_OK`, sending the packet directly through the kernel FIB and neighbor subsystem and bypassing netfilter entirely. mooring's own BPF maps are the authoritative connection state.

## Architecture

```
               ┌──────────────┐
               │  client pod  │
               └──────┬───────┘
                      │
               node uplink
                      │ TC egress (SNAT: pod-IP:pod-port → extIP:NAT-port)
                      ▼
                BGP routing → external server

     ┌──────────────────────────────────────────────────────────────┐
     │ Return path                                                   │
     │                                                               │
     │  external server                                              │
     │    → any node (ECMP)                                          │
     │    → TC ingress — node uplink  [Stage 1: IP revNAT]           │
     │        extIP:NAT-port → pod-IP:NAT-port                       │
     │        same-node? → [Stage 2: port revNAT]                    │
     │            pod-IP:NAT-port → pod-IP:pod-port → pod ✓          │
     │        cross-node? → BGP routing to pod's node                │
     │            → TC ingress — node uplink  [Stage 2: port revNAT] │
     │                pod-IP:NAT-port → pod-IP:pod-port → pod ✓      │
     └──────────────────────────────────────────────────────────────┘
```

## BPF Attachment Modes

### Default (CNI-agnostic, node uplink)

Both BPF programs attach to the node uplink once at daemon startup via netlink. No per-pod veth
management is required.

| Hook | Interface | Direction | Role |
|---|---|---|---|
| TC egress | node uplink | egress | Outbound SNAT |
| TC ingress | node uplink | ingress | Combined stage 1 + 2 revNAT |

Per-veth attachment (narrower scope, per-pod TC management) is planned as a future configuration option.

### Cilium integration (optional)

When enabled, the daemon uses the CiliumDatapathPlugin API to attach programs into Cilium's existing datapath hooks (`cil_from_container`, `cil_from_netdev`, `cil_to_container`). Requires Cilium with BPF host routing. This mode is tested as a secondary target.

## Custom Resources

API group: `hanapedia.link/v1alpha1`.

### NATConfig

Cluster-scoped. Defines the egress policy and external IP pool for a set of client pods.

```yaml
apiVersion: hanapedia.link/v1alpha1
kind: NATConfig
metadata:
  name: prod
spec:
  externalIPPool:
    - "203.0.113.0/28"
  portRangeSize: 100
  targetCIDRs:
    - "0.0.0.0/0"
  podSelector:
    matchLabels:
      egress: prod
```

| Field | Description |
|---|---|
| `externalIPPool` | CIDR blocks providing the external (SNAT) IPs |
| `portRangeSize` | Fixed number of ports per allocation block; uniform across all pods in this NATConfig |
| `targetCIDRs` | Destination CIDRs for which SNAT is applied |
| `podSelector` | Selects client pods this NATConfig applies to |

### NATPortRange

Cluster-scoped. Created by the operator; one per `(pod, NATConfig)` pair. Records all port range
allocations for that pod across every external IP in the pool. Named
`{podNamespace}-{podName}-{natConfigName}`. Owned by the corresponding `NATPortRangeRequest` —
Kubernetes GC deletes it automatically when the request is deleted. Carries a finalizer
(`mooring.hanapedia.link/allocation`) so the operator can reclaim block indices before GC removes
the object.

All daemon pods watch this resource and sync it into the stage 1 port-range lookup BPF maps.
When `externalIPPool` changes, the operator updates `allocations` in place rather than deleting
and recreating the resource.

```yaml
apiVersion: hanapedia.link/v1alpha1
kind: NATPortRange
metadata:
  name: default-pod-foo-prod
  finalizers:
    - mooring.hanapedia.link/allocation
spec:
  podName: pod-foo
  podNamespace: default
  podIP: 10.0.0.5
  nodeName: node-1
  natConfig: prod
  portRangeCount: 1   # mirrored from NATPortRangeRequest; used by NATConfig controller
  allocations:
    - externalIP: 203.0.113.1
      portStart: 1300
      portEnd: 1399
    - externalIP: 203.0.113.2
      portStart: 1700
      portEnd: 1799
```

### NATPortRangeRequest

Cluster-scoped. Created by the daemon when a new client pod starts; exists for the pod's entire
lifetime. Named `{podNamespace}-{podName}-{natConfigName}`.

The operator ensures a `NATPortRange` exists for every `NATPortRangeRequest`. On pod deletion,
the daemon sets `status.deletionGracePeriodExpiry` (default 240 s, to cover `TIME_WAIT` expiry)
and deletes the request after expiry. Kubernetes GC then removes the owned `NATPortRange`.

```yaml
apiVersion: hanapedia.link/v1alpha1
kind: NATPortRangeRequest
metadata:
  name: default-pod-foo-prod
spec:
  podName: pod-foo
  podNamespace: default
  podIP: 10.0.0.5
  nodeName: node-1
  natConfig: prod
  portRangeCount: 1  # optional; number of fixed-size blocks per external IP; defaults to 1
status:
  deletionGracePeriodExpiry: ""  # set by daemon on pod deletion
```

## Components

### Operator (Deployment)

- **Startup reconstruction**: before reconciling any `NATPortRangeRequest`, replays all existing
  `NATPortRange` allocations into the in-memory allocator so new allocations never conflict with
  existing ones — critical for correctness when the operator restarts with pending requests.
- **NATPortRangeRequest controller**: ensures a `NATPortRange` exists for every request. Allocates
  `portRangeCount` blocks per external IP from a per-NATConfig `BlockAllocator` (per-IP free sets;
  different pods may share block indices on different IPs). Handles `portRangeCount` increases
  (allocate delta per IP) and decreases (free excess blocks). Creates `NATPortRange` with an owner
  reference and a finalizer for safe block reclamation.
- **NATPortRange controller**: when GC marks a `NATPortRange` for deletion (triggered by
  `NATPortRangeRequest` deletion), frees the allocated block indices back to the per-IP free sets
  and removes the finalizer.
- **NATConfig controller**: when `externalIPPool` changes, updates each affected `NATPortRange`
  in place — adds allocations for new IPs, removes allocations for dropped IPs. Reads
  `portRangeCount` from the `NATPortRange` spec directly; never reads `NATPortRangeRequest`.
- Never creates, updates, or deletes `NATPortRangeRequest` — the daemon owns its lifecycle.

### Daemon (DaemonSet)

- Watches node-local pods (field selector on `spec.nodeName`); creates `NATPortRangeRequest` for
  new pods matching a NATConfig selector; sets the deletion grace period on pod removal.
- Deletes `NATPortRangeRequest` after its grace period expires.
- Watches `NATConfig` selector changes; reconciles local pods to create or retire requests.
- Syncs `NATPortRange` resources into SNAT config (local node) and per-protocol port-range lookup
  BPF maps (all nodes).
- Runs a BGP speaker that advertises all external IPs from all NATConfigs.
- Attaches TC BPF programs to the node uplink at startup via netlink (default mode; no per-pod TC
  attachment); uses CiliumDatapathPlugin in Cilium mode.
- Performs periodic NAT table cleanup for stale entries.

## Update Resiliency

BPF programs and maps are pinned to bpffs at `/sys/fs/bpf/mooring/`. On daemon restart, existing programs keep running and in-flight connections are unaffected. The daemon re-attaches to pinned maps and reconciles state against current `NATPortRange` resources. Node-level updates (kernel upgrades, etc.) require pod eviction, handled by the normal grace period mechanism.

## Limitations

- **Max concurrent connections** per pod per external IP is bounded by `portRangeSize × portRangeCount`. Pods needing more capacity should request a higher `portRangeCount` in their NATPortRangeRequest.
- **BGP underlay with native pod routing is required.** Overlay networks are not supported.
- **Cilium mode** requires Cilium with BPF host routing and CiliumDatapathPlugin. It may have ordering dependencies with other TC programs on the uplink and is tested as a secondary target.
