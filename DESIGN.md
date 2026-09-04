# mooring — Egress NAT with Connection Resiliency

## Motivation

Kubernetes egress NAT implementations (e.g. cybozu-go/coil) typically dedicate specific pods to
perform SNAT on behalf of client pods. Global IPs are bound to these NAT pods and advertised via
BGP. When NAT pods are restarted during rollout, all active connections passing through them are
dropped — there is no way to hand over in-flight TCP state.

mooring eliminates this downtime by distributing NAT across all nodes and decoupling the external IP
identity from any individual pod or node.

---

## Assumptions

- **BGP underlay**: pod CIDRs are advertised via BGP, making pod IPs natively routable across the
  cluster without encapsulation.
- **Veth-based pod networking**: the CNI creates a veth pair per pod, with the host-side end
  visible in the root network namespace. This is true of virtually all CNI plugins.
- **Cilium CNI** with **BPF host routing** and the **CiliumDatapathPlugin** API are required only
  when the Cilium integration feature is enabled (see [BPF Attachment Modes](#bpf-attachment-modes)).

---

## Key Properties

- No encapsulation — no MTU overhead, no tunnel management.
- No dedicated NAT pods — the client pod's own node performs SNAT.
- External IPs are shared across all nodes — any node can receive and process return traffic.
- BPF programs and maps are pinned to bpffs — existing connections survive daemon restarts.
- Port ranges are per (pod, external IP) pair — no NAT table collisions by construction.
- **CNI-agnostic by default** — works with any veth-based CNI; Cilium is an optional integration.

---

## Architecture Overview

Each node running a client pod also acts as the SNAT node for that pod. External IPs from the
Gateway's pool are advertised by all nodes via BGP, creating ECMP paths for return traffic. Return
packets are processed in two stages:

1. **Stage 1 (any node)** — stateless IP revNAT: resolves pod IP from the NAT port, rewrites
   `dst` to pod IP, forwards via BGP routing.
2. **Stage 2 (client node)** — stateful port revNAT: looks up the full NAT table entry, rewrites
   `dst-port` to the original pod port.

This two-stage design is possible because port ranges are allocated uniquely per (pod, external IP)
pair, so the NAT port alone identifies the pod without needing to carry the external IP through
the return path.

---

## BPF Attachment Modes

### Default mode (CNI-agnostic)

The daemon attaches BPF programs directly via netlink using standard Linux TC hooks. No CNI
plugin API is required.

| Hook | Interface | Direction | Role |
|---|---|---|---|
| TC egress | host-side veth | egress | Outbound SNAT |
| TC ingress | node uplink | ingress | Stage 1: IP revNAT |
| TC ingress | host-side veth | ingress | Stage 2: port revNAT |

The daemon locates the host-side veth for each client pod by inspecting the pod's network
namespace (via `/proc/<pid>/ns/net`) and resolving the peer index via netlink. TC programs are
attached and detached as pods start and stop.

**Conntrack bypass:** kernel conntrack is incompatible with the two-stage revNAT because it
would see the stage 1 IP rewrite without having tracked the original connection from the pod IP.
The daemon installs `iptables -t raw` `NOTRACK` rules for the external IP pool on startup:

```
iptables -t raw -A PREROUTING  -d <external-IP-pool> -j NOTRACK
iptables -t raw -A OUTPUT      -s <external-IP-pool> -j NOTRACK
```

This ensures conntrack is bypassed for all NAT traffic; mooring's own BPF maps are the
authoritative connection state.

### Cilium integration (optional feature)

When enabled, the daemon uses the CiliumDatapathPlugin API instead of direct TC attachment.

| Hook | Cilium equivalent | Role |
|---|---|---|
| TC egress on host-side veth | `cil_from_container` | Outbound SNAT |
| TC ingress on node uplink | `cil_from_netdev` extension | Stage 1: IP revNAT |
| TC ingress on host-side veth | `cil_to_container` | Stage 2: port revNAT |

Conntrack bypass is not needed in this mode because Cilium's BPF host routing already disables
kernel conntrack cluster-wide.

**Caveats:** Cilium mode introduces ordering dependencies with other TC programs on the uplink
interface. Coexistence must be validated per Cilium version. This mode is tested as a secondary
target; the default mode is the reference implementation.

---

## Port Allocation Strategy

### Problem

If the same NAT port number is used for the same pod across two different external IPs, the stage 2
NAT table — keyed on `{pod-IP, NAT-port, server-IP, server-port}` — cannot distinguish the two
connections.

### Solution: non-overlapping ranges per (pod, external IP)

The operator allocates a distinct, non-overlapping port range for each (pod, external IP) pair.
For example:

```
pod-foo on 203.0.113.1 → ports [1000, 1099]
pod-foo on 203.0.113.2 → ports [1100, 1199]
pod-bar on 203.0.113.1 → ports [1200, 1299]
pod-bar on 203.0.113.2 → ports [1300, 1399]
```

Because ranges do not overlap across external IPs for the same pod, the NAT port implicitly
encodes which external IP was used. The stage 2 NAT table key is always unambiguous.

Port exhaustion per external IP is an operational concern mitigated by provisioning separate IP
pools for high-churn and low-churn client pods.

---

## Custom Resources

### Gateway

Cluster-scoped. Defines the egress policy for a set of client pods.

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
| `defaultPortRangeSize` | Default number of ports per (pod, external IP) allocation |
| `targetCIDRs` | Destination CIDRs for which SNAT is applied |
| `podSelector` | Selects client pods that this Gateway applies to |

### MasqPortRange

Cluster-scoped. Created by the operator; one per client pod. Records all port range allocations
for that pod across every external IP in the pool.

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
  deletionGracePeriodExpiry: ""   # set when pod is deleted; range not freed until this time
```

All daemon pods on every node watch `MasqPortRange` resources and sync them into the stage 1
port-lookup BPF map.

### MasqPortRangeRequest

Namespace-scoped. Created by the daemon on the node where a new client pod starts. The operator
watches these, allocates ranges, creates the corresponding `MasqPortRange`, and deletes the
request.

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
  portRangeSize: 100   # optional; defaults to Gateway.spec.defaultPortRangeSize
```

---

## BPF Maps

### NAT table (per node, outbound node only)

Keyed on the return packet's headers as they arrive at the client node after stage 1 revNAT.

| Field | Role |
|---|---|
| Key: `{pod-IP, NAT-port, server-IP, server-port, proto}` | Uniquely identifies a connection |
| Value: `{pod-port}` | Original source port to restore |

Type: `BPF_MAP_TYPE_LRU_HASH`. Entries are evicted when the map is full; TTL-based cleanup is
performed by the daemon for closed connections.

### Port-range lookup map (all nodes)

Used by stage 1 to resolve pod IP from an incoming return packet's `(external-IP, dst-port)`.

One array map per external IP, indexed by port number (size 65536):

| Index | Value |
|---|---|
| NAT-port (0–65535) | pod-IP (0 if unallocated) |

Type: `BPF_MAP_TYPE_ARRAY`. Updated by each daemon when `MasqPortRange` resources change.

### SNAT config map (per node, outbound node only)

Provides the outbound BPF program with the port ranges for each local client pod.

| Field | Role |
|---|---|
| Key: `pod-IP` | Client pod |
| Value: `[{externalIP, portStart, portEnd, nextPort}, ...]` | All allocated ranges; `nextPort` is an atomic counter for port selection |

Type: `BPF_MAP_TYPE_HASH`. Updated by the daemon when `MasqPortRange` resources change.

---

## Packet Flow

The hook names below use the default (CNI-agnostic) TC attachment. See
[BPF Attachment Modes](#bpf-attachment-modes) for the Cilium equivalents.

### Outbound (client pod → external server)

```
client pod
  │  src=pod-IP:pod-port, dst=server-IP:server-port
  ▼
TC egress — host-side veth  (attached to egress-client pods only)
  │  matches dst against Gateway targetCIDRs
  │  looks up pod-IP in SNAT config map → selects externalIP + allocates NAT-port
  │  writes NAT table: {pod-IP, NAT-port, server-IP, server-port} → {pod-port}
  │  SNATs src: pod-IP:pod-port → externalIP:NAT-port
  ▼
BGP routing
  ▼
external server  (sees src=externalIP:NAT-port)
```

### Return path — Stage 1: IP revNAT (any node)

```
external server
  │  src=server-IP:server-port, dst=externalIP:NAT-port
  ▼
Any node (BGP ECMP)
  ▼
TC ingress — node uplink  (all nodes)
  │  checks dst-IP against external IP pool
  │  looks up port-range map[externalIP][NAT-port] → pod-IP
  │  rewrites dst: externalIP:NAT-port → pod-IP:NAT-port
  ▼
BGP routing  (pod-IP is routable → packet forwarded to pod's node)
  ▼
```

### Return path — Stage 2: port revNAT (client node)

```
  ▼
Client node
  │  src=server-IP:server-port, dst=pod-IP:NAT-port
  ▼
TC ingress — host-side veth  (attached to egress-client pods only)
  │  looks up NAT table: {pod-IP, NAT-port, server-IP, server-port} → {pod-port}
  │  rewrites dst-port: NAT-port → pod-port
  ▼
client pod  (src=server-IP:server-port, dst=pod-IP:pod-port ✓)
```

---

## Components

### Operator

Runs as a Deployment (single replica with leader election).

Responsibilities:
- Watches `MasqPortRangeRequest` resources.
- Allocates non-overlapping port ranges per (pod, external IP) pair from the Gateway's pool.
- Creates `MasqPortRange` resources.
- Enforces the grace period on `MasqPortRange` deletion: sets
  `status.deletionGracePeriodExpiry` when a pod is deleted, and only removes the resource after
  the expiry.

### Daemon

Runs as a DaemonSet on all nodes.

Responsibilities:
- Watches pods with matching Gateway `podSelector`; creates `MasqPortRangeRequest` for new pods.
- Watches `MasqPortRange` resources; syncs allocations into the SNAT config map and port-range
  lookup map.
- Runs a BGP speaker that advertises all external IPs from all Gateways.
- **Default mode**: attaches and detaches TC BPF programs on host-side veth interfaces and the
  node uplink via netlink; installs `iptables -t raw NOTRACK` rules for the external IP pool.
- **Cilium mode**: installs BPF programs via CiliumDatapathPlugin instead of direct TC attachment;
  skips NOTRACK rules.
- Performs periodic NAT table cleanup for stale entries.

---

## Pod Lifecycle

### New pod startup

1. Pod is scheduled on a node and its network namespace is configured by the CNI plugin.
2. Daemon on that node detects the new pod (via pod informer) and creates a
   `MasqPortRangeRequest`.
3. Operator allocates port ranges and creates a `MasqPortRange`.
4. Daemon on every node syncs the new `MasqPortRange` into the port-range lookup map.
5. Daemon on the pod's node syncs the SNAT config map and attaches the outbound and inbound BPF
   programs to the pod's host-side veth (default mode) or pod endpoint via CiliumDatapathPlugin
   (Cilium mode).
6. Pod is marked ready.

### Pod deletion

1. Pod is deleted; daemon detects deletion.
2. Operator sets `status.deletionGracePeriodExpiry` on the pod's `MasqPortRange` (default: 240s,
   to cover `TIME_WAIT` expiry).
3. After expiry, operator deletes the `MasqPortRange`.
4. Daemons on all nodes sync the deletion out of the port-range lookup map.

---

## Update Resiliency

BPF programs and maps are pinned to bpffs (`/sys/fs/bpf/mooring/`). On daemon restart:

- Existing BPF programs continue running — in-flight connections are unaffected.
- The daemon re-attaches to pinned maps and reconciles their state against current `MasqPortRange`
  resources in the API server.
- No packet loss occurs during daemon rollout.

Node-level updates (kernel upgrade, etc.) require pod eviction, which triggers normal port range
cleanup via the grace period mechanism.

---

## Limitations

- **Max concurrent connections per pod per external IP** is bounded by the assigned port range
  size. Pods with high connection churn should be assigned to a dedicated IP pool with a larger
  default range size.
- **Requires BGP underlay** with pod CIDRs advertised (native routing). Overlay networks are not
  supported.
- **Cilium mode requires** Cilium with BPF host routing and the CiliumDatapathPlugin API. It is
  tested as a secondary target and may have ordering dependencies with other TC programs on the
  uplink interface.

---

## Open Questions

- **Same-node optimization**: when ECMP routes a return packet directly to the client node, stages
  1 and 2 could be merged into a single BPF pass. Deferred to implementation.
- **Port selection across multiple external IPs**: fill-first (use one IP until range is exhausted,
  then spill to the next) vs. round-robin per connection. Deferred to implementation.
- **BPF map type for port-range lookup**: per-external-IP array (simple, O(1), ~256 KB per IP) is
  the baseline; alternatives can be evaluated during implementation.
- **TC program coexistence on the uplink**: if other tools (e.g. bandwidth shaping, observability)
  also attach TC programs to the node uplink, ordering and priority need to be defined. The
  default mode must document expected TC chain position.
