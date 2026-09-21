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
- **Sidecar BGP daemon**: each node runs an external BGP daemon (e.g. FRR, BIRD) as a sidecar or
  node-level DaemonSet pod that is already part of the DC BGP fabric. The mooring daemon peers with
  it over localhost. The sidecar must accept the mooring peer as a passive neighbor (mooring
  initiates the TCP connection).
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

### Default mode (CNI-agnostic, node uplink)

Both BPF programs attach once to the node uplink interface at daemon startup. No per-pod veth
management is required.

| Hook | Interface | Direction | Role |
|---|---|---|---|
| TCX egress (head) | node uplink | egress | Outbound SNAT |
| TCX ingress (head) | node uplink | ingress | Combined stage 1 + 2 revNAT |

The egress program matches outbound packets by looking up the source pod IP in the nat_config
map. The ingress program handles both revNAT stages in a single pass:

- If the destination is a known external IP, it performs stage 1 (IP revNAT) and then attempts
  stage 2 immediately — the **same-node optimization** succeeds when `nat_map` has a revnat entry
  for the pod (i.e., the pod is local). If it misses, the packet is forwarded by BGP
  to the pod's node where the uplink ingress program there handles stage 2.
- If the destination is already a pod IP (cross-node: stage 1 ran on another node), stage 2 is
  performed directly.

**Conntrack bypass:** on a transit node (stage 1 ran here, pod is on another node), conntrack
would see the rewritten SYN-ACK as a new, untracked connection and mark it INVALID — causing
`KUBE-FORWARD`'s `ctstate INVALID -j DROP` rule to drop the packet before it can be forwarded.

Instead of iptables NOTRACK rules, the stage 1 not-local path returns
`bpf_redirect_neigh(skb->ifindex, NULL, 0, 0)` rather than `TCX_NEXT`. This sends the packet
directly through the kernel's FIB + neighbor subsystem, bypassing netfilter entirely. The correct
L2 dst MAC is resolved automatically; no iptables rules are installed. mooring's own BPF maps are
the authoritative connection state.

### Per-veth attachment (future configuration option)

A future configuration mode will allow attaching the SNAT program to each client pod's
host-side veth and the port revNAT program to the host-side veth ingress. This narrows the
scope of packet inspection to client pods only, at the cost of per-pod TC attachment management.

| Hook | Interface | Direction | Role |
|---|---|---|---|
| TCX egress (head) | host-side veth | egress | Outbound SNAT (client pods only) |
| TCX ingress (head) | node uplink | ingress | Stage 1: IP revNAT |
| TCX ingress (head) | host-side veth | ingress | Stage 2: port revNAT (client pods only) |

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

The stage 2 lookup (a revnat entry in `nat_map`, see [BPF Maps](#bpf-maps)) is keyed on
`{server-IP, server-port, pod-IP, NAT-port, proto}`. The external IP is absent from this key because
stage 1 has already overwritten the packet destination by the time stage 2 runs. If the same NAT
port were assigned to the same pod across two different external IPs, two distinct connections to
the same server could produce identical keys — causing one to overwrite the other and breaking that
connection.

### Solution: fixed-size blocks with per-IP free sets

The port space `[minPort, maxPort]` for each external IP is divided into fixed-size blocks of
`NATConfig.portRangeSize` ports. Each block index `k` maps to an unambiguous port range:

```
block k → [minPort + k × portRangeSize,  minPort + (k+1) × portRangeSize − 1]
```

The operator maintains a **per-IP free-block set** (one per external IP per NATConfig) of
available block indices. For a given pod, `AllocateForPod` draws `portRangeCount` indices from
each IP's free set while maintaining a cross-IP exclusion set — no index is reused across the same
pod's IPs. This guarantees the pod's port ranges are non-overlapping across all external IPs.

Critically, **different pods may hold the same block index on different IPs simultaneously** — the
constraint is per-pod, not global. This efficient reuse is what makes the per-IP free-set design
preferable to a single global pool.

```
portRangeCount=1, 2 external IPs, portRangeSize=100

pod-foo allocated:
  ext-ip-1: block 3 → ports [1300, 1399]
  ext-ip-2: block 7 → ports [1700, 1799]   ← indices 3 and 7 differ; non-overlapping ✓

pod-bar allocated (same cluster, different pod):
  ext-ip-1: block 7 → ports [1700, 1799]   ← block 7 free on ext-ip-1; reused ✓
  ext-ip-2: block 3 → ports [1300, 1399]   ← block 3 free on ext-ip-2; reused ✓

pod-foo on ext-ip-1 (block 3) and pod-bar on ext-ip-1 (block 7): non-overlapping ✓
pod-foo's own indices across its IPs (3, 7) are distinct: NAT table unambiguous ✓
pod-bar's own indices across its IPs (7, 3) are distinct: NAT table unambiguous ✓
```

A pod needing more NAT capacity requests a higher `portRangeCount`; the block size itself is fixed
per NATConfig and never overridden per-pod. Freed blocks are returned to the per-IP free set as an
idempotent map insertion (making double-free a safe no-op) and reused on the next allocation.

---

## Custom Resources

API group: `hanapedia.link/v1alpha1`.

### NATConfig

Cluster-scoped. Defines the egress policy for a set of client pods.

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
  nodeSelector:           # optional; omit to advertise from all nodes
    matchLabels:
      node-role: nat-gateway
```

| Field | Description |
|---|---|
| `externalIPPool` | CIDR blocks providing the external (SNAT) IPs |
| `portRangeSize` | Fixed number of ports per allocation block; applies uniformly to all pods |
| `targetCIDRs` | Destination CIDRs for which SNAT is applied |
| `podSelector` | Selects client pods that this NATConfig applies to |
| `nodeSelector` | Optional. Selects which nodes advertise pool CIDRs via BGP for the return path. If omitted, all nodes advertise. BPF maps are updated on all nodes regardless of this field. |

### NATPortRange

Cluster-scoped. Created by the operator when a NATPortRangeRequest appears; one per (pod, NATConfig)
pair. Records all port range allocations for that pod across every external IP in the pool.
Named `{podNamespace}-{podName}-{natConfigName}`. Owned by the corresponding NATPortRangeRequest
(Kubernetes GC deletes it when the request is deleted). Carries a finalizer
(`mooring.hanapedia.link/allocation`) so the operator can reclaim block indices before deletion.

```yaml
apiVersion: hanapedia.link/v1alpha1
kind: NATPortRange
metadata:
  name: default-pod-foo-prod
  finalizers:
    - mooring.hanapedia.link/allocation
  ownerReferences:
    - apiVersion: hanapedia.link/v1alpha1
      kind: NATPortRangeRequest
      name: default-pod-foo-prod
spec:
  podName: pod-foo
  podNamespace: default
  podIP: 10.0.0.5
  nodeName: node-1
  natConfig: prod
  targetCIDRs:          # copied from NATConfig.spec.targetCIDRs at creation time
    - "0.0.0.0/0"
  portRangeCount: 1     # mirrors the NPRR value; used by NATConfig controller without reading NPRR
  allocations:
    - externalIP: 203.0.113.1
      portStart: 1300
      portEnd: 1399
    - externalIP: 203.0.113.2
      portStart: 1700
      portEnd: 1799
  staleSince: null      # set by daemon NPRR controller when pod grace period expires
```

All daemon pods on every node watch `NATPortRange` resources and sync them into the stage 1
port-range lookup BPF map. When `externalIPPool` changes on the NATConfig, the operator updates
the `allocations` slice in place — no delete-and-recreate is required. The operator's NATConfig
controller skips NPRs with `staleSince` set to avoid re-adding BPF entries that are being cleaned up.

### NATPortRangeRequest

Cluster-scoped. Created by the daemon on the node where a new client pod starts and destroyed by
the daemon after the pod's deletion grace period expires. Named `{podNamespace}-{podName}-{natConfigName}`.

The request exists for the entire lifetime of the client pod. The operator watches it and ensures
a corresponding `NATPortRange` exists at all times.

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
  portRangeCount: 1   # optional; number of fixed-size blocks per external IP; defaults to 1
status:
  deletionGracePeriodExpiry: ""  # set by daemon on pod deletion; request held until expiry
```

---

## BPF Maps

### nat_map (per node, outbound node only)

A single map holds both directions of every tracked connection — the forward (snat) entry the
egress program uses to reuse or allocate a port, and the reverse (revnat) entry the ingress program
uses to restore the original pod port. A live connection always occupies exactly one of each:

| Entry | Key | Value |
|---|---|---|
| snat   | `{pod-IP, pod-port, server-IP, server-port, proto, kind=SNAT}`   | `{ext-IP, NAT-port, closing_ns}` |
| revnat | `{server-IP, server-port, pod-IP, NAT-port, proto, kind=REVNAT}` | `{ext-IP, pod-port, closing_ns}` |

Both entries share one generic key shape (`ip_a, ip_b, port_a, port_b, proto, kind`) and one generic
value shape (`nat_ip, port, closing_ns`) — `port` means NAT-port on a snat entry and pod-port on a
revnat entry. `kind` exists purely so the two entry shapes can never collide: without it, a snat key
and a revnat key draw from the same `(IP, port, IP, port, proto)` domain, so one flow's forward key
could in principle coincide with a different flow's reverse key (e.g. if some server's own
`IP:port` happened to equal another flow's `pod-IP:NAT-port`). With `kind` in the key, that's
structurally impossible rather than merely unlikely.

Both `snat_egress` and `revnat_ingress` read and write this same map (`revnat_ingress` needs the
snat side too, for connection tracking on the server→pod direction — see "Connection tracking and
port reclamation" below), so it's shared between the two programs the same way `target_cidrs` is.

Type: `BPF_MAP_TYPE_LRU_HASH`, `max_entries = 131072`. Sized as `2 × 65536`: every connection holds
exactly one snat and one revnat entry, and 65536 concurrent connections matches what this map
replaced. (An earlier design used three separate 65536-entry per-protocol NAT tables for the revnat
side plus one more 65536-entry map for the forward/session side — nominally 4×65536 capacity, but
the forward map was never itself split per protocol, so it was already the binding constraint at
65536 total connections regardless of protocol mix; the per-protocol split on the reverse side never
actually bought extra capacity in practice. `nat_map` makes that honest with one map sized for the
capacity that was actually reachable.) Entries are evicted under global map pressure regardless of
protocol or direction — this was already true of the old forward/session map, which was never
protocol-split either; unifying doesn't reduce isolation that existed before. For TCP, entries are
additionally removed proactively — see "Connection tracking and port reclamation" below. UDP and
ICMP entries are never proactively removed; LRU eviction is their only cleanup path.

### Port-range lookup map (all nodes)

Used by stage 1 to resolve pod IP from an incoming return packet's `(external-IP, dst-port)`.

Implemented as three `BPF_MAP_TYPE_HASH_OF_MAPS` maps (one per IP protocol: TCP, UDP, ICMP):

- **Outer map**: keyed by `ext-IP (u32)`, value is the FD of the corresponding inner map.
- **Inner map** (`BPF_MAP_TYPE_ARRAY`, 65536 entries): indexed by port number (host order); value is pod-IP (`u32`, 0 if unallocated).

| Outer key | Inner index | Inner value |
|---|---|---|
| ext-IP | NAT-port (0–65535) | pod-IP (0 if unallocated) |

Each daemon syncs all `NATPortRange` resources into these maps regardless of node ownership, because any node can be the stage 1 revNAT node for a given return packet.

### nat_config map (per node, outbound node only)

Provides the outbound BPF program with the port ranges for each local client pod, scoped per target CIDR.

| Field | Role |
|---|---|
| Key: `{pod-IP, cidr-addr, cidr-prefixlen}` | Client pod + matched target CIDR |
| Value: `[{externalIP, portStart, portEnd}, ...]` | All allocated ranges for that (pod, target-CIDR) pair |

Type: `BPF_MAP_TYPE_HASH`, `max_entries = 65536`. Updated by the daemon when `NATPortRange` resources change.

The compound key is necessary because a pod may match multiple NATConfigs with different target CIDRs — each target CIDR implies a distinct external IP pool. Keying by `(pod-IP, target-CIDR)` lets the egress program pick the correct ext-IP pool based on which CIDR the packet's destination fell into. As a side effect, each `(pod, target-CIDR)` entry has an independent port-allocation state, so the usable ports per (pod, target-CIDR) pair is the full range size rather than a fraction shared across pools.

### Port allocation within a block (egress node)

Each `{externalIP, portStart, portEnd}` entry has no free list and no counter — the range's size
(`portEnd - portStart + 1`) is all the state that's needed. On a new connection, the egress program
picks one entry (see "picking an entry" below), then within it picks a starting port via
`clamp_to_range(port_start, port_end, seed)` — a fixed-point projection of a 16-bit seed onto
`[port_start, port_end]` (`start + (seed * range) >> 16`), the same technique Cilium's `bpf_nat.h`
uses for SNAT port selection. The seed is the connection's own pod-side port (TCP/UDP source port,
or the ICMP echo id), so port selection is deterministic per flow rather than drawing from
`bpf_get_prandom_u32()` — cheaper (a multiply and a shift instead of a helper call plus a modulo by
a non-constant divisor) and harmless to determinize, since a "collision" is scoped to the full
`(pod-IP, port, server-IP, server-port)` tuple: two flows from the same pod-side port to *different*
destinations landing on the same starting port were never going to collide with each other anyway.

- **ICMP**: uses the seeded port unconditionally, overwriting whatever was there. Echo-id collisions
  are cheap and short-lived, so no collision checking is done at all.
- **TCP/UDP**: probes up to a fixed number of attempts (`MAX_PORT_ATTEMPTS`) starting from the seeded
  port, stepping linearly on collision. A "collision" means a revnat entry already exists in
  `nat_map` for that exact `(server-IP, server-port, pod-IP, candidate-port, proto)` tuple. If
  every attempt collides, that entry is exhausted for this connection and the egress program samples
  another one of the pod's entries (see below); if none of the sampled entries have room, the new
  connection fails (no SNAT applied) rather than forcing an allocation.

Picking *which* entry to try when a pod has more than one (multiple external IPs) is
`MAX_ENTRY_ATTEMPTS` independent samples (with replacement) from `cv->port_range_allocs[0..count-1]`,
trying each until one succeeds, via `clamp_to_range(0, count-1, pod_port + attempt)` — the same
fixed-point projection as port selection, just onto `[0, count-1]` instead of `[port_start,
port_end]` (`clamp_to_range` with `start = 0`). Folding the entry-attempt index into the seed is
what keeps a with-replacement resample of the same entry from recomputing the identical index and, in
turn, the identical starting port and already-failed probe sequence.

This removes `bpf_get_prandom_u32()` from the allocation path entirely (an earlier version used
`bpf_get_prandom_u32() % count` here) and, unlike that modulo, needs no defensive clamp or
compiler-barrier workaround: multiply-by-a-runtime-value followed by a constant shift is a shape the
verifier's own scalar range tracking bounds directly (confirmed by an actual `bpftool prog load`
against a real kernel), whereas `%` by a non-constant divisor gets no tracked bound at all — the
`bpf_get_prandom_u32() % count` version needed an explicit `if (idx >= MAX_PORT_RANGE_ALLOCS) idx = 0`
clamp wrapped in a compiler barrier (`asm volatile("" : "+r"(idx))`) just to give the verifier
something to prove `cv->port_range_allocs[idx]` safe against; without the barrier, clang's own optimizer
proved the clamp redundant and deleted it, leaving nothing for the verifier to check.

This is still deliberately **not** an exhaustive scan of every entry: an early version tried a random
pick first and only fell back to a fixed-order scan of every remaining entry (up to `MAX_PORT_RANGE_ALLOCS`
= 256) when that one was exhausted, and that fixed-order fallback loop — wrapping the port-probe loop
above, replicated per protocol — was enough nested branching (a map lookup plus several conditionals
per inner iteration, times up to 256 outer iterations, times 3 protocols) to blow the kernel
verifier's fixed 1,000,000-instruction processing budget outright (confirmed by an actual load
failure: `argument list too long: BPF program is too large. Processed 1000001 insn`). Sampling with a
small fixed attempt count sidesteps this because the loop bound is a compile-time constant unrelated
to `cv->count` or `MAX_PORT_RANGE_ALLOCS`, at the cost of no longer being exhaustive — a pod whose block is
nearly full can occasionally fail an allocation that would have succeeded against an entry that was
never sampled. `MAX_PORT_RANGE_ALLOCS` still bounds the `port_range_allocs[]` array's storage capacity, it just no
longer drives loop iteration count.

### Connection tracking and port reclamation

Because allocation is now collision-driven rather than a one-way counter, a NAT port can be reused
as soon as the table says the old connection is gone. For TCP, this is done actively:

- Both the egress program (pod→server packets) and the ingress program's stage 2 (server→pod
  packets) inspect TCP flags on every packet of a known flow.
- The first FIN or RST seen (either direction) stamps `closing_ns = bpf_ktime_get_ns()` on both the
  connection's snat entry and its paired revnat entry in `nat_map`.
- A **second** FIN or RST seen afterward (either direction, combined with ACK) confirms the close
  and deletes both entries immediately. Requiring a second terminating segment — rather than any
  ACK — specifically avoids tearing down a half-closed connection (one side FIN'd, the other still
  sending data) onto a fresh port mid-flow.
- If the close is never confirmed (crash, dropped FIN/RST, network partition), the entries are left
  in place — not evicted proactively — but become eligible for reclamation: a later allocation whose
  collision check (against the revnat entry) finds one marked `closing` for longer than
  `NAT_CLOSING_STALE_NS` (10s) treats it as free, reclaiming the port and deleting the stale snat
  entry (the stale revnat entry is overwritten naturally once the new allocation writes to that same
  key). An entry that was never marked `closing` at all is never reclaimed this way, no matter how
  old — only LRU eviction of the whole map applies to it.

UDP and ICMP entries never get marked `closing` (there's no equivalent signal), so they're never
reclaimed by this mechanism — LRU eviction of the whole map is their only cleanup path, same as
before this change.

### Target CIDRs map

LPM trie keyed on destination IP; hit means the packet is a candidate for SNAT.

| Field | Role |
|---|---|
| Key: `{prefixlen, addr}` | Network CIDR |
| Value: `{addr, prefixlen}` | The matching entry's own network address and prefix length |

Type: `BPF_MAP_TYPE_LPM_TRIE`. The value stores the CIDR identity redundantly so the egress program can recover _which_ CIDR matched from the lookup result (BPF LPM returns the value of the matching entry, not its key) and construct the `nat_config` compound key.

---

## Packet Flow

The hook names below use the default (CNI-agnostic) TC attachment. See
[BPF Attachment Modes](#bpf-attachment-modes) for the Cilium equivalents.

### Outbound (client pod → external server)

```
client pod
  │  src=pod-IP:pod-port, dst=server-IP:server-port
  ▼
TCX egress (head) — node uplink  (all nodes; filtered by target_cidrs LPM lookup)
  │  looks up dst in target_cidrs LPM → matched CIDR {cidr-addr, cidr-prefixlen} (or miss → pass)
  │  looks up (pod-IP, cidr-addr, cidr-prefixlen) in nat_config → selects externalIP + allocates NAT-port
  │  writes nat_map snat entry:   {pod-IP, pod-port, server-IP, server-port}   → {externalIP, NAT-port}
  │  writes nat_map revnat entry: {server-IP, server-port, pod-IP, NAT-port}   → {externalIP, pod-port}
  │  SNATs src: pod-IP:pod-port → externalIP:NAT-port
  ▼
BGP routing
  ▼
external server  (sees src=externalIP:NAT-port)
```

### Return path — Combined revNAT (node uplink)

A single TCX ingress program on the node uplink handles both stages.

```
external server
  │  src=server-IP:server-port, dst=externalIP:NAT-port
  ▼
Any node (BGP ECMP)
  ▼
TCX ingress (head) — node uplink  (combined stage 1+2 revNAT, all nodes)
  │  checks src-IP against target_cidrs
  │
  │  [case A] dst ∈ external IP pool  → Stage 1
  │    looks up port-range-map[externalIP][NAT-port] → pod-IP
  │    rewrites dst: externalIP → pod-IP
  │    attempts Stage 2 (same-node optimization):
  │      nat_map revnat hit  → rewrites dst-port: NAT-port → pod-port
  │                          → client pod ✓
  │      nat_map revnat miss → pod is on another node
  │                          → BGP routes pod-IP packet to pod's node → [case B]
  │
  │  [case B] dst ∈ pod CIDR  → Stage 2 (cross-node return)
  │    looks up nat_map revnat entry: {server-IP, server-port, pod-IP, NAT-port} → {externalIP, pod-port}
  │    rewrites dst-port: NAT-port → pod-port
  ▼
client pod  (src=server-IP:server-port, dst=pod-IP:pod-port ✓)
```

---

## Components

### Operator

Runs as a Deployment (single replica with leader election). Owns three controllers and one startup
runnable. Lookup and mutation flow is always top-down: NPRR → NATConfig → NPR (NPRR controller),
NATConfig → NPR (NATConfig controller), NPR only (NPR controller). The operator never reads or
mutates NATPortRangeRequest — the daemon owns its lifecycle.

#### Startup reconstruction

A `ReconstructionRunnable` runs once immediately after the cache syncs, before any reconciler
processes a single item:

1. Lists all NATConfigs → creates a `BlockAllocator` per NATConfig (keyed by `portRangeSize`) →
   calls `EnsureIP` for every IP in each pool.
2. Lists all NATPortRanges (skipping those with `DeletionTimestamp`) → calls `MarkUsed` for every
   allocation. Allocations for IPs no longer in the pool are skipped (NATConfig controller will
   clean them up on its next reconcile).
3. Closes the reconstruction gate channel → all blocked reconcilers unblock simultaneously.

The NPRR controller blocks at the start of every `Reconcile` call on this channel. NATConfig and
NPR controllers gate on it as well for a clean startup. This prevents allocation conflicts with
NATPortRangeRequests that arrived while the operator was down.

#### NATPortRangeRequest controller

Drives `NATPortRange` toward the desired state derived from NPRR → NATConfig.

- **Create** (no NPR exists): reads the NATConfig, expands `externalIPPool` CIDRs to individual
  IPs, calls `AllocateForPod(extIPs, portRangeCount)` on the per-NATConfig `BlockAllocator`,
  creates NPR with all allocations, `portRangeCount` mirrored in spec, owner reference to NPRR,
  and the allocation finalizer. On Create failure, frees the just-allocated blocks and requeues.
- **Update** (`portRangeCount` changed):
  - *Increased*: calls `AllocateForIP(ip, delta, existingPortStarts)` for each IP, maintaining
    the cross-IP exclusion invariant; appends new allocations to NPR and updates.
  - *Decreased*: for each IP, sorts current allocations by `portStart`, keeps the first M (desired
    count), frees the remainder; updates NPR.
- **No-op** when NPR exists and `portRangeCount` matches.

#### NATPortRange controller

Handles block reclamation when GC marks NPR for deletion.

- When `DeletionTimestamp` is set and the finalizer is present: reads `spec.allocations`, calls
  `Free` on the per-NATConfig `BlockAllocator` to return all block indices to their per-IP free
  sets, removes the finalizer, and updates the NPR. If the NATConfig's allocator is missing (the
  NATConfig was deleted first), skips `Free` and removes the finalizer unconditionally.

#### NATConfig controller

Reconciles each NPR's allocations when `externalIPPool` changes. Reads `portRangeCount` directly
from `NATPortRange.Spec` — never reads NATPortRangeRequest.

- Uses a field index on `.spec.natConfig` to list all NPRs for the changed NATConfig.
- For each NPR (skipping those with `DeletionTimestamp`):
  - Computes `toAdd` (IPs in desired pool absent from NPR allocations) and `toRemove` (IPs in NPR
    allocations absent from desired pool).
  - Removes stale allocations, then calls `AllocateForIP(ip, NPR.Spec.PortRangeCount, existingPortStarts)`
    for each new IP, maintaining cross-IP exclusion as new IPs are added in sequence.
  - Updates NPR. On error, requeues (retried with full idempotency next pass).
- After all NPRs are updated, calls `RemoveIP` on the allocator for each dropped IP.
- On NATConfig deletion (`NotFound`): removes the allocator from the registry and returns.
  The daemon handles NPRR deletion; GC cascades to NPR deletion; the NPR controller's finalizer
  reclaims the blocks.

#### Testing

Controller integration tests use `envtest` (the controller-runtime in-process API server) to
exercise full reconciliation cycles without a real cluster. The NATConfig controller's ExternalIPPool
change handling is covered by table-driven tests including: IP added, IP removed, full pool
replacement, reconstruction followed by reconcile (idempotency), and NPRs with `DeletionTimestamp`
skipped.

### Daemon

Runs as a DaemonSet on all nodes. Uses controller-runtime without leader election — every instance
reconciles independently against its own node's state.

**BPF attachment**: calls `loader.EnsureLoaded(iface)` at startup. If maps and TCX links are
already pinned from a previous run, the load step is skipped — existing programs continue running
and in-flight connections are unaffected. In Cilium mode, programs are installed via
CiliumDatapathPlugin instead of direct TC attachment.

Four controllers run concurrently:

#### Pod controller

Watches: Pods, filtered to this node via a per-object cache field selector on `spec.nodeName`.
Also triggered by NATConfig changes via `EnqueueRequestsFromMapFunc` fanning out to all cached
local pods.

Reconcile key: pod namespace/name.

- **Pod not found** (fully deleted from cache): queries the `spec.podIdentity` field index
  (`{podNamespace}/{podName}`) on `NATPortRangeRequest` to find all NPRRs for this pod; sets
  `DeletionGracePeriodExpiry = now + 240 s` on any that lack it.
- **Pod found, no IP yet** (`pod.Status.PodIP == ""`): requeues in 5 s.
- **Pod found**: lists all NATConfigs; evaluates each `podSelector` against pod labels to build
  a `matchingNCs` set; lists existing NPRRs for this pod via the `spec.podIdentity` index; then:
  - For each matching NATConfig not already covered by an NPRR: creates a `NATPortRangeRequest`
    named `{podNamespace}-{podName}-{natConfigName}`.
  - For each existing NPRR whose NATConfig is absent from `matchingNCs` (NATConfig deleted or
    selector narrowed): sets `DeletionGracePeriodExpiry` if not already set.
  - If pod is terminating (`DeletionTimestamp` set): sets `DeletionGracePeriodExpiry` on all
    remaining NPRRs for this pod.
  - If pod is running and an NPRR has a stale `DeletionGracePeriodExpiry` (pod restarted during
    the grace window): clears the expiry via a status subresource update.

#### NATPortRangeRequest controller

Watches: NATPortRangeRequest (cluster-scoped), cache-filtered to this node via a `spec.nodeName`
field selector declared in the CRD `selectableFields` (Kubernetes ≥ 1.30). Only this node's NPRRs
are held in the daemon's informer cache.

Reconcile logic:
1. `DeletionGracePeriodExpiry` nil → pod is alive; no action.
2. `remaining = expiry - now > 0` → return `RequeueAfter: remaining`.
3. `remaining ≤ 0` → delete the NPRR; Kubernetes GC cascades to delete the owned NATPortRange.

**Startup syncer**: an `NPRRStartupSyncer` Runnable (registered with the manager) executes once
immediately after the cache syncs. It lists all NPRRs for this node, checks whether the referenced
pod still exists in the cache, and sets `DeletionGracePeriodExpiry = now + 240 s` on any NPRR
whose pod is absent — covering pods that were deleted while the daemon was down.

#### NATConfig controller

Watches: NATConfig (cluster-scoped) and the local Node object, cache-filtered to
`metadata.name == NODE_NAME` via a per-object cache field selector. Manages the `target_cidrs`
and `ext_ip_pool` LPM BPF maps on all nodes, and drives BGP route advertisement via the
`RouteAdvertiser` interface.

Maintains three separate in-memory per-NATConfig tracking maps:
- `ncTargetCIDRs` / `ncExtIPCIDRs`: CIDRs last written to the respective BPF maps.
- `ncAdvertisedCIDRs`: CIDRs currently advertised by this node via BGP.

Keeping advertisement state separate from BPF map state allows nodes excluded by `NodeSelector`
to keep their BPF maps current (required for packet forwarding on all nodes) while not
participating in BGP advertisement.

On any NATConfig or local Node label-change event:
- Computes desired BPF CIDRs from the current spec (empty if deleted).
- Updates `target_cidrs` and `ext_ip_pool` BPF maps unconditionally on all nodes.
- Evaluates `spec.nodeSelector` against this node's labels to determine `desiredRouteCIDRs`:
  empty if the node does not match; equal to `externalIPPool` if it matches (or if
  `nodeSelector` is nil — the default, which matches all nodes).
- Diffs `desiredRouteCIDRs` against `ncAdvertisedCIDRs`; calls `AdvertisePrefix` for newly
  matching CIDRs and `WithdrawPrefix` for CIDRs no longer matched, skipping withdrawal if
  another NATConfig still has the same CIDR in its `ncAdvertisedCIDRs`.

When `spec.nodeSelector` is nil (the default), all nodes advertise all pool CIDRs. This keeps
routes stable during daemon restarts — remaining nodes keep the prefixes reachable so stage 1
revNAT continues to work cluster-wide. On daemon restart the in-memory tracking is empty, so
the first reconcile of each NATConfig re-advertises its entire pool and repopulates BPF maps
(idempotent).

Node label changes are handled by watching the local Node: when it changes, all NATConfigs are
re-enqueued so advertisement is enabled or withdrawn immediately.

NPRR lifecycle is owned entirely by the Pod controller (NATConfig changes fan out to all local
pods via `EnqueueRequestsFromMapFunc`). The NATConfig controller has no field index on
`NATPortRangeRequest` and does not create or update NPRRs.

#### NATPortRange sync controller

Watches: NATPortRange (all nodes watch all resources).

Maintains an in-memory cache (`map[string]{TargetCIDRs, Allocations}`, key: NPR name) tracking
what was last written to BPF maps. The cache starts empty at daemon startup — the first reconcile
of each NPR re-adds all current allocations, idempotently repopulating the maps after a restart.

**Daemon finalizer** (`mooring.hanapedia.link/bpf-sync`): added to the NPR at the end of the
first successful `syncAlive`. It prevents Kubernetes from fully deleting the NPR until
`syncDeleted` has finished cleaning up BPF maps and explicitly removed the finalizer. Without
this, a daemon restart between the GC deleting the NPR and the daemon running `syncDeleted` would
leave stale port-range and nat_config entries in BPF maps indefinitely. `IsNotFound` in `Reconcile`
therefore always means "this daemon never synced the NPR" and requires no BPF action.

- **DeletionTimestamp set**: removes all entries in `spec.Allocations` from
  `port_range_lookup_{tcp,udp,icmp}` (all nodes). If `spec.nodeName == NODE_NAME`, iterates
  `spec.TargetCIDRs` and calls `RemoveNatConfigAllocs(podIP, cidr, uniqueExtIPs)` for each target CIDR
  to remove that pod's `nat_config` entries, leaving allocations from other pods intact. Removes
  the `mooring.hanapedia.link/bpf-sync` finalizer, then clears the cache entry.
- **No DeletionTimestamp**: computes a minimal diff across two dimensions:
  - *Allocation diff* (`toRemove`, `toAdd`): from `spec.Allocations` vs cached allocations.
  - *Target-CIDR diff* (`removedCIDRs`, `addedCIDRs`, `commonCIDRs`): from `spec.TargetCIDRs`
    vs cached CIDRs.

  Applies `RemovePortRange` / `AddPortRange` (TCP, UDP, ICMP) for changed allocations (all nodes).
  If local node, drives `nat_config` updates:

  | Changed dimension | Action |
  |---|---|
  | Allocation removed, CIDR unchanged | `RemoveNatConfigAllocs(podIP, cidr, removedExtIPs)` for each common CIDR |
  | Allocation added, CIDR unchanged | `UpsertNatConfigEntry(podIP, cidr, extIP, ...)` for each common CIDR |
  | CIDR removed entirely | `RemoveNatConfigAllocs(podIP, cidr, allOldExtIPs)` |
  | CIDR added | `UpsertNatConfigEntry(podIP, cidr, extIP, ...)` for all current allocations |

  Updates the cache entry with the new `{TargetCIDRs, Allocations}` state.

#### BGP speaker

Each daemon pod embeds a GoBGP server (`internal/routing/bgp`) that runs as an active BGP client.
It is registered with the controller-runtime manager as a `Runnable` so its lifecycle is managed
alongside the controllers.

**Active client mode**: GoBGP is started with `ListenPort: -1` (never binds to a socket). It
actively initiates the TCP session to the sidecar BGP daemon at `BGP_PEER_ADDR` (default
`127.0.0.1:179`). The sidecar must be configured with the mooring peer as `passive`.

**Configuration** is provided via environment variables:

| Env var | Required | Default | Description |
|---|---|---|---|
| `BGP_LOCAL_ASN` | yes | — | Mooring daemon's AS number |
| `BGP_REMOTE_ASN` | yes | — | Sidecar BGP daemon's AS number |
| `BGP_ROUTER_ID` | yes | — | Node IP used as the BGP router ID |
| `BGP_PEER_ADDR` | no | `127.0.0.1` | Sidecar BGP daemon address |
| `BGP_NEXT_HOP` | no | `BGP_ROUTER_ID` | Next-hop attribute for advertised routes |

**`RouteAdvertiser` interface**: the BGP speaker is injected into the NATConfig controller via a
`routing.RouteAdvertiser` interface (`internal/routing`), which exposes only
`AdvertisePrefix(ctx, *net.IPNet)` and `WithdrawPrefix(ctx, *net.IPNet)`. This keeps the
controller independent of BGP and allows alternative implementations (L2 advertisement, kernel FIB
sync via netlink) to be substituted without changing controller logic. A `NoopAdvertiser` is
provided for unit tests and envtest.

---

## Pod Lifecycle

### New pod startup

1. Pod is scheduled on a node and its network namespace is configured by the CNI plugin.
2. Daemon on that node detects the new pod (via pod informer, filtered by node field selector)
   and creates a `NATPortRangeRequest` for each matching NATConfig.
3. Operator sees the `NATPortRangeRequest`, allocates port ranges, and creates a `NATPortRange`
   with an owner reference back to the request.
4. Daemons on every node see the new `NATPortRange` and sync its allocations into the
   per-protocol port-range lookup maps.
5. Daemon on the pod's node additionally syncs the allocation into the nat_config map. No BPF
   program attachment is needed in default mode — the uplink programs are already running.
6. Pod is marked ready.

### Pod deletion

1. Pod is deleted; daemon on the pod's node detects the deletion.
2. Daemon sets `NATPortRangeRequest.Status.DeletionGracePeriodExpiry = now + 240s` (covers
   `TIME_WAIT` expiry) and does nothing else immediately.
3. After expiry, the daemon's `NATPortRangeRequest` reconciler deletes the request.
4. Kubernetes GC deletes the owned `NATPortRange` (blocked until all finalizers are removed).
5. Daemons on all nodes see the `NATPortRange` `DeletionTimestamp`, clean up BPF maps, then
   remove their `mooring.hanapedia.link/bpf-sync` finalizer. Once the last finalizer (the
   operator's `mooring.hanapedia.link/allocation`) is removed, the NPR is garbage-collected.

### ExternalIPPool change

1. Operator detects the change on `NATConfig`.
2. For each `NATPortRange` referencing that NATConfig, the operator updates `spec.allocations`
   in place: removes entries for IPs no longer in the pool, adds entries for new IPs.
3. Daemons see the `NATPortRange` update and reconcile BPF maps accordingly (remove stale
   entries, add new ones). No resource deletion or recreation is required.

---

## Update Resiliency

BPF programs and maps are pinned to bpffs (`/sys/fs/bpf/mooring/`). On daemon restart:

- Existing BPF programs continue running — in-flight connections are unaffected.
- The daemon re-attaches to pinned maps and reconciles their state against current `NATPortRange`
  resources in the API server.
- No packet loss occurs during daemon rollout.

Node-level updates (kernel upgrade, etc.) require pod eviction, which triggers normal port range
cleanup via the grace period mechanism.

---

## Limitations

- **Max concurrent connections per pod per (external IP, target CIDR)** is bounded by the assigned
  port range size — this bounds concurrency, not lifetime churn, since ports are reclaimed as TCP
  connections close (see "Connection tracking and port reclamation" above) rather than being
  consumed once and never reused. Each `(pod, target-CIDR)` pair has its own independent port
  space, so a pod matching N target CIDRs effectively multiplies its available NAT capacity by N.
  Pods expecting a high number of *concurrent* connections should use a dedicated NATConfig with a
  larger `portRangeSize` or finer target CIDR splits.
- **Requires BGP underlay** with pod CIDRs advertised (native routing). Overlay networks are not
  supported. Each node must also run a sidecar BGP daemon (FRR, BIRD, etc.) configured to accept
  the mooring peer as a passive neighbor and redistribute its routes to the DC fabric.
- **Cilium mode requires** Cilium with BPF host routing and the CiliumDatapathPlugin API. It is
  tested as a secondary target and may have ordering dependencies with other TC programs on the
  uplink interface.

---

## Open Questions

### Resolved

- **TCX chain position and Cilium coexistence**: programs attach at the head of the TCX list
  (`link.Head()`), return `TCX_NEXT` on non-matching packets, and use `SEC("tcx/egress")` /
  `SEC("tcx/ingress")`. Cilium always appends at the tail of the TCX list, so head attachment
  guarantees mooring runs first. `TCX_NEXT` passes non-matching packets to the next program in
  the chain (including Cilium), so coexistence requires no coordination.
- **Port selection across multiple external IPs**: `MAX_ENTRY_ATTEMPTS` independent random draws
  (with replacement) from `nat_config.allocations[]`, not an exhaustive scan — see "Port allocation
  within a block" above for why an exhaustive fixed-order fallback scan was tried first and rejected
  (it blew the kernel verifier's instruction budget).
- **BPF map type for port-range lookup**: `BPF_MAP_TYPE_HASH_OF_MAPS` with per-external-IP
  inner `BPF_MAP_TYPE_ARRAY` maps of 65536 `u32` entries (~256 KB per IP). O(1) lookup by port
  index; outer map is pinned; inner maps are referenced by FD stored in the outer map.
- **nat_config map key**: compound `{pod-IP, cidr-addr, cidr-prefixlen}` so a pod matching
  multiple NATConfigs gets independent ext-IP pools per target CIDR.
