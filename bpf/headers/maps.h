#pragma once

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct lpm_key {
  __u32 prefixlen;
  __be32 addr;
};

// nat_map_tcp/nat_map_any together hold both the forward (snat) and reverse
// (revnat) direction of every tracked connection, disambiguated by `kind`,
// split by protocol so each can run its own GC policy (bpf/nat_gc.c):
// nat_map_tcp for TCP, nat_map_any for UDP+ICMP (like Cilium's conntrack
// split, minus the v4/v6 axis mooring doesn't have). Each live connection
// occupies exactly two entries, one per map depending on its protocol:
//
// snat entry:
//   key   {pod_ip, pod_port, server_ip, server_port, proto, SNAT}
//   value {ext_ip, nat_port}
// revnat entry:
//   key   {server_ip, server_port, pod_ip, nat_port, proto, REVNAT}
//   value {ext_ip, pod_port}
//
// snat_egress owns both maps: it looks up/writes the snat entry to reuse or
// allocate a port, and looks up (as part of allocation's collision check) and
// writes the paired revnat entry. revnat_ingress looks up the revnat entry to
// restore the original pod port, and looks up/updates the paired snat entry
// for connection tracking on the server->pod direction. Both entries for a
// connection are always kept in sync -- see snat_egress.c and
// revnat_ingress.c for the mark/confirm/reclaim logic, and bpf/nat_gc.c for
// the periodic sweep that replaces LRU eviction as the capacity-reclaim
// mechanism.
//
// `kind` exists solely so the two entry shapes can never collide: without it,
// a snat key and a revnat key draw from the same (ip, port, ip, port, proto)
// domain, so one flow's forward key could in principle coincide with a
// different flow's reverse key. With it, that's structurally impossible.
#define NAT_ENTRY_SNAT   0
#define NAT_ENTRY_REVNAT 1

struct nat_map_key {
  __be32 ip_a;
  __be32 ip_b;
  __be16 port_a;
  __be16 port_b;
  __u8 proto;
  __u8 kind;
};

// One value shape shared by both nat_map_tcp and nat_map_any -- deliberately
// not two separate per-map structs, so the proto-dispatch in
// nat_map_lookup_snat/revnat below (choosing which map to hit at runtime)
// type-checks: the verifier only accepts merging the two maps' pointer types
// after a runtime branch if their value type is identical.
struct nat_map_val {
  __be32 nat_ip;
  __be16 port; // nat_port for a snat entry, pod_port for a revnat entry
  union {
    // nat_map_tcp only. 0 = not closing. Else bpf_ktime_get_ns() at the
    // moment THIS entry's own direction (pod-side for a snat entry,
    // server-side for a revnat entry) most recently showed a FIN or RST
    // with no resumed ordinary traffic since. Set only from traffic
    // actually seen in this entry's own direction -- never mirrored from
    // the peer entry; see nat_map_track_tcp_close for the deletion rule
    // this enables. Also doubles as the staleness timestamp for the
    // allocator's lazy reclaim check (snat_egress.c's try_alloc_port) and
    // for bpf/nat_gc.c's proactive sweep.
    __u64 closing_ns;
    // nat_map_any only. 0 = touched since GC's last sweep, 1 = marked
    // stale by GC (bpf/nat_gc.c), due for deletion next sweep unless the
    // datapath clears it back to 0 first on a hit (snat_egress.c's reuse
    // branch, revnat_core.h's do_port_revnat).
    __u8 stale;
  };
};

// How long a TCP entry marked closing can sit unconfirmed before it may be
// reclaimed -- either lazily, by a colliding allocation (snat_egress.c's
// try_alloc_port), or proactively, by the next GC sweep (bpf/nat_gc.c).
// Covers unclean ends (crash, dropped FIN/RST) that close-tracking never
// gets to confirm. TCP only -- UDP/ICMP use the `stale` generation marker
// above instead, with no timestamp.
#define NAT_CLOSING_STALE_NS (10ULL * 1000000000ULL)

// max_entries = 65536 each, matching this map's share of the old combined
// nat_map's 131072 (2x65536) capacity -- see nat_map_lookup_snat/revnat
// below for why both maps share one value type despite the split. Plain
// BPF_MAP_TYPE_HASH, not LRU: a full map now rejects new entries (signaling
// nat_map_gc_signal below) instead of silently evicting something that may
// still be live, and bpf/nat_gc.c's periodic sweep is what's actually
// responsible for keeping each map below capacity.
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 65536);
  __type(key, struct nat_map_key);
  __type(value, struct nat_map_val);
} nat_map_tcp SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 65536);
  __type(key, struct nat_map_key);
  __type(value, struct nat_map_val);
} nat_map_any SEC(".maps");

// Best-effort signal from snat_egress.c's allocation path to the userspace
// GC runnable (internal/gc, cmd/daemon's GCRunnable): nat_map_tcp or
// nat_map_any just rejected an insert because it's full, so trigger an
// out-of-cycle sweep instead of waiting for the next periodic one. A
// dropped event (ring full, GC not running yet) just means the next
// periodic sweep catches it instead -- this is a latency optimization, not
// a correctness dependency.
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 4096);
} nat_map_gc_signal SEC(".maps");

// Named wrappers around nat_map_{tcp,any}'s key (and, for update, value)
// construction, one pair per entry kind -- so a call site reads as what
// it's doing (look up the snat entry for this flow) rather than a
// six-field key-struct literal sitting next to a bpf_map_* call, and so the
// proto -> map dispatch lives in exactly one place instead of being
// re-spelled at every call site in revnat_core.h and snat_egress.c (both of
// which already have `proto` in hand at every call site).
static __always_inline void *nat_map_for_proto(__u8 proto) {
  return proto == IPPROTO_TCP ? (void *)&nat_map_tcp : (void *)&nat_map_any;
}

static __always_inline struct nat_map_val *
nat_map_lookup_snat(__be32 pod_ip, __be32 server_ip, __be16 pod_port,
                    __be16 server_port, __u8 proto) {
  struct nat_map_key key = {
      .ip_a = pod_ip,
      .ip_b = server_ip,
      .port_a = pod_port,
      .port_b = server_port,
      .proto = proto,
      .kind = NAT_ENTRY_SNAT,
  };
  return bpf_map_lookup_elem(nat_map_for_proto(proto), &key);
}

static __always_inline struct nat_map_val *
nat_map_lookup_revnat(__be32 server_ip, __be32 pod_ip, __be16 server_port,
                      __be16 nat_port, __u8 proto) {
  struct nat_map_key key = {
      .ip_a = server_ip,
      .ip_b = pod_ip,
      .port_a = server_port,
      .port_b = nat_port,
      .proto = proto,
      .kind = NAT_ENTRY_REVNAT,
  };
  return bpf_map_lookup_elem(nat_map_for_proto(proto), &key);
}

static __always_inline long nat_map_update_snat(__be32 pod_ip, __be32 server_ip,
                                                __be16 pod_port,
                                                __be16 server_port, __u8 proto,
                                                __be32 nat_ip, __be16 nat_port,
                                                __u64 closing_ns) {
  struct nat_map_key key = {
      .ip_a = pod_ip,
      .ip_b = server_ip,
      .port_a = pod_port,
      .port_b = server_port,
      .proto = proto,
      .kind = NAT_ENTRY_SNAT,
  };
  struct nat_map_val val = {
      .nat_ip = nat_ip, .port = nat_port, .closing_ns = closing_ns};
  return bpf_map_update_elem(nat_map_for_proto(proto), &key, &val, BPF_ANY);
}

static __always_inline long
nat_map_update_revnat(__be32 server_ip, __be32 pod_ip, __be16 server_port,
                      __be16 nat_port, __u8 proto, __be32 nat_ip,
                      __be16 pod_port, __u64 closing_ns) {
  struct nat_map_key key = {
      .ip_a = server_ip,
      .ip_b = pod_ip,
      .port_a = server_port,
      .port_b = nat_port,
      .proto = proto,
      .kind = NAT_ENTRY_REVNAT,
  };
  struct nat_map_val val = {
      .nat_ip = nat_ip, .port = pod_port, .closing_ns = closing_ns};
  return bpf_map_update_elem(nat_map_for_proto(proto), &key, &val, BPF_ANY);
}

static __always_inline long nat_map_delete_snat(__be32 pod_ip, __be32 server_ip,
                                                __be16 pod_port,
                                                __be16 server_port,
                                                __u8 proto) {
  struct nat_map_key key = {
      .ip_a = pod_ip,
      .ip_b = server_ip,
      .port_a = pod_port,
      .port_b = server_port,
      .proto = proto,
      .kind = NAT_ENTRY_SNAT,
  };
  return bpf_map_delete_elem(nat_map_for_proto(proto), &key);
}

static __always_inline long nat_map_delete_revnat(__be32 server_ip,
                                                  __be32 pod_ip,
                                                  __be16 server_port,
                                                  __be16 nat_port, __u8 proto) {
  struct nat_map_key key = {
      .ip_a = server_ip,
      .ip_b = pod_ip,
      .port_a = server_port,
      .port_b = nat_port,
      .proto = proto,
      .kind = NAT_ENTRY_REVNAT,
  };
  return bpf_map_delete_elem(nat_map_for_proto(proto), &key);
}

// Shared TCP close state machine for nat_map_tcp -- used by do_port_revnat
// (revnat_core.h, own_kind = NAT_ENTRY_REVNAT, own = the revnat entry nv)
// and by snat_egress.c (own_kind = NAT_ENTRY_SNAT, own = the snat entry sv).
// server_ip, pod_ip, server_port, nat_port and pod_port together determine
// both the revnat and snat keys regardless of which one the caller holds,
// so both callers pass the same five scalars; own_kind just says which one
// own is, to find the peer when needed.
//
// See nat_map_val's closing_ns comment above for what each entry's own
// field means. own/peer are plain pointers into the map's own backing
// memory, so writing through them needs no bpf_map_update_elem. Only TCP
// calls this, so proto is always IPPROTO_TCP.
static __always_inline void
nat_map_track_tcp_close(__be32 server_ip, __be32 pod_ip, __be16 server_port,
                        __be16 nat_port, __be16 pod_port,
                        struct nat_map_val *own, __u8 own_kind, __u8 fin,
                        __u8 rst) {
  if (!own->closing_ns && !fin && !rst)
    return; // healthy flow, nothing to record

  if (fin || rst) {
    if (own->closing_ns)
      return; // already marked from this side; the other side's own
              // traffic would already have deleted both if it mattered

    own->closing_ns = bpf_ktime_get_ns();

    struct nat_map_val *peer =
        (own_kind == NAT_ENTRY_REVNAT)
            ? nat_map_lookup_snat(pod_ip, server_ip, pod_port, server_port,
                                  IPPROTO_TCP)
            : nat_map_lookup_revnat(server_ip, pod_ip, server_port, nat_port,
                                    IPPROTO_TCP);
    if (peer && peer->closing_ns) {
      nat_map_delete_revnat(server_ip, pod_ip, server_port, nat_port,
                            IPPROTO_TCP);
      nat_map_delete_snat(pod_ip, server_ip, pod_port, server_port,
                          IPPROTO_TCP);
    }
    return;
  }

  own->closing_ns =
      0; // this side resumed ordinary traffic; its own mark was premature
}

// Value stored in target_cidrs: the canonical network address and prefix length
// of the matched CIDR. Stored redundantly so the egress program can retrieve
// the matching CIDR identity from the value (BPF LPM lookup returns the value
// of the matching entry, not the key) and use it as part of the nat_config
// key.
struct target_cidr_val {
  __be32 addr;
  __u32 prefixlen;
};

struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __uint(max_entries, 256);
  __type(key, struct lpm_key);
  __type(value, struct target_cidr_val);
} target_cidrs SEC(".maps");

// Exact-match (prefixlen=32) lookup against target_cidrs -- used by both
// revnat_core.h (is src a server this pod talks to?) and snat_egress.c (is
// dst?). Returns NULL on a miss.
static __always_inline struct target_cidr_val *lookup_target_cidr(__be32 addr) {
  struct lpm_key key = {
      .prefixlen = 32,
      .addr = addr,
  };
  return bpf_map_lookup_elem(&target_cidrs, &key);
}
