#pragma once

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct lpm_key {
  __u32 prefixlen;
  __be32 addr;
};

// nat_map holds both the forward (snat) and reverse (revnat) direction of
// every tracked connection, in a single map, disambiguated by `kind`. Each
// live connection occupies exactly two entries:
//
// snat entry:
//   key   {pod_ip, pod_port, server_ip, server_port, proto, SNAT}
//   value {ext_ip, nat_port}
// revnat entry:
//   key   {server_ip, server_port, pod_ip, nat_port, proto, REVNAT}
//   value {ext_ip, pod_port}
//
// snat_egress owns both: it looks up/writes the snat entry to reuse or
// allocate a port, and looks up (as part of allocation's collision check) and
// writes the paired revnat entry. revnat_ingress looks up the revnat entry to
// restore the original pod port, and looks up/updates the paired snat entry
// for connection tracking on the server->pod direction. Both entries for a
// connection are always kept in sync -- see snat_egress.c and
// revnat_ingress.c for the mark/confirm/reclaim logic.
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

struct nat_map_val {
  __be32 nat_ip;
  __be16 port; // nat_port for a snat entry, pod_port for a revnat entry
  // 0 = not closing. Else bpf_ktime_get_ns() at the moment THIS entry's own
  // direction (pod-side for a snat entry, server-side for a revnat entry)
  // most recently showed a FIN or RST with no resumed ordinary traffic
  // since. Set only from traffic actually seen in this entry's own
  // direction -- never mirrored from the peer entry; see
  // nat_map_track_tcp_close for the deletion rule this enables. Also
  // doubles as the staleness timestamp for the allocator's reclaim check
  // (snat_egress.c's try_alloc_port). UDP/ICMP never set this, so they're
  // never reclaimed that way.
  __u64 closing_ns;
};

// max_entries = 2x the target concurrent-connection count: every connection
// holds exactly one snat and one revnat entry. 131072 (2x65536) matches
// today's real effective ceiling -- the old per-protocol nat_table_tcp/udp/icmp
// maps had 3x65536 combined capacity, but the (never protocol-split)
// outbound_sessions map was already capping total connections at 65536
// regardless of protocol mix, so that combined capacity was never actually
// reachable.
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 131072);
  __type(key, struct nat_map_key);
  __type(value, struct nat_map_val);
} nat_map SEC(".maps");

// Named wrappers around nat_map's key (and, for update, value) construction,
// one pair per entry kind -- so a call site reads as what it's doing (look
// up the snat entry for this flow) rather than a six-field key-struct
// literal sitting next to a bpf_map_* call. The key layout above (which
// field is ip_a vs ip_b, what `kind` means) lives here, in exactly one
// place, instead of being re-spelled at every call site in revnat_core.h
// and snat_egress.c.
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
  return bpf_map_lookup_elem(&nat_map, &key);
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
  return bpf_map_lookup_elem(&nat_map, &key);
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
  return bpf_map_update_elem(&nat_map, &key, &val, BPF_ANY);
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
  return bpf_map_update_elem(&nat_map, &key, &val, BPF_ANY);
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
  return bpf_map_delete_elem(&nat_map, &key);
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
  return bpf_map_delete_elem(&nat_map, &key);
}

// Shared TCP close state machine for nat_map -- used by do_port_revnat
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
