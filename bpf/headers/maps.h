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
  // 0 = not closing. Else bpf_ktime_get_ns() at the moment a FIN or RST was
  // first observed for this (TCP-only) flow. ktime is monotonic-since-boot, so
  // 0 is never a real timestamp once packets are flowing -- safe as a
  // sentinel. UDP/ICMP entries never set this, which is what makes them
  // permanently ineligible for the stale-reclaim check in the allocator (no
  // marker, no override).
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
// (revnat_core.h, server->pod direction, own_kind = NAT_ENTRY_REVNAT, own =
// the revnat entry nv) and by snat_egress.c (pod->server direction,
// own_kind = NAT_ENTRY_SNAT, own = the snat entry sv). server_ip, pod_ip,
// server_port, nat_port and pod_port together fully determine *both* the
// revnat key (server_ip, pod_ip, server_port, nat_port) and the snat key
// (pod_ip, server_ip, pod_port, server_port) regardless of which one the
// caller already holds -- so both callers pass the same five scalars, and
// own_kind is just which entry that is (to know which lookup finds the
// peer; the delete path drops both unconditionally either way).
//
// The first FIN or RST (either direction) stamps closing_ns on both
// entries. A second FIN or RST, combined with ACK, confirms the close and
// deletes both -- requiring a second terminating segment (not just any
// ACK) specifically avoids tearing down a half-closed connection (one side
// FIN'd, the other still sending data) onto a fresh port mid-flow. If the
// close is never confirmed (crash, dropped FIN/RST), the entries are left
// in place but become eligible for reclamation -- see snat_egress.c's
// try_alloc_port for that stale-entry path.
//
// own (nv/sv) is taken as a plain pointer -- the caller already has it from
// its own nat_map_lookup_revnat/nat_map_lookup_snat call, and writing
// through it (own->closing_ns = ...) mutates that entry directly in the map
// (bpf_map_lookup_elem on a hash-type map returns a pointer into the map's
// own backing memory, not a copy -- no bpf_map_update_elem needed, same for
// peer below). Only TCP ever calls this, so proto is always IPPROTO_TCP
// rather than a parameter.
static __always_inline void
nat_map_track_tcp_close(__be32 server_ip, __be32 pod_ip, __be16 server_port,
                        __be16 nat_port, __be16 pod_port,
                        struct nat_map_val *own, __u8 own_kind, __u8 fin,
                        __u8 rst, __u8 ack) {
  if (own->closing_ns) {
    if ((fin || rst) && ack) {
      nat_map_delete_revnat(server_ip, pod_ip, server_port, nat_port,
                            IPPROTO_TCP);
      nat_map_delete_snat(pod_ip, server_ip, pod_port, server_port,
                          IPPROTO_TCP);
    }
    return;
  }
  if (!fin && !rst)
    return;
  __u64 now = bpf_ktime_get_ns();
  own->closing_ns = now;
  struct nat_map_val *peer =
      (own_kind == NAT_ENTRY_REVNAT)
          ? nat_map_lookup_snat(pod_ip, server_ip, pod_port, server_port,
                                IPPROTO_TCP)
          : nat_map_lookup_revnat(server_ip, pod_ip, server_port, nat_port,
                                  IPPROTO_TCP);
  if (peer)
    peer->closing_ns = now;
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
