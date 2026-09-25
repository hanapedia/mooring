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
