#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct nat_key {
  __be32 pod_ip;
  __be32 server_ip;
  __be16 nat_port;
  __be16 server_port;
  // total 12 bytes, no padding needed
};

struct nat_val {
  __be16 pod_port;
};

struct lpm_key {
  __u32 prefixlen;
  __be32 addr;
};

/// Per-protocol NAT tables

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 65536);
  __type(key, struct nat_key);
  __type(value, struct nat_val);
} nat_table_tcp SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 65536);
  __type(key, struct nat_key);
  __type(value, struct nat_val);
} nat_table_udp SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 65536);
  __type(key, struct nat_key);
  __type(value, struct nat_val);
} nat_table_icmp SEC(".maps");

// Value stored in target_cidrs: the canonical network address and prefix length
// of the matched CIDR. Stored redundantly so the egress program can retrieve
// the matching CIDR identity from the value (BPF LPM lookup returns the value
// of the matching entry, not the key) and use it as part of the snat_config
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
