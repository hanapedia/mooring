#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct nat_key {
  __be32 pod_ip;
  __be16 nat_port;
  __be32 server_ip;
  __be16 server_port;
  __u8 proto;
  __u8 pad[3]; /* verifier does not allow uninitialized bytes */
};

struct nat_val {
  __be16 pod_port;
};

struct lpm_key {
  __u32 prefixlen;
  __be32 addr;
};

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 65536);
  __type(key, struct nat_key);
  __type(value, struct nat_val);
} nat_table SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __uint(max_entries, 256);
  __type(key, struct lpm_key);
  __type(value, __u8);
} target_cidrs SEC(".maps");
