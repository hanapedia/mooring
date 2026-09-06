// SPDX-License-Identifier: GPL-2.0
#include "tc.h"
#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

char __license[] SEC("license") = "GPL";

/// Map key and value types defs
struct snat_entry {
  __be32 ext_ip;
  __u16 port_start;
  __u16 port_end;
  __u32 next_port; /* atomic counter for port allocation */
};

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

/* forward session map key: original connection 5-tuple */
struct session_key {
  __be32 pod_ip;
  __be16 pod_port;
  __be32 server_ip;
  __be16 server_port;
  __u8   proto;
  __u8   pad[3];
};

struct session_val {
  __be16 nat_port;
};

struct lpm_key {
  __u32 prefixlen;
  __be32 addr;
};

/// Map defs
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, __be32);
  __type(value, struct snat_entry);
} snat_config SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 65536);
  __type(key, struct nat_key);
  __type(value, struct nat_val);
} nat_table SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 65536);
  __type(key, struct session_key);
  __type(value, struct session_val);
} outbound_sessions SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __uint(max_entries, 256);
  __type(key, struct lpm_key);
  __type(value, __u8);
} target_cidrs SEC(".maps");

/// entrypoint for snat_egress
SEC("tc")
int snat_egress(struct __sk_buff *skb) {
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;

  // parse ethernet header
  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end)
    return TC_ACT_OK;

  if (eth->h_proto != bpf_htons(ETH_P_IP))
    return TC_ACT_OK;

  // parse IP header
  struct iphdr *iph = (void *)(eth + 1);
  if ((void *)(iph + 1) > data_end)
    return TC_ACT_OK;

  // handle only tcp and udp (may want to handle icmp)
  if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP)
    return TC_ACT_OK;

  // look up dest against target cidrs
  struct lpm_key lpm = {
      .prefixlen = 32, /* match dest IP exactly */
      .addr = iph->daddr,
  };
  if (!bpf_map_lookup_elem(&target_cidrs, &lpm))
    return TC_ACT_OK;

  // look up snat config for this pod
  __be32 pod_ip = iph->saddr;
  struct snat_entry *entry = bpf_map_lookup_elem(&snat_config, &pod_ip);
  if (!entry)
    return TC_ACT_OK;

  // parse l4 header
  __be16 pod_port, server_port;
  __u32 l4_off = sizeof(struct ethhdr) + sizeof(struct iphdr);
  __u32 csum_off;

  if (iph->protocol == IPPROTO_TCP) {
    struct tcphdr *tcph = (void *)iph + sizeof(struct iphdr);
    if ((void *)(tcph + 1) > data_end)
      return TC_ACT_OK;
    pod_port = tcph->source;
    server_port = tcph->dest;
    csum_off = l4_off + offsetof(struct tcphdr, check);
  } else {
    struct udphdr *udph = (void *)iph + sizeof(struct iphdr);
    if ((void *)(udph + 1) > data_end)
      return TC_ACT_OK;
    pod_port = udph->source;
    server_port = udph->dest;
    csum_off = l4_off + offsetof(struct udphdr, check);
  }

  // look up existing session before allocating a new port
  struct session_key sk = {
      .pod_ip = pod_ip,
      .pod_port = pod_port,
      .server_ip = iph->daddr,
      .server_port = server_port,
      .proto = iph->protocol,
  };
  struct session_val *sv = bpf_map_lookup_elem(&outbound_sessions, &sk);

  __be16 nat_port;
  if (sv) {
    // existing connection — reuse the allocated port
    nat_port = sv->nat_port;
  } else {
    // new connection — allocate a port and record it
    __u16 range = entry->port_end - entry->port_start + 1;
    nat_port = bpf_htons(entry->port_start +
                         (__sync_fetch_and_add(&entry->next_port, 1) % range));

    struct session_val new_sv = {.nat_port = nat_port};
    bpf_map_update_elem(&outbound_sessions, &sk, &new_sv, BPF_ANY);

    struct nat_key nk = {
        .pod_ip = pod_ip,
        .nat_port = nat_port,
        .server_ip = iph->daddr,
        .server_port = server_port,
        .proto = iph->protocol,
    };
    struct nat_val nv = {.pod_port = pod_port};
    bpf_map_update_elem(&nat_table, &nk, &nv, BPF_ANY);
  }

  // fix ip checksum
  __be32 ext_ip = entry->ext_ip;
  __u32 ip_csum = sizeof(struct ethhdr) + offsetof(struct iphdr, check);
  bpf_l3_csum_replace(skb, ip_csum, pod_ip, ext_ip, sizeof(__be32));

  // fix l4 checksum with updated src ip
  bpf_l4_csum_replace(skb, csum_off, pod_ip, ext_ip,
                      BPF_F_PSEUDO_HDR | sizeof(__be32));

  // fix l4 checksum with updated src port
  bpf_l4_csum_replace(skb, csum_off, pod_port, nat_port, sizeof(__be16));

  // rewrite headers
  iph->saddr = ext_ip;
  if (iph->protocol == IPPROTO_TCP) {
    struct tcphdr *tcph = (void *)iph + sizeof(struct iphdr);
    if ((void *)(tcph + 1) > data_end)
      return TC_ACT_OK;
    tcph->source = nat_port;
  } else {
    struct udphdr *udph = (void *)iph + sizeof(struct iphdr);
    if ((void *)(udph + 1) > data_end)
      return TC_ACT_OK;
    udph->source = nat_port;
  }

  return TC_ACT_OK;
}
