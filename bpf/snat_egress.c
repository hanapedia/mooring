// SPDX-License-Identifier: GPL-2.0
#include "maps.h"
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

#define MAX_SNAT_ALLOCS 16

struct snat_config_val {
  struct snat_entry allocations[MAX_SNAT_ALLOCS];
  __u32 count;
};

/* forward session map key: original connection 5-tuple */
struct session_key {
  __be32 pod_ip;
  __be16 pod_port;
  __be32 server_ip;
  __be16 server_port;
  __u8 proto;
  __u8 pad[3];
};

struct session_val {
  __be32 ext_ip;
  __be16 nat_port;
};

/// Map defs
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, __be32);
  __type(value, struct snat_config_val);
} snat_config SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 65536);
  __type(key, struct session_key);
  __type(value, struct session_val);
} outbound_sessions SEC(".maps");

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

  // handle only tcp, udp, and icmp
  if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP &&
      iph->protocol != IPPROTO_ICMP)
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
  } else if (iph->protocol == IPPROTO_UDP) {
    struct udphdr *udph = (void *)iph + sizeof(struct iphdr);
    if ((void *)(udph + 1) > data_end)
      return TC_ACT_OK;
    pod_port = udph->source;
    server_port = udph->dest;
    csum_off = l4_off + offsetof(struct udphdr, check);
  } else { // ICMP (use port as id)
    struct icmphdr *icmph = (void *)iph + sizeof(struct iphdr);
    if ((void *)(icmph + 1) > data_end)
      return TC_ACT_OK;
    // handle only echo for now
    if (icmph->type != ICMP_ECHO)
      return TC_ACT_OK;
    pod_port = icmph->un.echo.id;
    server_port = 0;
    csum_off = l4_off + offsetof(struct icmphdr, checksum);
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

  __be32 ext_ip = 0;
  __be16 nat_port = 0;
  if (sv) {
    // existing connection — reuse the allocated port
    ext_ip = sv->ext_ip;
    nat_port = sv->nat_port;
  } else {
    struct snat_config_val *cv = bpf_map_lookup_elem(&snat_config, &pod_ip);
    if (!cv || cv->count == 0) // no snat config found
      return TC_ACT_OK;

    for (__u32 i = 0; i < MAX_SNAT_ALLOCS; i++) {
      if (i >= cv->count)
        break;

      struct snat_entry *e = &cv->allocations[i];
      __u16 range = e->port_end - e->port_start + 1;
      __u32 slot = __sync_fetch_and_add(&e->next_port, 1);

      if (slot >= range)
        continue; // try next entry

      nat_port = bpf_htons((__u16)(e->port_start + slot));
      ext_ip = e->ext_ip;
      break; // stop at first non-exhausted entry
    }

    if (!ext_ip)
      return TC_ACT_OK; // all entries exhausted

    struct session_val new_sv = {.ext_ip = ext_ip, .nat_port = nat_port};
    bpf_map_update_elem(&outbound_sessions, &sk, &new_sv, BPF_ANY);

    struct nat_key nk = {
        .pod_ip = pod_ip,
        .nat_port = nat_port,
        .server_ip = iph->daddr,
        .server_port = server_port,
    };
    struct nat_val nv = {.pod_port = pod_port};
    if (iph->protocol == IPPROTO_TCP) {
      bpf_map_update_elem(&nat_table_tcp, &nk, &nv, BPF_ANY);
    } else if (iph->protocol == IPPROTO_UDP) {
      bpf_map_update_elem(&nat_table_udp, &nk, &nv, BPF_ANY);
    } else { // ICMP
      bpf_map_update_elem(&nat_table_icmp, &nk, &nv, BPF_ANY);
    }
  }

  // rewrite headers before csum helpers: bpf_l3/l4_csum_replace call
  // skb_make_writable internally, which can reallocate the skb and causes the
  // verifier to invalidate all PTR_TO_PACKET registers. Do direct writes first.
  iph->saddr = ext_ip;
  if (iph->protocol == IPPROTO_TCP) {
    struct tcphdr *tcph = (void *)iph + sizeof(struct iphdr);
    if ((void *)(tcph + 1) > data_end)
      return TC_ACT_OK;
    tcph->source = nat_port;
  } else if (iph->protocol == IPPROTO_UDP) {
    struct udphdr *udph = (void *)iph + sizeof(struct iphdr);
    if ((void *)(udph + 1) > data_end)
      return TC_ACT_OK;
    udph->source = nat_port;
  } else { // ICMP (uses port as id)
    struct icmphdr *icmph = (void *)iph + sizeof(struct iphdr);
    if ((void *)(icmph + 1) > data_end)
      return TC_ACT_OK;
    icmph->un.echo.id = nat_port;
  }

  // fix checksums — from/to values are passed explicitly so the order relative
  // to the header rewrites above does not affect correctness.
  __u32 ip_csum = sizeof(struct ethhdr) + offsetof(struct iphdr, check);
  if (iph->protocol != IPPROTO_ICMP) {
    bpf_l3_csum_replace(skb, ip_csum, pod_ip, ext_ip, sizeof(__be32));
    bpf_l4_csum_replace(skb, csum_off, pod_ip, ext_ip,
                        BPF_F_PSEUDO_HDR | sizeof(__be32));
    bpf_l4_csum_replace(skb, csum_off, pod_port, nat_port, sizeof(__be16));
  } else {
    bpf_l3_csum_replace(skb, ip_csum, pod_ip, ext_ip, sizeof(__be32));
    bpf_l4_csum_replace(skb, csum_off, pod_port, nat_port, sizeof(__be16));
  }

  return TC_ACT_OK;
}
