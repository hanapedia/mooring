// SPDX-License-Identifier: GPL-2.0
#include "maps.h"
#include "tc.h"
#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

char __license[] SEC("license") = "GPL";

struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __uint(max_entries, 256);
  __type(key, struct lpm_key);
  __type(value, __u8);
} ext_ip_pool SEC(".maps");

/* Fill the ports in the range for allocated port each IP
 * Only for PoC.
 * For actual implementation crete range for each ext IP
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 65536);
  __type(key, struct port_key);
  __type(value, __be32); // pod_ip
} port_range_lookup SEC(".maps");

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

// Re-derives packet pointers from skb so callers that have already called csum
// helpers (which invalidate PTR_TO_PACKET registers) can safely call this.
static __always_inline int do_port_revnat(struct __sk_buff *skb, __be16 nat_port,
                                          __be16 server_port, __u32 csum_off) {
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;

  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end)
    return TC_ACT_OK;

  struct iphdr *iph = (void *)(eth + 1);
  if ((void *)(iph + 1) > data_end)
    return TC_ACT_OK;

  // look up nat_table to see if the pod is local
  struct nat_key nk = {
      .pod_ip = iph->daddr,
      .nat_port = nat_port,
      .server_ip = iph->saddr,
      .server_port = server_port,
      .proto = iph->protocol,
  };
  struct nat_val *nv = bpf_map_lookup_elem(&nat_table, &nk);
  if (!nv) {
    bpf_printk("revnat: stage2 not-local ifindex=%u src=%x dst=%x port=%u\n", skb->ifindex, bpf_ntohl(iph->saddr), bpf_ntohl(iph->daddr), bpf_ntohs(nat_port));
    // Bypass netfilter entirely: route via the neighbor subsystem so conntrack
    // never sees this transit packet (avoids KUBE-FORWARD INVALID drop).
    return bpf_redirect_neigh(skb->ifindex, NULL, 0, 0);
  }

  __be16 pod_port = nv->pod_port;

  // rewrite headers before csum helper (bpf_l4_csum_replace calls
  // skb_make_writable, which can invalidate PTR_TO_PACKET registers)
  if (iph->protocol == IPPROTO_TCP) {
    struct tcphdr *tcph = (void *)iph + sizeof(struct iphdr);
    if ((void *)(tcph + 1) > data_end)
      return TC_ACT_OK;
    tcph->dest = pod_port;
  } else {
    struct udphdr *udph = (void *)iph + sizeof(struct iphdr);
    if ((void *)(udph + 1) > data_end)
      return TC_ACT_OK;
    udph->dest = pod_port;
  }

  bpf_printk("revnat: stage2 local ifindex=%u src=%x dst=%x port=%u\n", skb->ifindex, bpf_ntohl(iph->saddr), bpf_ntohl(iph->daddr), bpf_ntohs(nat_port));

  bpf_l4_csum_replace(skb, csum_off, nat_port, pod_port, sizeof(__be16));

  return TC_ACT_OK;
}

/*
 * Is src in target cidr
 * - yes -> continue
 * - no -> early exit
 * Is dest ext ip?
 * - yes -> stage 1
 *   nat_table hit? (pod is local)
 *   - yes -> stage2
 * - no -> is dest pod_ip with nat_table hit?
 *   - yes ->
 * Need to check if the packet's dest is any of the external IPs.
 * Look up dest IP + port to find client pod
 * rewrite header with pod IP.
 */
SEC("tc")
int revnat_ingress(struct __sk_buff *skb) {
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

  // look up src against target_cidrs
  struct lpm_key slpm = {
      .prefixlen = 32, /* match src IP exactly */
      .addr = iph->saddr,
  };
  if (!bpf_map_lookup_elem(&target_cidrs, &slpm))
    return TC_ACT_OK;

  // handle only tcp and udp (may want to handle icmp)
  if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP)
    return TC_ACT_OK;

  // parse l4 header
  __be16 nat_port, server_port;
  __u32 l4_off = sizeof(struct ethhdr) + sizeof(struct iphdr);
  __u32 csum_off;

  if (iph->protocol == IPPROTO_TCP) {
    struct tcphdr *tcph = (void *)iph + sizeof(struct iphdr);
    if ((void *)(tcph + 1) > data_end)
      return TC_ACT_OK;
    nat_port = tcph->dest;
    server_port = tcph->source;
    csum_off = l4_off + offsetof(struct tcphdr, check);
  } else {
    struct udphdr *udph = (void *)iph + sizeof(struct iphdr);
    if ((void *)(udph + 1) > data_end)
      return TC_ACT_OK;
    nat_port = udph->dest;
    server_port = udph->source;
    csum_off = l4_off + offsetof(struct udphdr, check);
  }

  // look up dest against ext ip pool
  // TODO: optimization. move before L4 parsing
  struct lpm_key dlpm = {
      .prefixlen = 32, /* match dest IP exactly */
      .addr = iph->daddr,
  };
  // dst is not an external IP — stage 1 already ran on another node and dst is
  // now pod_ip. attempt stage 2 directly.
  if (!bpf_map_lookup_elem(&ext_ip_pool, &dlpm)) {
    bpf_printk("revnat: stage2 path ifindex=%u src=%x dst=%x\n", skb->ifindex, bpf_ntohl(iph->saddr), bpf_ntohl(iph->daddr));
    return do_port_revnat(skb, nat_port, server_port, csum_off);
  }

  bpf_printk("revnat: stage1 path ifindex=%u src=%x dst=%x port=%u\n", skb->ifindex, bpf_ntohl(iph->saddr), bpf_ntohl(iph->daddr), bpf_ntohs(nat_port));

  // lookup the port range to find pod ip
  struct port_key pk = {.ext_ip = iph->daddr, .nat_port = nat_port};
  __be32 *pod_ip_ptr = bpf_map_lookup_elem(&port_range_lookup, &pk);
  if (!pod_ip_ptr) {
    bpf_printk("revnat: stage1 port_range miss ext=%x port=%u\n", bpf_ntohl(iph->daddr), bpf_ntohs(nat_port));
    return TC_ACT_OK;
  }
  __be32 pod_ip = *pod_ip_ptr;

  __be32 ext_ip = iph->daddr;

  // rewrite dst IP before csum helpers (which invalidate PTR_TO_PACKET regs)
  iph->daddr = pod_ip;

  __u32 ip_csum = sizeof(struct ethhdr) + offsetof(struct iphdr, check);
  bpf_l3_csum_replace(skb, ip_csum, ext_ip, pod_ip, sizeof(__be32));
  bpf_l4_csum_replace(skb, csum_off, ext_ip, pod_ip,
                      BPF_F_PSEUDO_HDR | sizeof(__be32));

  // do_port_revnat re-derives its own packet pointers from skb, so it is safe
  // to call after the csum helpers above have invalidated our iph pointer.
  return do_port_revnat(skb, nat_port, server_port, csum_off);
}
