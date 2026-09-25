// SPDX-License-Identifier: GPL-2.0
#pragma once

// Shared revnat stage1 (stateless ext-IP -> pod-IP rewrite) + stage2
// (stateful nat-port -> pod-port rewrite, including the cross-node transit
// redirect) logic. Written purely in terms of __ctx_buff and the ctx_*
// adapter functions so it compiles unchanged under both
// bpf/headers/ctx/skb.h (TC, included by bpf/revnat_ingress.c) and
// bpf/headers/ctx/xdp.h (XDP, included by bpf/revnat_xdp.c) -- see those two
// files for what each ctx_* name resolves to in each context.

#include "maps.h"
#include "revnat_maps.h"
#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

// Stage 2: rewrite nat_port back to the original pod_port for a packet whose
// destination is now a pod IP (either because stage1 just ran in this same
// pass, or because it arrived on the pod's own node after stage1 ran
// remotely). csum_off is the byte offset of the port/id checksum field
// (tcph->check / udph->check / icmph->checksum), computed once by the
// caller during L4 parsing.
//
// Re-derives packet pointers from ctx so callers that have already invoked
// a csum helper (which, on the skb/TC side, can invalidate PTR_TO_PACKET
// registers) can safely call this.
static __always_inline int do_port_revnat(__ctx_buff *ctx, __be16 nat_port,
                                          __be16 server_port,
                                          __u32 csum_off) {
  void *data = ctx_data(ctx);
  void *data_end = ctx_data_end(ctx);

  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end)
    return CTX_PASS;

  struct iphdr *iph = (void *)(eth + 1);
  if ((void *)(iph + 1) > data_end)
    return CTX_PASS;

  // look up the revnat entry in nat_map to see if the pod is local
  struct nat_map_key revnat_key = {
      .ip_a = iph->saddr, // server_ip
      .ip_b = iph->daddr, // pod_ip
      .port_a = server_port,
      .port_b = nat_port,
      .proto = iph->protocol,
      .kind = NAT_ENTRY_REVNAT,
  };
  struct nat_map_val *nv = bpf_map_lookup_elem(&nat_map, &revnat_key);
  if (!nv) {
    bpf_printk("revnat: stage2 not-local src=%x dst=%x port=%u\n",
               bpf_ntohl(iph->saddr), bpf_ntohl(iph->daddr),
               bpf_ntohs(nat_port));
    return ctx_redirect_transit(ctx);
  }

  __be16 pod_port = nv->port;

  // rewrite headers before the csum helper -- on the skb/TC side,
  // bpf_l4_csum_replace calls skb_make_writable internally, which can
  // invalidate PTR_TO_PACKET registers.
  if (iph->protocol == IPPROTO_TCP) {
    struct tcphdr *tcph = (void *)iph + sizeof(struct iphdr);
    if ((void *)(tcph + 1) > data_end)
      return CTX_PASS;

    // Mirror of the connection tracking in snat_egress.c, for the
    // server->pod direction (a server-initiated FIN/RST, or the server's
    // ACK confirming a pod-initiated close, never appears on the egress
    // path). See snat_egress.c's try_alloc_port for the matching stale-entry
    // reclaim during allocation.
    struct nat_map_key snat_key = {
        .ip_a = revnat_key.ip_b, // pod_ip
        .ip_b = revnat_key.ip_a, // server_ip
        .port_a = pod_port,
        .port_b = revnat_key.port_a, // server_port
        .proto = IPPROTO_TCP,
        .kind = NAT_ENTRY_SNAT,
    };
    if (nv->closing_ns) {
      // See snat_egress.c for why this requires a second FIN/RST rather than
      // a plain ACK (half-closed connections would otherwise be torn down
      // while one direction is still flowing).
      if ((tcph->fin || tcph->rst) && tcph->ack) {
        bpf_map_delete_elem(&nat_map, &revnat_key);
        bpf_map_delete_elem(&nat_map, &snat_key);
      }
    } else if (tcph->fin || tcph->rst) {
      __u64 now = bpf_ktime_get_ns();
      nv->closing_ns = now;
      struct nat_map_val *sv = bpf_map_lookup_elem(&nat_map, &snat_key);
      if (sv)
        sv->closing_ns = now;
    }

    tcph->dest = pod_port;
  } else if (iph->protocol == IPPROTO_UDP) {
    struct udphdr *udph = (void *)iph + sizeof(struct iphdr);
    if ((void *)(udph + 1) > data_end)
      return CTX_PASS;
    udph->dest = pod_port;
  } else { // ICMP (use port as id)
    struct icmphdr *icmph = (void *)iph + sizeof(struct iphdr);
    if ((void *)(icmph + 1) > data_end)
      return CTX_PASS;
    icmph->un.echo.id = pod_port;
  }

  bpf_printk("revnat: stage2 local src=%x dst=%x port=%u\n",
             bpf_ntohl(iph->saddr), bpf_ntohl(iph->daddr),
             bpf_ntohs(nat_port));

  ctx_l4_csum_replace_port(ctx, csum_off, nat_port, pod_port);

  return CTX_PASS;
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
static __always_inline int revnat_core(__ctx_buff *ctx) {
  void *data = ctx_data(ctx);
  void *data_end = ctx_data_end(ctx);

  // parse ethernet header
  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end)
    return CTX_PASS;

  if (eth->h_proto != bpf_htons(ETH_P_IP))
    return CTX_PASS;

  // parse IP header
  struct iphdr *iph = (void *)(eth + 1);
  if ((void *)(iph + 1) > data_end)
    return CTX_PASS;

  // look up src against target_cidrs
  struct lpm_key slpm = {
      .prefixlen = 32, /* match src IP exactly */
      .addr = iph->saddr,
  };
  if (!bpf_map_lookup_elem(&target_cidrs, &slpm))
    return CTX_PASS;

  // handle only tcp, udp, or icmp
  if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP &&
      iph->protocol != IPPROTO_ICMP)
    return CTX_PASS;

  // parse l4 header
  __be16 nat_port, server_port;
  __u32 l4_off = sizeof(struct ethhdr) + sizeof(struct iphdr);
  __u32 csum_off;

  if (iph->protocol == IPPROTO_TCP) {
    struct tcphdr *tcph = (void *)iph + sizeof(struct iphdr);
    if ((void *)(tcph + 1) > data_end)
      return CTX_PASS;
    nat_port = tcph->dest;
    server_port = tcph->source;
    csum_off = l4_off + offsetof(struct tcphdr, check);
  } else if (iph->protocol == IPPROTO_UDP) {
    struct udphdr *udph = (void *)iph + sizeof(struct iphdr);
    if ((void *)(udph + 1) > data_end)
      return CTX_PASS;
    nat_port = udph->dest;
    server_port = udph->source;
    csum_off = l4_off + offsetof(struct udphdr, check);
  } else { // ICMP (use port as id)
    struct icmphdr *icmph = (void *)iph + sizeof(struct iphdr);
    if ((void *)(icmph + 1) > data_end)
      return CTX_PASS;
    // handle only echo for now
    if (icmph->type != ICMP_ECHOREPLY)
      return CTX_PASS;
    nat_port = icmph->un.echo.id;
    server_port = 0;
    csum_off = l4_off + offsetof(struct icmphdr, checksum);
  }

  // look up dest against ext ip pool
  struct lpm_key dlpm = {
      .prefixlen = 32, /* match dest IP exactly */
      .addr = iph->daddr,
  };
  // dst is not an external IP — stage 1 already ran on another node and dst
  // is now pod_ip. attempt stage 2 directly.
  if (!bpf_map_lookup_elem(&ext_ip_pool, &dlpm)) {
    bpf_printk("revnat: stage2 path src=%x dst=%x\n", bpf_ntohl(iph->saddr),
               bpf_ntohl(iph->daddr));
    return do_port_revnat(ctx, nat_port, server_port, csum_off);
  }

  bpf_printk("revnat: stage1 path src=%x dst=%x port=%u\n",
             bpf_ntohl(iph->saddr), bpf_ntohl(iph->daddr),
             bpf_ntohs(nat_port));

  // lookup per-protocol port range to find pod ip
  __be32 ext_ip = iph->daddr;
  void *inner;
  if (iph->protocol == IPPROTO_TCP) {
    inner = bpf_map_lookup_elem(&port_range_lookup_tcp, &ext_ip);
  } else if (iph->protocol == IPPROTO_UDP) {
    inner = bpf_map_lookup_elem(&port_range_lookup_udp, &ext_ip);
  } else { // ICMP
    inner = bpf_map_lookup_elem(&port_range_lookup_icmp, &ext_ip);
  }
  if (!inner) {
    bpf_printk("revnat: stage1 port_range miss ext=%x port=%u\n",
               bpf_ntohl(iph->daddr), bpf_ntohs(nat_port));
    return CTX_PASS;
  }
  __u32 port_idx = bpf_ntohs(nat_port);
  __be32 *pod_ip_ptr = bpf_map_lookup_elem(inner, &port_idx);
  if (!pod_ip_ptr || !*pod_ip_ptr) // check if the value is zero
    return CTX_PASS;

  // rewrite dst IP before csum helpers (which, on the skb/TC side,
  // invalidate PTR_TO_PACKET registers)
  __be32 pod_ip = *pod_ip_ptr;
  iph->daddr = pod_ip;

  __u32 ip_csum = sizeof(struct ethhdr) + offsetof(struct iphdr, check);
  if (iph->protocol != IPPROTO_ICMP) {
    ctx_l3_csum_replace(ctx, ip_csum, ext_ip, pod_ip);
    ctx_l4_csum_replace_ip(ctx, csum_off, ext_ip, pod_ip);
  } else {
    ctx_l3_csum_replace(ctx, ip_csum, ext_ip, pod_ip);
  }

  // do_port_revnat re-derives its own packet pointers, so it is safe to
  // call after the csum helpers above.
  return do_port_revnat(ctx, nat_port, server_port, csum_off);
}
