// SPDX-License-Identifier: GPL-2.0
#pragma once

// Protocol-dependent L4 helpers shared by revnat_core.h (server->pod
// direction) and snat_egress.c (pod->server direction). Both sides parse a
// TCP/UDP/ICMP header into the same shape, rewrite one port field back out,
// and fix up checksums the same way when an IP address changes -- this file
// is where that per-protocol branching lives, so neither caller's main logic
// has to switch on proto itself.
//
// Written in terms of plain data/data_end/iph pointers (not __ctx_buff) for
// parse/write, since neither needs anything from ctx beyond the packet
// pointers the caller already derived. The checksum helper below does take
// __ctx_buff, so it relies on the caller having already included one of
// ctx/skb.h or ctx/xdp.h first (same convention revnat_core.h already
// follows).

#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

// Raw per-protocol L4 extraction, wire-header-order (source/dest). ICMP has
// no source/dest pair -- its one port (the echo id) comes back via icmp_id,
// with src_port/dst_port left zeroed. Callers that need ICMP's id folded
// into their own "nat_port"/"pod_port"/etc. terminology do that mapping
// themselves (it's a one-line direction choice, not a parsing concern).
struct l4_raw {
  __be16 src_port;  // tcph->source / udph->source, else 0
  __be16 dst_port;  // tcph->dest / udph->dest, else 0
  __be16 icmp_id;   // icmph->un.echo.id, else 0
  __u8 icmp_type;   // icmph->type -- only meaningful if proto == IPPROTO_ICMP
  __u32 csum_off;   // byte offset of the L4 checksum field
  __u8 tcp_syn, tcp_fin, tcp_rst, tcp_ack; // only meaningful if proto == IPPROTO_TCP
};

// Is iph unparseable as a single, complete IP+L4 header? Two independent
// reasons: ihl < 5 is a malformed header (shorter than the IPv4 minimum,
// so even the base IP fields can't be trusted); a non-first fragment
// (frag_off's MF bit or a nonzero offset) carries no L4 header at all --
// it's a raw continuation of the original datagram's payload, so reading
// anything at the assumed L4 offset would read attacker-controlled
// payload bytes as if they were ports/flags. ihl > 5 (IP options) is
// deliberately *not* rejected here -- see ip_hdr_len below, which is what
// lets a packet with options still be parsed correctly instead of needing
// to reject it.
static __always_inline int ip_header_unparseable(struct iphdr *iph) {
  return iph->ihl < 5 ||
         (bpf_ntohs(iph->frag_off) & (IP_MF | IP_OFFSET)) != 0;
}

// Byte length of iph's header including options, for callers that have
// already rejected ip_header_unparseable(iph) -- ihl is otherwise
// untrusted input (attacker-controlled on any packet they send).
static __always_inline __u32 ip_hdr_len(struct iphdr *iph) {
  return iph->ihl * 4;
}

// l4_off is the byte offset of the L4 header from the start of the packet
// (used to turn offsetof(...) into an absolute csum_off). Returns 0 on a
// bounds-check miss (header doesn't fit before data_end); *out is left
// partially written in that case and must not be used.
static __always_inline int parse_l4_raw(void *data_end, struct iphdr *iph,
                                        __u32 l4_off, __u8 proto,
                                        struct l4_raw *out) {
  void *l4 = (void *)iph + ip_hdr_len(iph);
  switch (proto) {
  case IPPROTO_TCP: {
    struct tcphdr *tcph = l4;
    if ((void *)(tcph + 1) > data_end)
      return 0;
    out->src_port = tcph->source;
    out->dst_port = tcph->dest;
    out->csum_off = l4_off + offsetof(struct tcphdr, check);
    out->tcp_syn = tcph->syn;
    out->tcp_fin = tcph->fin;
    out->tcp_rst = tcph->rst;
    out->tcp_ack = tcph->ack;
    return 1;
  }
  case IPPROTO_UDP: {
    struct udphdr *udph = l4;
    if ((void *)(udph + 1) > data_end)
      return 0;
    out->src_port = udph->source;
    out->dst_port = udph->dest;
    out->csum_off = l4_off + offsetof(struct udphdr, check);
    return 1;
  }
  default: { // IPPROTO_ICMP
    struct icmphdr *icmph = l4;
    if ((void *)(icmph + 1) > data_end)
      return 0;
    out->icmp_id = icmph->un.echo.id;
    out->icmp_type = icmph->type;
    out->csum_off = l4_off + offsetof(struct icmphdr, checksum);
    return 1;
  }
  }
}

// Overwrites the header's source-side port field in place: tcph->source /
// udph->source / icmph echo id (ICMP has only the one field -- "source" here
// just means "the field write_l4_src_port owns", paired with
// write_l4_dst_port below owning the other slot for protocols that have
// one). Returns 0 on a bounds-check miss.
static __always_inline int write_l4_src_port(void *data_end,
                                             struct iphdr *iph, __u8 proto,
                                             __be16 new_port) {
  void *l4 = (void *)iph + ip_hdr_len(iph);
  if (proto == IPPROTO_TCP) {
    struct tcphdr *tcph = l4;
    if ((void *)(tcph + 1) > data_end)
      return 0;
    tcph->source = new_port;
  } else if (proto == IPPROTO_UDP) {
    struct udphdr *udph = l4;
    if ((void *)(udph + 1) > data_end)
      return 0;
    udph->source = new_port;
  } else { // ICMP
    struct icmphdr *icmph = l4;
    if ((void *)(icmph + 1) > data_end)
      return 0;
    icmph->un.echo.id = new_port;
  }
  return 1;
}

// Overwrites the header's destination-side port field in place: tcph->dest /
// udph->dest / icmph echo id. See write_l4_src_port above.
static __always_inline int write_l4_dst_port(void *data_end,
                                             struct iphdr *iph, __u8 proto,
                                             __be16 new_port) {
  void *l4 = (void *)iph + ip_hdr_len(iph);
  if (proto == IPPROTO_TCP) {
    struct tcphdr *tcph = l4;
    if ((void *)(tcph + 1) > data_end)
      return 0;
    tcph->dest = new_port;
  } else if (proto == IPPROTO_UDP) {
    struct udphdr *udph = l4;
    if ((void *)(udph + 1) > data_end)
      return 0;
    udph->dest = new_port;
  } else { // ICMP
    struct icmphdr *icmph = l4;
    if ((void *)(icmph + 1) > data_end)
      return 0;
    icmph->un.echo.id = new_port;
  }
  return 1;
}

// Updates the L3 checksum for an IP address change, and -- except for ICMP,
// whose checksum has no pseudo-header -- the L4 checksum's pseudo-header
// contribution too. Requires one of ctx/skb.h or ctx/xdp.h to already be
// included by the caller (for __ctx_buff and ctx_l3_csum_replace/
// ctx_l4_csum_replace_ip).
static __always_inline void fixup_ip_change_csum(__ctx_buff *ctx, __u8 proto,
                                                 __u32 ip_csum_off,
                                                 __u32 l4_csum_off,
                                                 __be32 from_ip,
                                                 __be32 to_ip) {
  ctx_l3_csum_replace(ctx, ip_csum_off, from_ip, to_ip);
  if (proto != IPPROTO_ICMP)
    ctx_l4_csum_replace_ip(ctx, l4_csum_off, from_ip, to_ip);
}
