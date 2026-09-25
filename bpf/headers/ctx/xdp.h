// SPDX-License-Identifier: GPL-2.0
#pragma once

// XDP context adapter. Counterpart of ctx/skb.h -- see that file for the
// shared contract every symbol here implements. XDP has neither
// bpf_l3_csum_replace/bpf_l4_csum_replace nor bpf_redirect_neigh, so both
// checksum maintenance and the cross-node transit redirect are implemented
// by hand here instead of delegating to a kernel helper.

// vmlinux.h must come before tc.h -- see the comment in ctx/skb.h.
#include "../vmlinux.h"
#include "../tc.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

// Macro, not typedef: same CO-RE relocation reason as ctx/skb.h.
#define __ctx_buff struct xdp_md

#define CTX_PASS XDP_PASS
#define CTX_DROP XDP_DROP

static __always_inline void *ctx_data(const __ctx_buff *ctx) {
  return (void *)(long)ctx->data;
}

static __always_inline void *ctx_data_end(const __ctx_buff *ctx) {
  return (void *)(long)ctx->data_end;
}

// RFC 1071/1624 incremental one's-complement checksum update. Operates on
// the raw big-endian bit patterns throughout (no htons/ntohs anywhere) --
// that's what makes plain 16-bit-word one's-complement addition produce the
// correct on-the-wire checksum bytes regardless of host byte order. This is
// the same math bpf_l3_csum_replace/bpf_l4_csum_replace perform internally;
// XDP just has no helper to do it for us.
static __always_inline __u16 csum_fold(__u32 csum) {
  csum = (csum & 0xffff) + (csum >> 16);
  csum = (csum & 0xffff) + (csum >> 16); // second pass: fold any carry from the first
  return (__u16)~csum;
}

// 32-bit field replace (e.g. an IPv4 address, in either the real IP header
// or a TCP/UDP pseudo-header).
static __always_inline void csum_replace_u32(__be16 *csum_field, __be32 from,
                                              __be32 to) {
  __u32 csum = (__u32)(__u16) ~(*csum_field);
  csum += (~from >> 16) & 0xffff;
  csum += (~from) & 0xffff;
  csum += (to >> 16) & 0xffff;
  csum += to & 0xffff;
  *csum_field = csum_fold(csum);
}

// 16-bit field replace (e.g. a TCP/UDP port or an ICMP echo id).
static __always_inline void csum_replace_u16(__be16 *csum_field, __be16 from,
                                              __be16 to) {
  __u32 csum = (__u32)(__u16) ~(*csum_field);
  csum += (__u16) ~from;
  csum += (__u16)to;
  *csum_field = csum_fold(csum);
}

// Adapter signatures take a byte offset (matching ctx/skb.h, whose
// bpf_l3_csum_replace/bpf_l4_csum_replace helpers require one -- see the
// comment there) rather than a field pointer, even though XDP packet
// pointers never get invalidated the way skb ones do. Reconstruct and
// bounds-check the pointer from the offset here; the check is always
// provably true at runtime (callers only ever pass offsets within a header
// region they've already bounds-checked) but the verifier still requires it
// to be visible on this exact derivation path.
static __always_inline void ctx_l3_csum_replace(__ctx_buff *ctx,
                                                 __u32 csum_off, __be32 from,
                                                 __be32 to) {
  void *data = ctx_data(ctx);
  void *data_end = ctx_data_end(ctx);
  __be16 *field = data + csum_off;
  if ((void *)(field + 1) > data_end)
    return;
  csum_replace_u32(field, from, to);
}

static __always_inline void ctx_l4_csum_replace_ip(__ctx_buff *ctx,
                                                    __u32 csum_off,
                                                    __be32 from, __be32 to) {
  void *data = ctx_data(ctx);
  void *data_end = ctx_data_end(ctx);
  __be16 *field = data + csum_off;
  if ((void *)(field + 1) > data_end)
    return;
  csum_replace_u32(field, from, to);
}

static __always_inline void ctx_l4_csum_replace_port(__ctx_buff *ctx,
                                                      __u32 csum_off,
                                                      __be16 from,
                                                      __be16 to) {
  void *data = ctx_data(ctx);
  void *data_end = ctx_data_end(ctx);
  __be16 *field = data + csum_off;
  if ((void *)(field + 1) > data_end)
    return;
  csum_replace_u16(field, from, to);
}

// Substitute for bpf_redirect_neigh: resolve the next hop + its L2 address
// via a forwarding-style FIB lookup, rewrite the Ethernet header by hand,
// and redirect out the resolved interface.
//
// On BPF_FIB_LKUP_RET_NO_NEIGH we DROP rather than falling back to
// XDP_PASS. XDP_PASS would hand the packet to the kernel's normal
// ip_forward() path, which is exactly where the netfilter/conntrack
// exposure this redirect exists to avoid would reappear (the packet's
// addresses were just rewritten by stage 1, so it won't match existing
// conntrack state and can hit a KUBE-FORWARD ctstate-INVALID drop). A
// genuine miss here should be rare in practice: the resolved neighbor is
// the uplink's BGP next hop, which stays warm as a side effect of the BGP
// session itself being up, not something revnat traffic depends on freshly
// resolving.
static __always_inline int ctx_redirect_transit(__ctx_buff *ctx) {
  void *data = ctx_data(ctx);
  void *data_end = ctx_data_end(ctx);

  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end)
    return CTX_DROP;

  struct iphdr *iph = (void *)(eth + 1);
  if ((void *)(iph + 1) > data_end)
    return CTX_DROP;

  struct bpf_fib_lookup fib_params = {};
  fib_params.family = AF_INET;
  fib_params.tos = iph->tos;
  fib_params.l4_protocol = iph->protocol;
  fib_params.tot_len = bpf_ntohs(iph->tot_len);
  fib_params.ipv4_src = iph->saddr;
  fib_params.ipv4_dst = iph->daddr;
  fib_params.ifindex = ctx->ingress_ifindex;

  // Forwarding-style lookup (flags = 0), matching what ip_forward()/
  // bpf_redirect_neigh would do -- not a locally-originated-packet lookup.
  int rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);
  if (rc != BPF_FIB_LKUP_RET_SUCCESS) {
    bpf_printk("revnat: xdp transit fib_lookup miss rc=%d ifindex=%u\n", rc,
               ctx->ingress_ifindex);
    // TODO(observability): this printk is a placeholder. Add a real
    // counter/metric for this drop path once datapath observability
    // (counters exported via moorctl/metrics) lands.
    return CTX_DROP;
  }

  eth->h_proto = bpf_htons(ETH_P_IP);
  __builtin_memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
  __builtin_memcpy(eth->h_source, fib_params.smac, ETH_ALEN);

  return bpf_redirect(fib_params.ifindex, 0);
}
