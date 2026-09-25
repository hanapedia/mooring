// SPDX-License-Identifier: GPL-2.0
#pragma once

// TC/skb context adapter. revnat_core.h is written purely in terms of
// __ctx_buff and the ctx_* functions below; this header (included before
// revnat_core.h by revnat_ingress.c) resolves them to the skb-specific
// implementation, so the shared core compiles as a tcx/ingress program.
//
// See ctx/xdp.h for the XDP-side counterpart of every symbol defined here.

// vmlinux.h must come before tc.h: tc.h's plain #define macros (e.g.
// IPPROTO_TCP) share names with vmlinux.h's BTF-generated enum constants of
// the same names, and #define-ing them first corrupts those enum
// definitions when vmlinux.h is then parsed.
#include "../vmlinux.h"
#include "../tc.h"
#include <bpf/bpf_helpers.h>

// Macro, not typedef: a typedef'd name breaks CO-RE relocation of __sk_buff's preserve_access_index fields (kernel BTF has no "__ctx_buff").
#define __ctx_buff struct __sk_buff

#define CTX_PASS TCX_NEXT
#define CTX_DROP TC_ACT_SHOT

static __always_inline void *ctx_data(__ctx_buff *ctx) {
  return (void *)(long)ctx->data;
}

static __always_inline void *ctx_data_end(__ctx_buff *ctx) {
  return (void *)(long)ctx->data_end;
}

// bpf_l3_csum_replace/bpf_l4_csum_replace take a byte offset into the
// packet, not a pointer -- and it has to stay a *scalar* offset, not a
// pointer computed from one of the parsed header structs: both helpers call
// skb_make_writable internally, which can reallocate the skb and so
// invalidates every live PTR_TO_PACKET register. A scalar offset (computed
// via sizeof/offsetof, not pointer subtraction) is immune to that -- which
// is exactly how the original revnat_ingress.c computed csum_off, and why
// call sites in revnat_core.h pass offsets here rather than field pointers.
static __always_inline void ctx_l3_csum_replace(__ctx_buff *ctx,
                                                 __u32 csum_off, __be32 from,
                                                 __be32 to) {
  bpf_l3_csum_replace(ctx, csum_off, from, to, sizeof(__be32));
}

// TCP/UDP pseudo-header checksum fixup when an IP address changes (the
// pseudo-header covers src/dst IP, so it needs updating alongside the real
// IP header checksum handled by ctx_l3_csum_replace above).
static __always_inline void ctx_l4_csum_replace_ip(__ctx_buff *ctx,
                                                    __u32 csum_off,
                                                    __be32 from, __be32 to) {
  bpf_l4_csum_replace(ctx, csum_off, from, to, BPF_F_PSEUDO_HDR | sizeof(__be32));
}

static __always_inline void ctx_l4_csum_replace_port(__ctx_buff *ctx,
                                                      __u32 csum_off,
                                                      __be16 from,
                                                      __be16 to) {
  bpf_l4_csum_replace(ctx, csum_off, from, to, sizeof(__be16));
}

// Bypasses netfilter entirely: route via the neighbor subsystem so conntrack
// never sees this transit packet (avoids KUBE-FORWARD INVALID drop). This
// holds even on a cold ARP/NDP cache -- bpf_redirect_neigh queues the packet
// in the neighbor subsystem's own resolution path rather than falling
// through to the normal ip_forward()/netfilter walk.
static __always_inline int ctx_redirect_transit(__ctx_buff *ctx) {
  return bpf_redirect_neigh(ctx->ifindex, NULL, 0, 0);
}
