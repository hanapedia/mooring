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

// Looks up the nat_map revnat entry for the (server_ip, pod_ip, server_port,
// nat_port, proto) tuple implied by the current packet -- dst must already
// be pod_ip by the time this is called (stage 1, if any, has already run
// this pass). Returns NULL on a miss; callers decide what that means (a
// genuine cross-node transit candidate vs. traffic that was never a tracked
// mooring flow at all) -- this function has no opinion either way, see
// revnat_core's two call sites.
//
// Re-derives packet pointers from ctx so callers that have already invoked
// a csum helper (which, on the skb/TC side, can invalidate PTR_TO_PACKET
// registers) can safely call this.
static __always_inline struct nat_map_val *
lookup_revnat_entry(__ctx_buff *ctx, __be16 nat_port, __be16 server_port) {
  void *data = ctx_data(ctx);
  void *data_end = ctx_data_end(ctx);

  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end)
    return NULL;

  struct iphdr *iph = (void *)(eth + 1);
  if ((void *)(iph + 1) > data_end)
    return NULL;

  struct nat_map_key revnat_key = {
      .ip_a = iph->saddr, // server_ip
      .ip_b = iph->daddr, // pod_ip
      .port_a = server_port,
      .port_b = nat_port,
      .proto = iph->protocol,
      .kind = NAT_ENTRY_REVNAT,
  };
  // bpf_printk("revnat: lookup src=%x dst=%x port=%u\n",
  //            bpf_ntohl(iph->saddr), bpf_ntohl(iph->daddr),
  //            bpf_ntohs(nat_port));
  return bpf_map_lookup_elem(&nat_map, &revnat_key);
}

// Builds the revnat/snat key pair for the current flow and hands off to the
// shared TCP close state machine (track_tcp_close, maps.h) -- nv (already
// found by lookup_revnat_entry) is "own" (the revnat entry); the paired snat
// entry is "peer". No packet access -- every scalar here is something the
// caller already has in hand (safe to use regardless of any csum helper
// that may have run since it was captured).
//
// Takes pod_port explicitly rather than reading nv->port itself: track_tcp_close
// can delete nv's own backing map entry on a confirmed close, so the caller
// must have already cached pod_port as a plain scalar *before* calling this
// -- see do_port_revnat below, which is called with that same cached value
// rather than nv, for exactly this reason.
static __always_inline void revnat_track_tcp_close(__be32 server_ip,
                                                    __be32 pod_ip,
                                                    __be16 server_port,
                                                    __be16 nat_port,
                                                    __be16 pod_port,
                                                    struct nat_map_val *nv,
                                                    __u8 fin, __u8 rst,
                                                    __u8 ack) {
  struct nat_map_key revnat_key = {
      .ip_a = server_ip,
      .ip_b = pod_ip,
      .port_a = server_port,
      .port_b = nat_port,
      .proto = IPPROTO_TCP,
      .kind = NAT_ENTRY_REVNAT,
  };
  struct nat_map_key snat_key = {
      .ip_a = pod_ip,
      .ip_b = server_ip,
      .port_a = pod_port,
      .port_b = server_port,
      .proto = IPPROTO_TCP,
      .kind = NAT_ENTRY_SNAT,
  };
  track_tcp_close(&revnat_key, nv, &snat_key, fin, rst, ack);
}

// Stage 2: rewrite nat_port back to pod_port for a packet whose destination
// is already pod_ip. csum_off is the byte offset of the port/id checksum
// field (tcph->check / udph->check / icmph->checksum), computed once by the
// caller during L4 parsing.
//
// Takes pod_port as a plain scalar rather than the nat_map_val it came from
// -- this is purely the rewrite now (TCP close tracking is the caller's job,
// see revnat_track_tcp_close above), and the scalar is also what keeps this
// safe to call *after* revnat_track_tcp_close, which may have already
// deleted the map entry pod_port was read from.
//
// Always returns CTX_PASS: by the time this is called, the only decision
// left (redirect vs. pass on a nat_map miss) has already been made by the
// caller via lookup_revnat_entry's result.
//
// Re-derives packet pointers from ctx for the same reason
// lookup_revnat_entry does.
static __always_inline int do_port_revnat(__ctx_buff *ctx, __be16 pod_port,
                                          __be16 nat_port, __u32 csum_off) {
  void *data = ctx_data(ctx);
  void *data_end = ctx_data_end(ctx);

  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end)
    return CTX_PASS; // unreachable in practice -- caller already bounds-checked this

  struct iphdr *iph = (void *)(eth + 1);
  if ((void *)(iph + 1) > data_end)
    return CTX_PASS; // unreachable in practice -- caller already bounds-checked this

  // rewrite headers before the csum helper -- on the skb/TC side,
  // bpf_l4_csum_replace calls skb_make_writable internally, which can
  // invalidate PTR_TO_PACKET registers.
  if (iph->protocol == IPPROTO_TCP) {
    struct tcphdr *tcph = (void *)iph + sizeof(struct iphdr);
    if ((void *)(tcph + 1) > data_end)
      return CTX_PASS; // unreachable in practice -- caller already bounds-checked this
    tcph->dest = pod_port;
  } else if (iph->protocol == IPPROTO_UDP) {
    struct udphdr *udph = (void *)iph + sizeof(struct iphdr);
    if ((void *)(udph + 1) > data_end)
      return CTX_PASS; // unreachable in practice -- caller already bounds-checked this
    udph->dest = pod_port;
  } else { // ICMP (use port as id)
    struct icmphdr *icmph = (void *)iph + sizeof(struct iphdr);
    if ((void *)(icmph + 1) > data_end)
      return CTX_PASS; // unreachable in practice -- caller already bounds-checked this
    icmph->un.echo.id = pod_port;
  }

  // bpf_printk("revnat: stage2 local src=%x dst=%x port=%u\n",
  //            bpf_ntohl(iph->saddr), bpf_ntohl(iph->daddr),
  //            bpf_ntohs(nat_port));

  ctx_l4_csum_replace_port(ctx, csum_off, nat_port, pod_port);

  return CTX_PASS;
}

/*
 * Is dest a known mooring IP, and which kind? (single dst_kind hash lookup,
 * before any LPM walk or L4 parsing)
 * - miss -> not meant for mooring at all (e.g. another system, such as
 *           coil's Egress feature, sharing a destination range with a
 *           mooring NATConfig) -> CTX_PASS. This is the cheap primary
 *           filter: the overwhelming majority of ingress traffic has
 *           nothing to do with mooring and is rejected here by one hash
 *           lookup, never touching target_cidrs or any other map.
 * - hit  -> is src in target_cidrs? A secondary filter, now worth paying
 *           for (an LPM walk) only because dst already matched one of our
 *           own IPs: it catches traffic that guessed/spoofed a live
 *           ext-IP+port or local pod IP but isn't actually coming from a
 *           server this pod talks to, before it can reach port_range_lookup
 *           or trigger a cross-node ctx_redirect_transit attempt. It is
 *           *not* a correctness boundary either way -- lookup_revnat_entry's
 *           nat_map lookup, keyed on the exact src IP+port, is the real
 *           authority in both branches below; this just keeps unauthenticated
 *           noise from reaching that far.
 * - no   -> CTX_PASS
 * - EXT_IP -> stage 1: resolve pod_ip from the port, rewrite dst, then look
 *             up the nat_map revnat entry (lookup_revnat_entry): found ->
 *             stage 2 (do_port_revnat); not found -> the pod lives on
 *             another node -> forward it (ctx_redirect_transit)
 * - POD_IP -> same lookup, but a miss doesn't change the outcome here --
 *             this was never a tracked NAT flow, so just CTX_PASS the same
 *             as a hit (which already rewrote the packet in place); never
 *             redirect
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

  // Captured as plain scalars (never re-read from iph later in this
  // function) so they stay valid regardless of any csum helper that may run
  // in between -- on the skb/TC side, bpf_l3/l4_csum_replace call
  // skb_make_writable internally, which can invalidate PTR_TO_PACKET
  // registers, including iph itself. src and protocol never change; dst
  // only changes (ext_ip -> pod_ip) in the EXT_IP branch below, where the
  // rewritten value is itself captured as pod_ip.
  __be32 server_ip = iph->saddr;
  __be32 daddr = iph->daddr;
  __u8 proto = iph->protocol;

  // Single exact-match lookup classifying dst, before any L4 parsing or LPM
  // walk. A miss here is the fix for a real bug: previously, a dst that
  // wasn't an ext IP was *assumed* to already be a tracked pod IP (stage 1
  // having run on another node) with no verification -- so traffic
  // belonging to another system entirely got treated as an already-stage1'd
  // mooring flow and, on the inevitable nat_map miss, was forcibly
  // redirected instead of passed through. See bpf/headers/revnat_maps.h for
  // dst_kind's lifecycle.
  __u8 *kind_ptr = bpf_map_lookup_elem(&dst_kind, &daddr);
  if (!kind_ptr) {
    // bpf_printk("revnat: dst_kind miss src=%x dst=%x -- not mooring\n",
    //            bpf_ntohl(server_ip), bpf_ntohl(daddr));
    return CTX_PASS;
  }
  __u8 kind = *kind_ptr;

  // dst matched one of our own IPs -- now worth the LPM cost of checking
  // src, to filter unauthenticated noise before port_range_lookup/nat_map.
  struct lpm_key slpm = {
      .prefixlen = 32, /* match src IP exactly */
      .addr = server_ip,
  };
  if (!bpf_map_lookup_elem(&target_cidrs, &slpm))
    return CTX_PASS;

  // handle only tcp, udp, or icmp
  if (proto != IPPROTO_TCP && proto != IPPROTO_UDP && proto != IPPROTO_ICMP)
    return CTX_PASS;

  // parse l4 header (shared by both DST_KIND_EXT_IP and DST_KIND_POD_IP).
  // tcp_fin/tcp_rst/tcp_ack are captured as plain scalars here too, same
  // reasoning as server_ip/daddr above -- revnat_track_tcp_close uses them
  // well after any csum helper the EXT_IP branch below might run.
  __be16 nat_port, server_port;
  __u32 l4_off = sizeof(struct ethhdr) + sizeof(struct iphdr);
  __u32 csum_off;
  __u8 tcp_fin = 0, tcp_rst = 0, tcp_ack = 0;

  if (proto == IPPROTO_TCP) {
    struct tcphdr *tcph = (void *)iph + sizeof(struct iphdr);
    if ((void *)(tcph + 1) > data_end)
      return CTX_PASS;
    nat_port = tcph->dest;
    server_port = tcph->source;
    csum_off = l4_off + offsetof(struct tcphdr, check);
    tcp_fin = tcph->fin;
    tcp_rst = tcph->rst;
    tcp_ack = tcph->ack;
  } else if (proto == IPPROTO_UDP) {
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

  if (kind == DST_KIND_POD_IP) {
    // dst is already a pod IP (stage 1 ran on another node, or this was
    // never a tracked NAT flow at all). Either way, found or not, pass it
    // through -- a hit rewrites in place; a miss means this was never a
    // tracked flow.
    struct nat_map_val *nv = lookup_revnat_entry(ctx, nat_port, server_port);
    if (!nv)
      return CTX_PASS;
    __be16 pod_port = nv->port; // cache before revnat_track_tcp_close, which
                                 // may delete nv's own backing map entry
    if (proto == IPPROTO_TCP)
      revnat_track_tcp_close(server_ip, daddr, server_port, nat_port,
                             pod_port, nv, tcp_fin, tcp_rst, tcp_ack);
    return do_port_revnat(ctx, pod_port, nat_port, csum_off);
  }

  // DST_KIND_EXT_IP: stage 1 -- lookup per-protocol port range to find pod ip
  // bpf_printk("revnat: stage1 path src=%x dst=%x port=%u\n",
  //            bpf_ntohl(server_ip), bpf_ntohl(daddr), bpf_ntohs(nat_port));

  __be32 ext_ip = daddr;
  void *inner;
  if (proto == IPPROTO_TCP) {
    inner = bpf_map_lookup_elem(&port_range_lookup_tcp, &ext_ip);
  } else if (proto == IPPROTO_UDP) {
    inner = bpf_map_lookup_elem(&port_range_lookup_udp, &ext_ip);
  } else { // ICMP
    inner = bpf_map_lookup_elem(&port_range_lookup_icmp, &ext_ip);
  }
  if (!inner) {
    // bpf_printk("revnat: stage1 port_range miss ext=%x port=%u\n",
    //            bpf_ntohl(ext_ip), bpf_ntohs(nat_port));
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
  if (proto != IPPROTO_ICMP) {
    ctx_l3_csum_replace(ctx, ip_csum, ext_ip, pod_ip);
    ctx_l4_csum_replace_ip(ctx, csum_off, ext_ip, pod_ip);
  } else {
    ctx_l3_csum_replace(ctx, ip_csum, ext_ip, pod_ip);
  }

  // lookup_revnat_entry re-derives its own packet pointers, so it is safe to
  // call after the csum helpers above. dst was just rewritten this pass, so
  // unlike the DST_KIND_POD_IP branch above, a miss here genuinely means
  // the pod lives on another node -- forward it there rather than passing
  // it through with an unrewritten port.
  struct nat_map_val *nv = lookup_revnat_entry(ctx, nat_port, server_port);
  if (!nv)
    return ctx_redirect_transit(ctx);
  __be16 pod_port = nv->port; // cache before revnat_track_tcp_close, which
                               // may delete nv's own backing map entry
  if (proto == IPPROTO_TCP)
    revnat_track_tcp_close(server_ip, pod_ip, server_port, nat_port,
                           pod_port, nv, tcp_fin, tcp_rst, tcp_ack);
  return do_port_revnat(ctx, pod_port, nat_port, csum_off);
}
