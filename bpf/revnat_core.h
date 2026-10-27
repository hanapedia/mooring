// SPDX-License-Identifier: GPL-2.0
#pragma once

// Shared revnat stage1 (stateless ext-IP -> pod-IP rewrite) + stage2
// (stateful nat-port -> pod-port rewrite, including the cross-node transit
// redirect) logic. Written purely in terms of __ctx_buff and the ctx_*
// adapter functions so it compiles unchanged under both
// bpf/headers/ctx/skb.h (TC, included by bpf/revnat_ingress.c) and
// bpf/headers/ctx/xdp.h (XDP, included by bpf/revnat_xdp.c) -- see those two
// files for what each ctx_* name resolves to in each context.

#include "l4.h"
#include "maps.h"
#include "revnat_maps.h"
#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

// Ingress-direction L4 parse: resolves straight to nat_port/server_port
// (the header's dest-side field / icmp id vs. its source-side field) and
// filters out anything but ICMP_ECHOREPLY -- revnat_core only ever sees
// replies travelling server -> pod, so a request reaching this path was
// never a tracked flow. tcp_syn/fin/rst/ack are only meaningful when proto ==
// IPPROTO_TCP (left zeroed otherwise, same as the inline code this
// replaces). Returns 0 on a bounds-check miss or the ICMP-type filter.
static __always_inline int
parse_l4_hdr(void *data_end, struct iphdr *iph, __u32 l4_off, __u8 proto,
            __be16 *nat_port, __be16 *server_port, __u32 *csum_off,
            __u8 *tcp_syn, __u8 *tcp_fin, __u8 *tcp_rst, __u8 *tcp_ack) {
  struct l4_raw raw = {};
  if (!parse_l4_raw(data_end, iph, l4_off, proto, &raw))
    return 0;

  if (proto == IPPROTO_ICMP) {
    if (raw.icmp_type != ICMP_ECHOREPLY)
      return 0;
    *nat_port = raw.icmp_id;
    *server_port = 0;
  } else {
    *nat_port = raw.dst_port;
    *server_port = raw.src_port;
  }
  *csum_off = raw.csum_off;
  *tcp_syn = raw.tcp_syn;
  *tcp_fin = raw.tcp_fin;
  *tcp_rst = raw.tcp_rst;
  *tcp_ack = raw.tcp_ack;
  return 1;
}

// Picks the per-protocol outer port_range_lookup_* map (declared in
// revnat_maps.h) and looks up ext_ip in it, returning the inner
// port_range_inner_t map (or NULL on a miss) -- the __u32 port-index lookup
// into that inner map is still the caller's job, same as before.
static __always_inline void *lookup_port_range_map(__u8 proto,
                                                    __be32 ext_ip) {
  switch (proto) {
  case IPPROTO_TCP:
    return bpf_map_lookup_elem(&port_range_lookup_tcp, &ext_ip);
  case IPPROTO_UDP:
    return bpf_map_lookup_elem(&port_range_lookup_udp, &ext_ip);
  default: // ICMP
    return bpf_map_lookup_elem(&port_range_lookup_icmp, &ext_ip);
  }
}

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

  return nat_map_lookup_revnat(iph->saddr /* server_ip */,
                               iph->daddr /* pod_ip */, server_port, nat_port,
                               iph->protocol);
}

// Stage 2: given a confirmed nat_map hit (nv), rewrite nat_port back to
// pod_port, fix up the L4 checksum, and run the TCP close state machine --
// all three always happen together on a hit, so they're one call from both
// of revnat_core's call sites (DST_KIND_POD_IP and DST_KIND_EXT_IP) rather
// than being sequenced by hand at each one. The nat_map lookup itself (the
// actual hit/miss branch, and what to do on a miss) stays at the call
// sites -- that's the real decision point, not something this function
// should hide.
//
// csum_off is the byte offset of the port/id checksum field (tcph->check /
// udph->check / icmph->checksum), computed once by the caller during L4
// parsing. pod_port is taken as a plain scalar (nv->port, read by the
// caller before calling this) rather than read from nv here, since the TCP
// close tracking below may delete nv's own backing map entry.
//
// Always returns CTX_PASS: by the time this is called, the only decision
// left (redirect vs. pass on a nat_map miss) has already been made by the
// caller via lookup_revnat_entry's result. Every bounds check below is
// consequently unreachable in practice -- the caller already did it -- but
// still required to re-derive packet pointers safely after the csum helper
// the caller may have already run (same reasoning as lookup_revnat_entry).
// write_l4_dst_port runs before ctx_l4_csum_replace_port since, on the
// skb/TC side, bpf_l4_csum_replace calls skb_make_writable internally,
// which can invalidate PTR_TO_PACKET registers.
static __always_inline int
do_port_revnat(__ctx_buff *ctx, __be32 server_ip, __be32 pod_ip,
              __be16 server_port, __be16 nat_port, __be16 pod_port,
              __u32 csum_off, __u8 proto, struct nat_map_val *nv,
              __u8 tcp_fin, __u8 tcp_rst) {
  if (proto == IPPROTO_TCP)
    nat_map_track_tcp_close(server_ip, pod_ip, server_port, nat_port,
                           pod_port, nv, NAT_ENTRY_REVNAT, tcp_fin, tcp_rst);

  void *data = ctx_data(ctx);
  void *data_end = ctx_data_end(ctx);

  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end)
    return CTX_PASS;

  struct iphdr *iph = (void *)(eth + 1);
  if ((void *)(iph + 1) > data_end)
    return CTX_PASS;

  if (!write_l4_dst_port(data_end, iph, proto, pod_port))
    return CTX_PASS;

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
 *           lookup, never touching target_cidrs or any other map. See
 *           bpf/headers/revnat_maps.h for dst_kind's lifecycle.
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
 * - a TCP SYN without ACK is dropped unconditionally here, before the
 *   EXT_IP/POD_IP branch: mooring is egress-only, so a legitimate ingress
 *   packet is always a reply, and a reply never starts with a bare SYN
 *   (barring simultaneous open, ignored). This also keeps such a packet
 *   from ever reaching a pod and provoking a reply that would seed a bogus
 *   nat_map entry on egress (see snat_egress.c's matching check).
 * - EXT_IP -> stage 1: resolve pod_ip from the port, rewrite dst, then look
 *             up the nat_map revnat entry (lookup_revnat_entry): found ->
 *             stage 2 (do_port_revnat); not found -> the pod lives on
 *             another node -> forward it (ctx_redirect_transit)
 * - POD_IP -> same lookup, but a miss doesn't change the outcome here --
 *             this was never a tracked NAT flow, so just CTX_PASS the same
 *             as a hit (which already rewrote the packet in place); never
 *             redirect
 *
 * server_ip/daddr/proto/tcp_syn/tcp_fin/tcp_rst/tcp_ack below are all captured as
 * plain scalars rather than re-read from iph later, since bpf_l3/l4_csum_
 * replace (on the skb/TC side) call skb_make_writable internally, which can
 * invalidate PTR_TO_PACKET registers including iph itself.
 */
static __always_inline int revnat_core(__ctx_buff *ctx) {
  void *data = ctx_data(ctx);
  void *data_end = ctx_data_end(ctx);

  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end)
    return CTX_PASS;

  if (eth->h_proto != bpf_htons(ETH_P_IP))
    return CTX_PASS;

  struct iphdr *iph = (void *)(eth + 1);
  if ((void *)(iph + 1) > data_end)
    return CTX_PASS;

  __be32 server_ip = iph->saddr;
  __be32 daddr = iph->daddr;
  __u8 proto = iph->protocol;

  __u8 *kind_ptr = bpf_map_lookup_elem(&dst_kind, &daddr);
  if (!kind_ptr)
    return CTX_PASS;
  __u8 kind = *kind_ptr;

  if (!lookup_target_cidr(server_ip))
    return CTX_PASS;

  if (proto != IPPROTO_TCP && proto != IPPROTO_UDP && proto != IPPROTO_ICMP)
    return CTX_PASS;

  __be16 nat_port, server_port;
  __u32 l4_off = sizeof(struct ethhdr) + sizeof(struct iphdr);
  __u32 csum_off;
  __u8 tcp_syn, tcp_fin, tcp_rst, tcp_ack;

  if (!parse_l4_hdr(data_end, iph, l4_off, proto, &nat_port, &server_port,
                    &csum_off, &tcp_syn, &tcp_fin, &tcp_rst, &tcp_ack))
    return CTX_PASS;

  if (proto == IPPROTO_TCP && tcp_syn && !tcp_ack)
    return CTX_DROP;

  if (kind == DST_KIND_POD_IP) {
    struct nat_map_val *nv = lookup_revnat_entry(ctx, nat_port, server_port);
    if (!nv)
      return CTX_PASS;
    __be16 pod_port = nv->port;
    return do_port_revnat(ctx, server_ip, daddr, server_port, nat_port,
                          pod_port, csum_off, proto, nv, tcp_fin, tcp_rst);
  }

  // DST_KIND_EXT_IP: stage 1 -- resolve pod_ip from the per-protocol port
  // range, rewrite dst, then fall through to stage 2 below.
  __be32 ext_ip = daddr;
  void *inner = lookup_port_range_map(proto, ext_ip);
  if (!inner)
    return CTX_PASS;
  __u32 port_idx = bpf_ntohs(nat_port);
  __be32 *pod_ip_ptr = bpf_map_lookup_elem(inner, &port_idx);
  if (!pod_ip_ptr || !*pod_ip_ptr) // zero = allocated slot, no pod assigned yet
    return CTX_PASS;

  __be32 pod_ip = *pod_ip_ptr;
  iph->daddr = pod_ip; // before the csum helpers below, per the PTR_TO_PACKET note above

  __u32 ip_csum = sizeof(struct ethhdr) + offsetof(struct iphdr, check);
  fixup_ip_change_csum(ctx, proto, ip_csum, csum_off, ext_ip, pod_ip);

  struct nat_map_val *nv = lookup_revnat_entry(ctx, nat_port, server_port);
  if (!nv)
    return ctx_redirect_transit(ctx);
  __be16 pod_port = nv->port;
  return do_port_revnat(ctx, server_ip, pod_ip, server_port, nat_port,
                        pod_port, csum_off, proto, nv, tcp_fin, tcp_rst);
}
