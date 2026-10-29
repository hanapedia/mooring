// SPDX-License-Identifier: GPL-2.0
#include "ctx/skb.h"
#include "l4.h"
#include "maps.h"
#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

char __license[] SEC("license") = "GPL";

// Egress-direction L4 parse: resolves straight to pod_port/server_port (the
// header's source-side field / icmp id vs. its dest-side field) and filters
// out anything but ICMP_ECHO -- snat_egress only ever sees requests
// travelling pod -> server. Mirrors revnat_core.h's parse_l4_hdr (ingress
// direction: dest-side -> nat_port), see that file's copy for why the
// ICMP-id/direction mapping isn't itself shared in l4.h. tcp_syn/fin/rst/ack
// are only meaningful when proto == IPPROTO_TCP. Returns 0 on a bounds-check
// miss or the ICMP-type filter.
static __always_inline int
parse_l4_hdr_snat(void *data_end, struct iphdr *iph, __u32 l4_off, __u8 proto,
                  __be16 *pod_port, __be16 *server_port, __u32 *csum_off,
                  __u8 *tcp_syn, __u8 *tcp_fin, __u8 *tcp_rst, __u8 *tcp_ack) {
  struct l4_raw raw = {};
  if (!parse_l4_raw(data_end, iph, l4_off, proto, &raw))
    return 0;

  if (proto == IPPROTO_ICMP) {
    if (raw.icmp_type != ICMP_ECHO)
      return 0;
    *pod_port = raw.icmp_id;
    *server_port = 0;
  } else {
    *pod_port = raw.src_port;
    *server_port = raw.dst_port;
  }
  *csum_off = raw.csum_off;
  *tcp_syn = raw.tcp_syn;
  *tcp_fin = raw.tcp_fin;
  *tcp_rst = raw.tcp_rst;
  *tcp_ack = raw.tcp_ack;
  return 1;
}

/// Map key and value types defs
struct port_range_alloc {
  __be32 ext_ip;
  __u16 port_start;
  __u16 port_end;
};

#define MAX_PORT_RANGE_ALLOCS 256

struct nat_config_val {
  struct port_range_alloc port_range_allocs[MAX_PORT_RANGE_ALLOCS];
  __u32 count;
};

// Key for nat_config: pod_ip combined with the matched target CIDR so that a
// pod matching multiple NATConfigs gets independent nat_config entries — one
// per target CIDR — each with its own ext-IP pool and port counters.
struct nat_config_key {
  __be32 pod_ip;
  __be32 cidr_addr;
  __u32 cidr_prefixlen;
};

// Max probes (random pick + linear walk) tried within a single
// port_range_alloc's port range before giving up on it and moving to another
// allocation.
#define MAX_PORT_ATTEMPTS 8

// Max independent (with-replacement) allocation entries sampled per packet
// before giving up entirely. Deliberately NOT a scan of every entry up to
// MAX_PORT_RANGE_ALLOCS: a 256-iteration outer loop wrapping the port-probe
// loop above is enough nested branching (map lookups + conditionals per inner
// iteration) to blow the kernel verifier's fixed 1,000,000-instruction
// processing budget — confirmed by an actual load failure ("BPF program is
// too large. Processed 1000001 insn"). A handful of samples is enough in
// practice: with only one allocation, repeated draws just land on it again
// and its own per-attempt port-seed still explores fresh ports each time (see
// try_alloc_port's seed_offset); with several, a small number of independent
// draws is very likely to land on one with room whenever any exist. The
// tradeoff is that allocation is no longer exhaustive — a pod whose block is
// nearly full can occasionally fail to find a free port that technically
// exists in an entry that was never sampled.
#define MAX_ENTRY_ATTEMPTS 8

// How long an entry marked closing (see nat_map_val's closing_ns comment in
// maps.h) can sit unconfirmed before a colliding allocation may reclaim it.
// Covers unclean ends (crash, dropped FIN/RST) that close-tracking never
// gets to confirm. TCP only — UDP/ICMP never set closing_ns.
#define NAT_CLOSING_STALE_NS (10ULL * 1000000000ULL)

/// Map defs
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __uint(max_entries, 4096);
  __type(key, struct nat_config_key);
  __type(value, struct nat_config_val);
} nat_config SEC(".maps");

// Fixed-point projection of a 16-bit seed onto the closed interval
// [start, end], used in place of a modulo (which needs a helper call for
// entropy plus a divide by a non-constant divisor) to pick a starting port.
// Same technique Cilium's bpf_nat.h uses for SNAT port selection. n is
// computed in 32 bits so the closed interval [0, 65535] doesn't wrap to 0.
static __always_inline __u16 clamp_to_range(__u16 start, __u16 end, __u16 val) {
  __u32 n = (__u32)(end - start) + 1;
  __u32 m = (__u32)val * n;
  return start + (__u16)(m >> 16);
}

// Tries to allocate a port out of a single port_range_alloc: a starting port
// derived deterministically from the connection's own pod-side port (no
// bpf_get_prandom_u32 call, no modulo), then up to MAX_PORT_ATTEMPTS linear
// steps on collision. A "collision" is an existing revnat entry in nat_map
// for that exact (server-IP, server-port, pod-IP, candidate-port) tuple.
// ICMP skips collision checking entirely and always overwrites (echo id
// collisions are cheap/self-correcting and short-lived). For TCP, a collision
// against an entry marked closing for longer than NAT_CLOSING_STALE_NS is
// treated as free and reclaimed (the stale flow's snat entry is deleted too
// -- its revnat entry gets overwritten naturally once this allocation
// succeeds and writes to the same key).
//
// seed_offset lets the caller vary the starting point across independent
// entry-attempts even when a with-replacement resample lands on this same
// entry again — otherwise a repeat visit would recompute the identical
// starting port and walk the identical (already-failed) sequence.
static __always_inline int try_alloc_port(struct port_range_alloc *e,
                                          __be32 pod_ip, __be32 server_ip,
                                          __be16 server_port, __be16 pod_port,
                                          __u32 seed_offset, __u8 proto,
                                          __be16 *out_port) {
  __u16 seed = bpf_ntohs(pod_port) + (__u16)seed_offset;
  __u16 port = clamp_to_range(e->port_start, e->port_end, seed);

  if (proto == IPPROTO_ICMP) {
    *out_port = bpf_htons(port);
    return 1;
  }

  for (__u32 attempt = 0; attempt < MAX_PORT_ATTEMPTS; attempt++) {
    __be16 candidate = bpf_htons(port);
    struct nat_map_val *existing =
        nat_map_lookup_revnat(server_ip, pod_ip, server_port, candidate, proto);
    if (!existing) {
      *out_port = candidate;
      return 1;
    }
    if (proto == IPPROTO_TCP && existing->closing_ns &&
        bpf_ktime_get_ns() - existing->closing_ns > NAT_CLOSING_STALE_NS) {
      // existing->port is the stale flow's pod_port
      nat_map_delete_snat(pod_ip, server_ip, existing->port, server_port,
                          proto);
      *out_port = candidate;
      return 1;
    }
    port = (port == e->port_end) ? e->port_start : port + 1;
  }
  return 0;
}

// Samples up to MAX_ENTRY_ATTEMPTS port_range_alloc slots (independently, with
// replacement, via the same seed-projection technique as try_alloc_port) and
// tries each in turn, stopping at the first success. The loop bound is a
// small compile-time constant unrelated to cv->count or MAX_PORT_RANGE_ALLOCS,
// which is what keeps this verifier-cheap regardless of how many allocations
// a pod actually has — see the comment on MAX_ENTRY_ATTEMPTS for why an
// exhaustive scan of every entry was rejected.
//
// idx is picked by the same clamp_to_range projection as try_alloc_port's
// port selection, just onto [0, count-1] -- chosen over
// "bpf_get_prandom_u32() % count" for the same reasons, and this multiply +
// constant-shift shape additionally lets the verifier's own range tracking
// prove idx < count directly, with no compiler-barrier workaround needed.
// attempt is passed through to try_alloc_port as seed_offset so a
// with-replacement resample of the same entry doesn't retry the exact same
// (already-failed) port sequence.
static __always_inline int
allocate_snat_port(struct nat_config_val *cv, __be32 pod_ip, __be32 server_ip,
                   __be16 server_port, __be16 pod_port, __u8 proto,
                   __be16 *out_port, __be32 *out_ext_ip) {
  __u32 count = cv->count;
  if (count > MAX_PORT_RANGE_ALLOCS)
    count = MAX_PORT_RANGE_ALLOCS;

  for (__u32 attempt = 0; attempt < MAX_ENTRY_ATTEMPTS; attempt++) {
    __u16 seed = bpf_ntohs(pod_port) + (__u16)attempt;
    __u32 idx = clamp_to_range(0, (__u16)(count - 1), seed);
    struct port_range_alloc *e = &cv->port_range_allocs[idx];
    if (try_alloc_port(e, pod_ip, server_ip, server_port, pod_port, attempt,
                       proto, out_port)) {
      *out_ext_ip = e->ext_ip;
      return 1;
    }
  }
  return 0;
}

// Looks up (or allocates) an ext_ip:nat_port for the current flow, rewrites
// src IP/port to it, and fixes up checksums -- the pod->server mirror of
// revnat_core's stage 2. iph->saddr/daddr are captured as pod_ip/server_ip
// scalars up front, and the header/port rewrite happens before the csum
// helpers below, for the same PTR_TO_PACKET-invalidation reason documented
// on revnat_core.
SEC("tcx/egress")
int snat_egress(struct __sk_buff *skb) {
  void *data = ctx_data(skb);
  void *data_end = ctx_data_end(skb);

  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end)
    return CTX_PASS;

  if (eth->h_proto != bpf_htons(ETH_P_IP))
    return CTX_PASS;

  struct iphdr *iph = (void *)(eth + 1);
  if ((void *)(iph + 1) > data_end)
    return CTX_PASS;

  __u8 proto = iph->protocol;
  if (proto != IPPROTO_TCP && proto != IPPROTO_UDP && proto != IPPROTO_ICMP)
    return CTX_PASS;

  struct target_cidr_val *tcv = lookup_target_cidr(iph->daddr);
  if (!tcv)
    return CTX_PASS;

  if (ip_header_unparseable(iph))
    return CTX_DROP;

  __be32 pod_ip = iph->saddr;
  __be32 server_ip = iph->daddr;

  __be16 pod_port, server_port;
  __u32 l4_off = sizeof(struct ethhdr) + ip_hdr_len(iph);
  __u32 csum_off;
  __u8 tcp_syn, tcp_fin, tcp_rst, tcp_ack;

  if (!parse_l4_hdr_snat(data_end, iph, l4_off, proto, &pod_port, &server_port,
                         &csum_off, &tcp_syn, &tcp_fin, &tcp_rst, &tcp_ack))
    return CTX_PASS;

  struct nat_map_val *sv =
      nat_map_lookup_snat(pod_ip, server_ip, pod_port, server_port, proto);

  __be32 ext_ip = 0;
  __be16 nat_port = 0;
  if (sv) {
    // existing connection — reuse the allocated port
    ext_ip = sv->nat_ip;
    nat_port = sv->port;

    if (proto == IPPROTO_TCP)
      nat_map_track_tcp_close(server_ip, pod_ip, server_port, nat_port,
                              pod_port, sv, NAT_ENTRY_SNAT, tcp_fin, tcp_rst);
  } else {
    // A TCP flow with no existing snat entry must be the pod's own pure
    // SYN -- anything else wasn't initiated by this pod (most likely its
    // kernel replying to an unsolicited packet let in by revnat_core's
    // redirect-on-miss). Drop rather than allocate or pass un-NATed, so it
    // can't seed a bogus entry or leak the pod's real IP via iph->saddr.
    if (proto == IPPROTO_TCP && !(tcp_syn && !tcp_ack))
      return CTX_DROP;

    // the matched target CIDR picks which NATConfig's ext-IP pool to
    // allocate from (a pod matching several NATConfigs gets independent
    // pools per destination)
    struct nat_config_key nc_key = {
        .pod_ip = pod_ip,
        .cidr_addr = tcv->addr,
        .cidr_prefixlen = tcv->prefixlen,
    };
    struct nat_config_val *cv = bpf_map_lookup_elem(&nat_config, &nc_key);
    if (!cv || cv->count == 0)
      return CTX_PASS;

    allocate_snat_port(cv, pod_ip, server_ip, server_port, pod_port, proto,
                       &nat_port, &ext_ip);
    if (!ext_ip)
      return CTX_PASS; // every allocation exhausted

    __u64 closing_ns = 0;
    if (proto == IPPROTO_TCP && (tcp_fin || tcp_rst))
      closing_ns = bpf_ktime_get_ns();

    nat_map_update_snat(pod_ip, server_ip, pod_port, server_port, proto, ext_ip,
                        nat_port, closing_ns);
    nat_map_update_revnat(server_ip, pod_ip, server_port, nat_port, proto,
                          ext_ip, pod_port, closing_ns);
  }

  iph->saddr = ext_ip;
  if (!write_l4_src_port(data_end, iph, proto, nat_port))
    return CTX_PASS;

  __u32 ip_csum = sizeof(struct ethhdr) + offsetof(struct iphdr, check);
  fixup_ip_change_csum(skb, proto, ip_csum, csum_off, pod_ip, ext_ip);
  ctx_l4_csum_replace_port(skb, csum_off, pod_port, nat_port);

  return CTX_PASS;
}
