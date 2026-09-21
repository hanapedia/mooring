// SPDX-License-Identifier: GPL-2.0
#include "maps.h"
#include "tc.h"
#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

char __license[] SEC("license") = "GPL";

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

// How long an entry must have been marked "closing" (FIN/RST seen, no
// confirming second FIN/RST yet) before it is eligible to be reclaimed by a
// colliding allocation. Covers unclean ends (crash, dropped FIN/RST) that the
// active connection-tracking below never gets to confirm. TCP only — UDP/ICMP
// entries never set closing_ns, so they are never reclaimed this way.
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
// Same technique Cilium's bpf_nat.h uses for SNAT port selection.
static __always_inline __u16 clamp_to_range(__u16 start, __u16 end, __u16 val) {
  __u32 n = (__u32)(end - start) + 1; // closed interval; computed in 32 bits
                                      // so [0, 65535] doesn't wrap to 0
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
    struct nat_map_key revnat_key = {
        .ip_a = server_ip,
        .ip_b = pod_ip,
        .port_a = server_port,
        .port_b = candidate,
        .proto = proto,
        .kind = NAT_ENTRY_REVNAT,
    };
    struct nat_map_val *existing = bpf_map_lookup_elem(&nat_map, &revnat_key);
    if (!existing) {
      *out_port = candidate;
      return 1;
    }
    if (proto == IPPROTO_TCP && existing->closing_ns &&
        bpf_ktime_get_ns() - existing->closing_ns > NAT_CLOSING_STALE_NS) {
      struct nat_map_key old_snat_key = {
          .ip_a = pod_ip,
          .ip_b = server_ip,
          .port_a = existing->port, // the stale flow's pod_port
          .port_b = server_port,
          .proto = proto,
          .kind = NAT_ENTRY_SNAT,
      };
      bpf_map_delete_elem(&nat_map, &old_snat_key);
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
static __always_inline int
allocate_snat_port(struct nat_config_val *cv, __be32 pod_ip, __be32 server_ip,
                   __be16 server_port, __be16 pod_port, __u8 proto,
                   __be16 *out_port, __be32 *out_ext_ip) {
  __u32 count = cv->count;
  if (count > MAX_PORT_RANGE_ALLOCS)
    count = MAX_PORT_RANGE_ALLOCS;

  for (__u32 attempt = 0; attempt < MAX_ENTRY_ATTEMPTS; attempt++) {
    // Same fixed-point projection as clamp_to_range, just onto
    // [0, count-1] instead of [port_start, port_end] (that's clamp_to_range
    // with start=0). Chosen over "bpf_get_prandom_u32() % count" for the same
    // reasons as port selection -- and unlike that modulo, this multiply +
    // constant-shift shape lets the verifier's own range tracking prove
    // idx < count directly, with no compiler-barrier workaround needed.
    __u16 seed = bpf_ntohs(pod_port) + (__u16)attempt;
    __u32 idx = clamp_to_range(0, (__u16)(count - 1), seed);
    struct port_range_alloc *e = &cv->port_range_allocs[idx];
    // attempt as seed_offset: keeps a with-replacement resample of the same
    // entry from retrying the exact same (already-failed) port sequence.
    if (try_alloc_port(e, pod_ip, server_ip, server_port, pod_port, attempt,
                       proto, out_port)) {
      *out_ext_ip = e->ext_ip;
      return 1;
    }
  }
  return 0;
}

/// entrypoint for snat_egress
SEC("tcx/egress")
int snat_egress(struct __sk_buff *skb) {
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;

  // parse ethernet header
  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end)
    return TCX_NEXT;

  if (eth->h_proto != bpf_htons(ETH_P_IP))
    return TCX_NEXT;

  // parse IP header
  struct iphdr *iph = (void *)(eth + 1);
  if ((void *)(iph + 1) > data_end)
    return TCX_NEXT;

  // handle only tcp, udp, and icmp
  if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP &&
      iph->protocol != IPPROTO_ICMP)
    return TCX_NEXT;

  // look up dest against target cidrs; value carries the matched CIDR identity
  struct lpm_key lpm = {
      .prefixlen = 32, /* match dest IP exactly */
      .addr = iph->daddr,
  };
  struct target_cidr_val *tcv = bpf_map_lookup_elem(&target_cidrs, &lpm);
  if (!tcv)
    return TCX_NEXT;

  // look up snat config keyed by (pod_ip, matched_target_cidr) so that a pod
  // matched by multiple NATConfigs uses the correct ext-IP pool per destination
  __be32 pod_ip = iph->saddr;
  __be32 server_ip = iph->daddr;
  // parse l4 header
  __be16 pod_port, server_port;
  __u32 l4_off = sizeof(struct ethhdr) + sizeof(struct iphdr);
  __u32 csum_off;
  __u8 tcp_fin = 0, tcp_rst = 0, tcp_ack = 0;

  if (iph->protocol == IPPROTO_TCP) {
    struct tcphdr *tcph = (void *)iph + sizeof(struct iphdr);
    if ((void *)(tcph + 1) > data_end)
      return TCX_NEXT;
    pod_port = tcph->source;
    server_port = tcph->dest;
    csum_off = l4_off + offsetof(struct tcphdr, check);
    tcp_fin = tcph->fin;
    tcp_rst = tcph->rst;
    tcp_ack = tcph->ack;
  } else if (iph->protocol == IPPROTO_UDP) {
    struct udphdr *udph = (void *)iph + sizeof(struct iphdr);
    if ((void *)(udph + 1) > data_end)
      return TCX_NEXT;
    pod_port = udph->source;
    server_port = udph->dest;
    csum_off = l4_off + offsetof(struct udphdr, check);
  } else { // ICMP (use port as id)
    struct icmphdr *icmph = (void *)iph + sizeof(struct iphdr);
    if ((void *)(icmph + 1) > data_end)
      return TCX_NEXT;
    // handle only echo for now
    if (icmph->type != ICMP_ECHO)
      return TCX_NEXT;
    pod_port = icmph->un.echo.id;
    server_port = 0;
    csum_off = l4_off + offsetof(struct icmphdr, checksum);
  }

  // look up existing connection before allocating a new port
  struct nat_map_key snat_key = {
      .ip_a = pod_ip,
      .ip_b = server_ip,
      .port_a = pod_port,
      .port_b = server_port,
      .proto = iph->protocol,
      .kind = NAT_ENTRY_SNAT,
  };
  struct nat_map_val *sv = bpf_map_lookup_elem(&nat_map, &snat_key);

  __be32 ext_ip = 0;
  __be16 nat_port = 0;
  if (sv) {
    // existing connection — reuse the allocated port
    ext_ip = sv->nat_ip;
    nat_port = sv->port;

    if (iph->protocol == IPPROTO_TCP) {
      struct nat_map_key revnat_key = {
          .ip_a = server_ip,
          .ip_b = pod_ip,
          .port_a = server_port,
          .port_b = sv->port,
          .proto = IPPROTO_TCP,
          .kind = NAT_ENTRY_REVNAT,
      };
      if (sv->closing_ns) {
        // A second terminating segment confirms the close. Deliberately not
        // just "tcp_ack" — a plain ACK also covers the common half-closed
        // case (this side FIN'd, the other still sending data before its own
        // FIN), and deleting on that would strand the still-open half onto a
        // fresh, different port mid-flow.
        if ((tcp_fin || tcp_rst) && tcp_ack) {
          bpf_map_delete_elem(&nat_map, &revnat_key);
          bpf_map_delete_elem(&nat_map, &snat_key);
        }
      } else if (tcp_fin || tcp_rst) {
        __u64 now = bpf_ktime_get_ns();
        struct nat_map_val *rv = bpf_map_lookup_elem(&nat_map, &revnat_key);
        if (rv)
          rv->closing_ns = now;
        sv->closing_ns = now;
      }
    }
  } else {
    struct nat_config_key nc_key = {
        .pod_ip = pod_ip,
        .cidr_addr = tcv->addr,
        .cidr_prefixlen = tcv->prefixlen,
    };
    struct nat_config_val *cv = bpf_map_lookup_elem(&nat_config, &nc_key);
    if (!cv || cv->count == 0) // no snat config found
      return TCX_NEXT;

    allocate_snat_port(cv, pod_ip, server_ip, server_port, pod_port,
                       iph->protocol, &nat_port, &ext_ip);

    if (!ext_ip)
      return TCX_NEXT; // every allocation exhausted

    __u64 closing_ns = 0;
    if (iph->protocol == IPPROTO_TCP && (tcp_fin || tcp_rst))
      closing_ns = bpf_ktime_get_ns();

    struct nat_map_val snat_val = {
        .nat_ip = ext_ip, .port = nat_port, .closing_ns = closing_ns};
    bpf_map_update_elem(&nat_map, &snat_key, &snat_val, BPF_ANY);

    struct nat_map_key revnat_key = {
        .ip_a = server_ip,
        .ip_b = pod_ip,
        .port_a = server_port,
        .port_b = nat_port,
        .proto = iph->protocol,
        .kind = NAT_ENTRY_REVNAT,
    };
    struct nat_map_val revnat_val = {
        .nat_ip = ext_ip, .port = pod_port, .closing_ns = closing_ns};
    bpf_map_update_elem(&nat_map, &revnat_key, &revnat_val, BPF_ANY);
  }

  // rewrite headers before csum helpers: bpf_l3/l4_csum_replace call
  // skb_make_writable internally, which can reallocate the skb and causes the
  // verifier to invalidate all PTR_TO_PACKET registers. Do direct writes first.
  iph->saddr = ext_ip;
  if (iph->protocol == IPPROTO_TCP) {
    struct tcphdr *tcph = (void *)iph + sizeof(struct iphdr);
    if ((void *)(tcph + 1) > data_end)
      return TCX_NEXT;
    tcph->source = nat_port;
  } else if (iph->protocol == IPPROTO_UDP) {
    struct udphdr *udph = (void *)iph + sizeof(struct iphdr);
    if ((void *)(udph + 1) > data_end)
      return TCX_NEXT;
    udph->source = nat_port;
  } else { // ICMP (uses port as id)
    struct icmphdr *icmph = (void *)iph + sizeof(struct iphdr);
    if ((void *)(icmph + 1) > data_end)
      return TCX_NEXT;
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

  return TCX_NEXT;
}
