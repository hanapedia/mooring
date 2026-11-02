// SPDX-License-Identifier: GPL-2.0
#include "maps.h"
#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

char __license[] SEC("license") = "GPL";

// Reported back to userspace (internal/gc) via BPF_PROG_TEST_RUN's ctx_in/
// ctx_out -- cilium/ebpf's Program.Run reuses the same buffer for both on a
// SEC("syscall") program, so whatever these fields hold when the program
// returns is exactly what RunOptions.ContextOut decodes.
struct gc_ctx {
  __u64 scanned;
  __u64 deleted;
  __u64 remaining;
};

// The peer entry's key for a nat_map_tcp entry: same ip_a/ip_b + port_a/
// port_b swap and kind flip nat_map_track_tcp_close (maps.h) already uses
// to find a TCP flow's other half, reimplemented here because that helper
// takes the five scalars its own callers already have decomposed, not a
// struct nat_map_key it could hand back.
static struct nat_map_key tcp_peer_key(struct nat_map_key *key) {
  struct nat_map_key peer = {
      .ip_a = key->ip_b,
      .ip_b = key->ip_a,
      .port_a = key->port_b,
      .port_b = key->port_a,
      .proto = key->proto,
      .kind = key->kind == NAT_ENTRY_SNAT ? NAT_ENTRY_REVNAT : NAT_ENTRY_SNAT,
  };
  return peer;
}

// bpf_for_each_map_elem callback for nat_map_tcp: proactively applies the
// same NAT_CLOSING_STALE_NS rescue try_alloc_port (snat_egress.c) already
// does lazily on a colliding allocation, so a half-closed connection is
// reclaimed on a timer instead of only when something happens to collide
// with it. Deletes both this entry and its peer; whichever of the two a
// sweep happens to visit first deletes both, so the peer delete missing on
// the other's turn is expected, not an error.
static long tcp_gc_cb(struct bpf_map *map, void *key, void *value, void *ctx) {
  struct gc_ctx *gc = ctx;
  struct nat_map_val *val = value;
  struct nat_map_key *k = key;

  gc->scanned++;

  if (val->closing_ns &&
      bpf_ktime_get_ns() - val->closing_ns > NAT_CLOSING_STALE_NS) {
    struct nat_map_key peer = tcp_peer_key(k);
    bpf_map_delete_elem(map, &peer);
    bpf_map_delete_elem(map, key);
    gc->deleted++;
    return 0;
  }

  gc->remaining++;
  return 0;
}

SEC("syscall")
int gc_nat_map_tcp(void *ctx) {
  // bpf_for_each_map_elem's callback_ctx argument must live on this
  // program's own stack (the verifier rejects a pointer straight into ctx,
  // a SEC("syscall") program's externally-provided buffer, with "R3
  // type=ctx expected=fp") -- so accumulate into a local struct and copy
  // the result into ctx only once the sweep is done.
  struct gc_ctx gc = {};
  bpf_for_each_map_elem(&nat_map_tcp, tcp_gc_cb, &gc, 0);
  *(struct gc_ctx *)ctx = gc;
  return 0;
}

// bpf_for_each_map_elem callback for nat_map_any (UDP/ICMP): generational
// mark/sweep. An entry still marked stale from the previous sweep (so
// untouched for a full GC period) is deleted; otherwise it's marked stale
// now, due for deletion next sweep unless the datapath clears it first
// (snat_egress.c's reuse branch, revnat_core.h's do_port_revnat). No
// peer-delete: each side's own staleness is tracked independently, same
// asymmetric design as nat_map_track_tcp_close -- an orphaned peer just
// costs one extra collision probe (try_alloc_port) until its own entry's
// own next sweep deletes it too.
static long any_gc_cb(struct bpf_map *map, void *key, void *value, void *ctx) {
  struct gc_ctx *gc = ctx;
  struct nat_map_val *val = value;

  gc->scanned++;

  if (val->stale) {
    bpf_map_delete_elem(map, key);
    gc->deleted++;
    return 0;
  }

  val->stale = 1;
  gc->remaining++;
  return 0;
}

SEC("syscall")
int gc_nat_map_any(void *ctx) {
  // See gc_nat_map_tcp above for why this can't accumulate directly into ctx.
  struct gc_ctx gc = {};
  bpf_for_each_map_elem(&nat_map_any, any_gc_cb, &gc, 0);
  *(struct gc_ctx *)ctx = gc;
  return 0;
}
