#pragma once

#include "maps.h"

// revnat stage-1 maps. Declared here (rather than directly in the entry
// point .c files) so both the TC and XDP revnat entry points
// (bpf/revnat_ingress.c, bpf/revnat_xdp.c) declare identically-named/typed
// maps -- the loader shares the actual map instances between whichever one
// is attached, and moorctl/internal/maps resolve maps purely by pinned
// path, so they keep working unmodified regardless of the active attach
// mode. Kept out of maps.h (rather than folded in there) so snat_egress.c,
// which never touches these, doesn't end up with unused map definitions in
// its own compiled object.
#define MAX_EXT_IPS 256

struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __uint(max_entries, MAX_EXT_IPS);
  __type(key, struct lpm_key);
  __type(value, __u8);
} ext_ip_pool SEC(".maps");

// inner map indicating port allocation for an ext ip
struct port_range_inner_t {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 65536);
  __type(key, __u32);    // port index
  __type(value, __be32); // pod ip network byte order
} port_range_inner SEC(".maps");

/// per protocol maps lookup pod ip using ext ip and nat port
struct {
  __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
  __uint(max_entries, MAX_EXT_IPS);
  __type(key, __be32); // ext_ip network byte order
  __array(values, struct port_range_inner_t);
} port_range_lookup_tcp SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
  __uint(max_entries, MAX_EXT_IPS);
  __type(key, __be32); // ext_ip network byte order
  __array(values, struct port_range_inner_t);
} port_range_lookup_udp SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
  __uint(max_entries, MAX_EXT_IPS);
  __type(key, __be32); // ext_ip network byte order
  __array(values, struct port_range_inner_t);
} port_range_lookup_icmp SEC(".maps");
