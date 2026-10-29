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

// dst_kind classifies an ingress packet's destination IP in a single exact
// (hash, not LPM) lookup: is it one of our external IPs (stage 1 candidate),
// one of this node's local client pod IPs (stage 2 candidate), or neither
// (not meant for mooring at all -- e.g. another system, such as coil's
// Egress feature, sharing the same target CIDR as a mooring NATConfig). A
// miss is the authoritative "not ours" answer; revnat_core relies on it to
// avoid treating unrelated traffic as an already-stage1'd mooring flow.
//
// DST_KIND_EXT_IP entries are written cluster-wide (every node), because
// stage 1 can run on any node via BGP ECMP. DST_KIND_POD_IP entries are
// written local-node-only (stage 2 only ever completes on the pod's own
// node, same as nat_map/nat_config), with their lifecycle driven entirely by
// the control plane (NATPortRangeSyncReconciler) -- never by the datapath --
// so the map never needs LRU eviction or staleness handling.
#define DST_KIND_EXT_IP 1
#define DST_KIND_POD_IP 2

// Still used below to size port_range_lookup_*'s outer HASH_OF_MAPS -- those
// remain keyed on individual ext IPs regardless of dst_kind.
#define MAX_EXT_IPS 256

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 8192); // expanded ext IPs + local client pod IPs
  __type(key, __be32);       // dst_ip, network byte order
  __type(value, __u8);       // DST_KIND_EXT_IP or DST_KIND_POD_IP
} dst_kind SEC(".maps");

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

// Key for pod_nat_ports below. port is host byte order, matching
// port_range_inner's key convention (bpf_ntohs(nat_port)).
struct pod_port_key {
  __be32 pod_ip;
  __u16 port;
};

// Answers "is port P inside this client pod's own allocated NAT block(s)?"
// -- independent of protocol, since AddPortRange registers a pod's block
// identically across all three port_range_lookup_* maps (block membership
// isn't itself protocol-specific). Used only by revnat_core.h's
// DST_KIND_POD_IP branch, to scope its nat_map-miss drop to a pod's own
// managed range: anything outside it (e.g. a Service's real listening
// port, reached via a load balancer's DSR dispatch) was never mooring's
// concern and is left to pass through untouched.
//
// A plain HASH, not HASH_OF_MAPS + a 65536-slot ARRAY per pod like
// port_range_lookup_* -- this scales with the number of ports actually
// allocated across all local client pods, not a fixed per-pod reservation,
// which matters once there are many client pods on one node.
// BPF_F_NO_PREALLOC keeps that scaling real rather than eagerly committing
// max_entries worth of memory upfront.
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __uint(max_entries, 131072);
  __type(key, struct pod_port_key);
  __type(value, __u8); // existence is the signal; value is unused
} pod_nat_ports SEC(".maps");
