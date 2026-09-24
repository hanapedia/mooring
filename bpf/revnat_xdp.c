// SPDX-License-Identifier: GPL-2.0
#include "ctx/xdp.h"
#include "revnat_core.h"

char __license[] SEC("license") = "GPL";

SEC("xdp")
int revnat_xdp(struct xdp_md *xdp) {
  return revnat_core(xdp);
}
