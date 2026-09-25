// SPDX-License-Identifier: GPL-2.0
#include "ctx/skb.h"
#include "revnat_core.h"

char __license[] SEC("license") = "GPL";

SEC("tcx/ingress")
int revnat_ingress(struct __sk_buff *skb) {
  return revnat_core(skb);
}
