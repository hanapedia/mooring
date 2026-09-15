# Cilium Compatibility

Mooring attaches its BPF programs at **TCX head** on the node's uplink interface, returning `TCX_NEXT` instead of `TC_ACT_OK` so the packet continues down the TCX chain. This allows Cilium to attach its own programs at the tail of the same chain without conflict.

## Compatibility Matrix

| Cilium Feature | Cilium 1.17 |
|---|---|
| kube-proxy replacement | ✓ |
| Native routing (`routingMode: native`) | ✓ |
| BPF host routing (`bpf.hostLegacyRouting: false`) | ✓ |
| BGP Control Plane | ✓ |

## Attachment Order

Mooring programs are inserted at TCX head, so they run **before** Cilium's programs on the same interface. The output below from a worker node confirms the ordering — `revnat_ingress`/`snat_egress` appear ahead of `cil_from_netdev`/`cil_to_netdev` on `node0`:

```
$ sudo nsenter -t $(docker inspect -f '{{.State.Pid}}' clab-kind-with-bgp-worker) -n bpftool net show
xdp:

tc:
cilium_net(3) tcx/ingress cil_to_host prog_id 31102 link_id 566
cilium_host(4) tcx/ingress cil_to_host prog_id 31091 link_id 564
cilium_host(4) tcx/egress cil_from_host prog_id 31084 link_id 565
lxc_health(6) tcx/ingress cil_from_container prog_id 31118 link_id 585
lxc340c91ee612d(8) tcx/ingress cil_from_container prog_id 31200 link_id 594
lxccdb072618a0b(10) tcx/ingress cil_from_container prog_id 31202 link_id 593
lxc0bf1c1c814bc(12) tcx/ingress cil_from_container prog_id 31225 link_id 595
node0(1691) tcx/ingress revnat_ingress prog_id 31356 link_id 600
node0(1691) tcx/ingress cil_from_netdev prog_id 31108 link_id 567
node0(1691) tcx/egress snat_egress prog_id 31354 link_id 598
node0(1691) tcx/egress cil_to_netdev prog_id 31115 link_id 568

flow_dissector:

netfilter:
```

`link_id 600` (revnat_ingress) < `link_id 567` (cil_from_netdev) on ingress, and `link_id 598` (snat_egress) < `link_id 568` (cil_to_netdev) on egress, confirming mooring runs first.

## Steps to Reproduce

```bash
cd e2e_v2
task start-cilium
task e2e-domestic1-test
```

`start-cilium` builds a containerlab topology with a BGP-peered ToR switch, deploys a kind cluster with kube-proxy disabled, installs Cilium with native routing and BGP Control Plane enabled, then installs mooring. `e2e-domestic1-test` sends traffic from a pod through the SNAT path to an external host at `192.168.10.100:8000` and verifies connectivity.
