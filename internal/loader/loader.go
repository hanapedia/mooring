package loader

import (
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	mooringbpf "github.com/hanapedia/mooring/internal/bpf"
)

const (
	bpffsRoot = "/sys/fs/bpf/mooring"
	mapsDir   = bpffsRoot + "/maps"
	linksDir  = bpffsRoot + "/links"
)

// Load attaches snat_egress (TC egress) and revnat_ingress (TC ingress) to
// iface via TCX, and pins all maps and links under /sys/fs/bpf/mooring/ so
// that connections and attachments survive daemon restarts.
func Load(iface string) error {
	netIface, err := net.InterfaceByName(iface)
	if err != nil {
		return fmt.Errorf("interface %q: %w", iface, err)
	}

	for _, dir := range []string{mapsDir, linksDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create bpffs dir %s: %w", dir, err)
		}
	}

	// Load snat_egress. Creates nat_table and target_cidrs; revnat shares them.
	snatObjs := &mooringbpf.SnatEgressObjects{}
	if err := mooringbpf.LoadSnatEgressObjects(snatObjs, nil); err != nil {
		return fmt.Errorf("load snat_egress: %w", err)
	}
	defer snatObjs.Close()

	// Load revnat_ingress, injecting the already-created nat_table and
	// target_cidrs so both programs operate on the same maps.
	revnatSpec, err := mooringbpf.LoadRevnatIngress()
	if err != nil {
		return fmt.Errorf("load revnat_ingress spec: %w", err)
	}
	revnatObjs := &mooringbpf.RevnatIngressObjects{}
	if err := revnatSpec.LoadAndAssign(revnatObjs, &ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{
			"nat_table_tcp":  snatObjs.NatTableTcp,
			"nat_table_udp":  snatObjs.NatTableUdp,
			"nat_table_icmp": snatObjs.NatTableIcmp,
			"target_cidrs":   snatObjs.TargetCidrs,
		},
	}); err != nil {
		return fmt.Errorf("load revnat_ingress: %w", err)
	}
	defer revnatObjs.Close()

	// Pin maps. Shared maps (nat_table_*, target_cidrs) are pinned from snatObjs.
	for name, m := range map[string]*ebpf.Map{
		"snat_config":            snatObjs.SnatConfig,
		"nat_table_tcp":          snatObjs.NatTableTcp,
		"nat_table_udp":          snatObjs.NatTableUdp,
		"nat_table_icmp":         snatObjs.NatTableIcmp,
		"outbound_sessions":      snatObjs.OutboundSessions,
		"target_cidrs":           snatObjs.TargetCidrs,
		"ext_ip_pool":            revnatObjs.ExtIpPool,
		"port_range_lookup_tcp":  revnatObjs.PortRangeLookupTcp,
		"port_range_lookup_udp":  revnatObjs.PortRangeLookupUdp,
		"port_range_lookup_icmp": revnatObjs.PortRangeLookupIcmp,
	} {
		if err := m.Pin(filepath.Join(mapsDir, name)); err != nil {
			return fmt.Errorf("pin map %s: %w", name, err)
		}
	}

	// Attach and pin snat_egress → TC egress at head of TCX list so our
	// rewrite runs before Cilium (which attaches at tail).
	egressLink, err := link.AttachTCX(link.TCXOptions{
		Interface: netIface.Index,
		Program:   snatObjs.SnatEgress,
		Attach:    ebpf.AttachTCXEgress,
		Anchor:    link.Head(),
	})
	if err != nil {
		return fmt.Errorf("attach snat_egress: %w", err)
	}
	if err := egressLink.Pin(filepath.Join(linksDir, "snat_egress")); err != nil {
		_ = egressLink.Close()
		return fmt.Errorf("pin snat_egress link: %w", err)
	}
	_ = egressLink.Close()

	// Attach and pin revnat_ingress → TC ingress at head of TCX list.
	ingressLink, err := link.AttachTCX(link.TCXOptions{
		Interface: netIface.Index,
		Program:   revnatObjs.RevnatIngress,
		Attach:    ebpf.AttachTCXIngress,
		Anchor:    link.Head(),
	})
	if err != nil {
		return fmt.Errorf("attach revnat_ingress: %w", err)
	}
	if err := ingressLink.Pin(filepath.Join(linksDir, "revnat_ingress")); err != nil {
		_ = ingressLink.Close()
		return fmt.Errorf("pin revnat_ingress link: %w", err)
	}
	_ = ingressLink.Close()

	return nil
}

// EnsureLoaded loads BPF programs if they are not already pinned.
// If the snat_egress TCX link already exists from a prior run, the load step
// is skipped — existing programs keep running and in-flight connections are
// unaffected.
func EnsureLoaded(iface string) error {
	if _, err := os.Stat(filepath.Join(linksDir, "snat_egress")); err == nil {
		return nil
	}
	return Load(iface)
}

// Unload detaches the TC programs from the uplink and removes all bpffs pins.
func Unload() error {
	for _, name := range []string{"snat_egress", "revnat_ingress"} {
		path := filepath.Join(linksDir, name)
		l, err := link.LoadPinnedLink(path, nil)
		if err != nil {
			// already detached or never loaded — skip
			continue
		}
		if err := l.Close(); err != nil {
			return fmt.Errorf("detach %s: %w", name, err)
		}
	}
	return os.RemoveAll(bpffsRoot)
}
