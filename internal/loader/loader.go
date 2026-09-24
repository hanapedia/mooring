package loader

import (
	"fmt"
	"log"
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

// AttachMode selects which hook revnat's stage1/stage2 rewrite runs on.
// snat_egress always runs on TC egress regardless of mode -- XDP is an
// RX-only hook, so there is no XDP equivalent for the egress/SNAT leg.
type AttachMode string

const (
	AttachModeTCX AttachMode = "tcx"
	AttachModeXDP AttachMode = "xdp"
)

// linkName is the bpffs pin name revnat's link is stored under for this
// mode. The two names double as the mutual-exclusivity check in Load: at
// most one of them is ever pinned at a time.
func (m AttachMode) linkName() string {
	if m == AttachModeXDP {
		return "revnat_xdp"
	}
	return "revnat_ingress"
}

func (m AttachMode) other() AttachMode {
	if m == AttachModeXDP {
		return AttachModeTCX
	}
	return AttachModeXDP
}

func validateMode(mode AttachMode) error {
	if mode != AttachModeTCX && mode != AttachModeXDP {
		return fmt.Errorf("invalid attach mode %q (must be %q or %q)", mode, AttachModeTCX, AttachModeXDP)
	}
	return nil
}

// Load attaches snat_egress (always TC egress) and revnat (TC ingress or
// XDP, depending on mode) to iface, and pins all maps and links under
// /sys/fs/bpf/mooring/ so that connections and attachments survive daemon
// restarts.
//
// revnat_ingress (TCX) and revnat_xdp are mutually exclusive: at most one is
// ever attached to a given interface. If the other mode's link is already
// pinned, Load fails rather than attaching both -- running both would
// double-process every packet (the second pass would see an
// already-rewritten packet -- dest already the pod IP, dest port already
// the pod port -- and misroute it, since e.g. stage2's nat_map lookup would
// be keyed off the already-rewritten port).
func Load(iface string, mode AttachMode) (err error) {
	if err = validateMode(mode); err != nil {
		return err
	}

	netIface, ifErr := net.InterfaceByName(iface)
	if ifErr != nil {
		return fmt.Errorf("interface %q: %w", iface, ifErr)
	}

	for _, dir := range []string{mapsDir, linksDir} {
		if mkErr := os.MkdirAll(dir, 0o700); mkErr != nil {
			return fmt.Errorf("create bpffs dir %s: %w", dir, mkErr)
		}
	}

	if _, statErr := os.Stat(filepath.Join(linksDir, mode.other().linkName())); statErr == nil {
		return fmt.Errorf("revnat is already attached in %q mode; run `moorctl unload` before switching to %q",
			mode.other(), mode)
	}

	// From this point on, any failure below would otherwise leave this
	// attempt's own partial bpffs pins behind (e.g. nat_map pinned but the
	// revnat link never attached) for the next Load/EnsureLoaded call to
	// collide with -- surfacing as a confusing "pin map nat_config: file
	// exists" on retry instead of the real underlying error, and getting
	// worse on every subsequent crash-loop restart. Roll back fully on error
	// so a retry always starts from a clean slate. Safe to unconditionally
	// Unload() here specifically because the mutual-exclusivity check above
	// already confirmed nothing valid in the *other* mode exists to disturb.
	defer func() {
		if err != nil {
			_ = Unload()
		}
	}()

	// Load snat_egress. Creates nat_map and target_cidrs; revnat shares them.
	snatObjs := &mooringbpf.SnatEgressObjects{}
	if err := mooringbpf.LoadSnatEgressObjects(snatObjs, nil); err != nil {
		return fmt.Errorf("load snat_egress: %w", err)
	}
	defer snatObjs.Close()

	// Pin maps owned by snat_egress up front so revnat's MapReplacements
	// below (and moorctl/internal/maps, which resolve everything by pinned
	// path) have somewhere to find them regardless of which revnat mode
	// loads next.
	for name, m := range map[string]*ebpf.Map{
		"nat_config":   snatObjs.NatConfig,
		"nat_map":      snatObjs.NatMap,
		"target_cidrs": snatObjs.TargetCidrs,
	} {
		if err := m.Pin(filepath.Join(mapsDir, name)); err != nil {
			return fmt.Errorf("pin map %s: %w", name, err)
		}
	}

	revnatMapReplacements := map[string]*ebpf.Map{
		"nat_map":      snatObjs.NatMap,
		"target_cidrs": snatObjs.TargetCidrs,
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

	switch mode {
	case AttachModeXDP:
		return loadRevnatXDP(netIface.Index, revnatMapReplacements)
	default:
		return loadRevnatTCX(netIface.Index, revnatMapReplacements)
	}
}

func loadRevnatTCX(ifindex int, mapReplacements map[string]*ebpf.Map) error {
	// injecting the already-created nat_map and target_cidrs so both programs
	// operate on the same maps. nat_map holds both the forward (snat) and
	// reverse (revnat) direction of every tracked connection, so revnat needs
	// it both to resolve the pod port and to mark/confirm/delete the paired
	// snat entry for connection tracking on the server->pod direction.
	spec, err := mooringbpf.LoadRevnatIngress()
	if err != nil {
		return fmt.Errorf("load revnat_ingress spec: %w", err)
	}
	objs := &mooringbpf.RevnatIngressObjects{}
	if err := spec.LoadAndAssign(objs, &ebpf.CollectionOptions{
		MapReplacements: mapReplacements,
	}); err != nil {
		return fmt.Errorf("load revnat_ingress: %w", err)
	}
	defer objs.Close()

	for name, m := range map[string]*ebpf.Map{
		"ext_ip_pool":            objs.ExtIpPool,
		"port_range_lookup_tcp":  objs.PortRangeLookupTcp,
		"port_range_lookup_udp":  objs.PortRangeLookupUdp,
		"port_range_lookup_icmp": objs.PortRangeLookupIcmp,
	} {
		if err := m.Pin(filepath.Join(mapsDir, name)); err != nil {
			return fmt.Errorf("pin map %s: %w", name, err)
		}
	}

	l, err := link.AttachTCX(link.TCXOptions{
		Interface: ifindex,
		Program:   objs.RevnatIngress,
		Attach:    ebpf.AttachTCXIngress,
		Anchor:    link.Head(),
	})
	if err != nil {
		return fmt.Errorf("attach revnat_ingress: %w", err)
	}
	if err := l.Pin(filepath.Join(linksDir, AttachModeTCX.linkName())); err != nil {
		_ = l.Close()
		return fmt.Errorf("pin revnat_ingress link: %w", err)
	}
	_ = l.Close()

	return nil
}

// attachXDPWithFallback tries native/driver XDP first (best performance --
// the entire point of the xdp attach mode) and falls back to generic
// (SKB-mode) XDP if that fails. This matters in practice, not just in
// theory: veth's native XDP implementation requires the frame to fit in a
// single page, so it unconditionally rejects attachment with ERANGE
// ("numerical result out of range") on any veth whose MTU exceeds that --
// e.g. this repo's own e2e_v2 kind topology uses a 9500 MTU veth for the
// BGP-routed underlay. Generic XDP has no such constraint (it runs later,
// after skb allocation, same as TC), so it's the correct fallback rather
// than a failure. Real NIC drivers can hit other reasons native XDP isn't
// available too (no driver support, offload conflicts); the fallback
// handles all of those the same way, not just the jumbo-MTU-veth case.
func attachXDPWithFallback(ifindex int, prog *ebpf.Program) (link.Link, error) {
	l, err := link.AttachXDP(link.XDPOptions{
		Interface: ifindex,
		Program:   prog,
	})
	if err == nil {
		log.Printf("loader: revnat_xdp attached in native/driver XDP mode on ifindex %d", ifindex)
		return l, nil
	}

	l, genErr := link.AttachXDP(link.XDPOptions{
		Interface: ifindex,
		Program:   prog,
		Flags:     link.XDPGenericMode,
	})
	if genErr != nil {
		return nil, fmt.Errorf("native mode: %w; generic mode: %w", err, genErr)
	}
	log.Printf("loader: revnat_xdp attached in generic (SKB) XDP mode on ifindex %d (native mode failed: %v)", ifindex, err)
	return l, nil
}

func loadRevnatXDP(ifindex int, mapReplacements map[string]*ebpf.Map) error {
	spec, err := mooringbpf.LoadRevnatXdp()
	if err != nil {
		return fmt.Errorf("load revnat_xdp spec: %w", err)
	}
	objs := &mooringbpf.RevnatXdpObjects{}
	if err := spec.LoadAndAssign(objs, &ebpf.CollectionOptions{
		MapReplacements: mapReplacements,
	}); err != nil {
		return fmt.Errorf("load revnat_xdp: %w", err)
	}
	defer objs.Close()

	for name, m := range map[string]*ebpf.Map{
		"ext_ip_pool":            objs.ExtIpPool,
		"port_range_lookup_tcp":  objs.PortRangeLookupTcp,
		"port_range_lookup_udp":  objs.PortRangeLookupUdp,
		"port_range_lookup_icmp": objs.PortRangeLookupIcmp,
	} {
		if err := m.Pin(filepath.Join(mapsDir, name)); err != nil {
			return fmt.Errorf("pin map %s: %w", name, err)
		}
	}

	l, err := attachXDPWithFallback(ifindex, objs.RevnatXdp)
	if err != nil {
		return fmt.Errorf("attach revnat_xdp: %w", err)
	}
	if err := l.Pin(filepath.Join(linksDir, AttachModeXDP.linkName())); err != nil {
		_ = l.Close()
		return fmt.Errorf("pin revnat_xdp link: %w", err)
	}
	_ = l.Close()

	return nil
}

// EnsureLoaded loads BPF programs in the given mode if they are not already
// pinned. If revnat is already attached in mode, the load step is skipped --
// existing programs keep running and in-flight connections are unaffected.
// If it's attached in the *other* mode, this errors the same way Load does:
// mode changes require an explicit `moorctl unload` first, rather than an
// unattended live migration on every daemon restart.
func EnsureLoaded(iface string, mode AttachMode) error {
	if err := validateMode(mode); err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(linksDir, mode.linkName())); err == nil {
		return nil
	}
	return Load(iface, mode)
}

// Unload detaches whichever revnat program (TCX or XDP) and snat_egress are
// attached to the uplink, and removes all bpffs pins.
func Unload() error {
	for _, name := range []string{"snat_egress", "revnat_ingress", "revnat_xdp"} {
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
