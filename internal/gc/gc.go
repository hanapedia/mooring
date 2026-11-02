// Package gc runs the periodic/on-demand garbage-collection sweeps for
// nat_map_tcp and nat_map_any (see bpf/headers/maps.h, bpf/nat_gc.c). Each
// sweep invokes one pinned SEC("syscall") BPF program via BPF_PROG_TEST_RUN:
// the entire scan -- walk every map entry, delete or mark the stale ones --
// runs in kernel space inside that single syscall, so triggering a sweep
// from userspace costs one syscall regardless of map size, same as every
// other map operation in this codebase staying off the per-packet path.
package gc

import (
	"fmt"
	"path/filepath"

	"github.com/cilium/ebpf"
)

const progsDir = "/sys/fs/bpf/mooring/progs"

// Kind selects which nat_map_* a sweep targets.
type Kind string

const (
	KindTCP Kind = "tcp"
	KindAny Kind = "any"
)

// progName returns the pinned program name for k, matching the SEC("syscall")
// names in bpf/nat_gc.c.
func (k Kind) progName() (string, error) {
	switch k {
	case KindTCP:
		return "gc_nat_map_tcp", nil
	case KindAny:
		return "gc_nat_map_any", nil
	default:
		return "", fmt.Errorf("gc: unknown kind %q (want %q or %q)", k, KindTCP, KindAny)
	}
}

// Stats mirrors bpf/nat_gc.c's struct gc_ctx field-for-field (order and
// width), since it's decoded directly from that struct's raw bytes via
// BPF_PROG_TEST_RUN's ctx_out -- see RunSweep.
type Stats struct {
	Scanned   uint64
	Deleted   uint64
	Remaining uint64
}

// RunSweep runs one GC sweep over nat_map_tcp (kind == KindTCP) or
// nat_map_any (kind == KindAny) and returns what the sweep found/did.
func RunSweep(kind Kind) (Stats, error) {
	progName, err := kind.progName()
	if err != nil {
		return Stats{}, err
	}

	prog, err := ebpf.LoadPinnedProgram(filepath.Join(progsDir, progName), nil)
	if err != nil {
		return Stats{}, fmt.Errorf("open gc program %q (is mooring loaded?): %w", progName, err)
	}
	defer prog.Close()

	var stats Stats
	if _, err := prog.Run(&ebpf.RunOptions{
		Context:    stats,
		ContextOut: &stats,
	}); err != nil {
		return Stats{}, fmt.Errorf("run gc program %q: %w", progName, err)
	}
	return stats, nil
}
