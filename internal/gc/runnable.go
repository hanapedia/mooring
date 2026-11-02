package gc

import (
	"context"
	"fmt"
	"log"
	"path/filepath"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

const (
	mapsDir         = "/sys/fs/bpf/mooring/maps"
	gcSignalMapName = "nat_map_gc_signal"

	// DefaultPeriod is used when Runnable.Period is zero. Keeps
	// nat_map_any's effective idle timeout (1x-2x this, see bpf/nat_gc.c)
	// in the same range as typical non-TCP conntrack idle timeouts.
	DefaultPeriod = 30 * time.Second

	// debounceWindow skips a sweep that would otherwise run within this
	// long of the previous one -- the ticker and the ringbuf signal can
	// race harmlessly but redundantly (e.g. a signal arriving just before a
	// scheduled tick), so this just avoids doing the same work twice back
	// to back, not a correctness requirement.
	debounceWindow = time.Second
)

// Runnable periodically sweeps nat_map_tcp and nat_map_any (RunSweep) on a
// fixed interval, and also out-of-cycle whenever the datapath signals one of
// them is full (nat_map_gc_signal, see bpf/headers/maps.h). It implements
// sigs.k8s.io/controller-runtime's manager.Runnable -- register it via
// mgr.Add(...) in cmd/daemon/main.go, the same way
// internal/routing/bgp.BGPSpeaker already is.
type Runnable struct {
	// Period is the fixed sweep interval. Zero means DefaultPeriod.
	Period time.Duration

	mu      sync.Mutex
	lastRun time.Time
}

// Start implements manager.Runnable. It blocks until ctx is cancelled.
func (r *Runnable) Start(ctx context.Context) error {
	period := r.Period
	if period <= 0 {
		period = DefaultPeriod
	}

	signalMap, err := ebpf.LoadPinnedMap(filepath.Join(mapsDir, gcSignalMapName), nil)
	if err != nil {
		return fmt.Errorf("gc: open %s (is mooring loaded?): %w", gcSignalMapName, err)
	}
	defer signalMap.Close()

	reader, err := ringbuf.NewReader(signalMap)
	if err != nil {
		return fmt.Errorf("gc: open ringbuf reader on %s: %w", gcSignalMapName, err)
	}
	defer reader.Close() // unblocks the goroutine below's Read() on shutdown

	signals := make(chan struct{})
	go func() {
		defer close(signals)
		for {
			if _, err := reader.Read(); err != nil {
				return // reader.Close() (above) or a real read error -- either way, stop
			}
			select {
			case signals <- struct{}{}:
			case <-ctx.Done():
				return
			}
		}
	}()

	ticker := time.NewTicker(period)
	defer ticker.Stop()

	r.sweepAll() // settle state once up front, same as this codebase's other periodic reconcilers

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			r.sweepAll()
		case <-signals:
			r.sweepAll()
		}
	}
}

// sweepAll runs both sweeps, debounced -- see debounceWindow.
func (r *Runnable) sweepAll() {
	r.mu.Lock()
	if time.Since(r.lastRun) < debounceWindow {
		r.mu.Unlock()
		return
	}
	r.lastRun = time.Now()
	r.mu.Unlock()

	for _, kind := range []Kind{KindTCP, KindAny} {
		stats, err := RunSweep(kind)
		if err != nil {
			log.Printf("gc: sweep %s failed: %v", kind, err)
			continue
		}
		log.Printf("gc: swept nat_map_%s: scanned=%d deleted=%d remaining=%d",
			kind, stats.Scanned, stats.Deleted, stats.Remaining)
	}
}
