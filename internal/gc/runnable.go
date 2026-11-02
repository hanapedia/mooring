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

	// signalRetryDelay is how long watchSignal waits before reopening
	// nat_map_gc_signal after an unexpected read failure, so a persistent
	// problem doesn't spin the retry loop.
	signalRetryDelay = 5 * time.Second
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

	// Fail fast if mooring isn't loaded yet; watchSignal handles a later
	// failure differently (retries instead of giving up).
	if err := probeSignal(); err != nil {
		return fmt.Errorf("gc: %w", err)
	}

	signals := watchSignal(ctx)

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

func openSignalReader() (*ringbuf.Reader, *ebpf.Map, error) {
	signalMap, err := ebpf.LoadPinnedMap(filepath.Join(mapsDir, gcSignalMapName), nil)
	if err != nil {
		return nil, nil, fmt.Errorf("open %s (is mooring loaded?): %w", gcSignalMapName, err)
	}
	reader, err := ringbuf.NewReader(signalMap)
	if err != nil {
		signalMap.Close()
		return nil, nil, fmt.Errorf("open ringbuf reader on %s: %w", gcSignalMapName, err)
	}
	return reader, signalMap, nil
}

func probeSignal() error {
	reader, signalMap, err := openSignalReader()
	if err != nil {
		return err
	}
	reader.Close()
	signalMap.Close()
	return nil
}

// watchSignal retries pumpSignal on failure instead of giving up on
// out-of-cycle triggers for good -- Start's ticker covers for it either
// way, so a broken signal path is degraded, not fatal.
func watchSignal(ctx context.Context) <-chan struct{} {
	signals := make(chan struct{})
	go func() {
		defer close(signals)
		for ctx.Err() == nil {
			if err := pumpSignal(ctx, signals); err != nil {
				log.Printf("gc: nat_map_gc_signal reader failed, reopening in %s: %v", signalRetryDelay, err)
				select {
				case <-time.After(signalRetryDelay):
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return signals
}

// pumpSignal relays nat_map_gc_signal records into signals until ctx is
// cancelled (nil) or a read fails for any other reason (that error).
func pumpSignal(ctx context.Context, signals chan<- struct{}) error {
	reader, signalMap, err := openSignalReader()
	if err != nil {
		return err
	}
	defer signalMap.Close()
	defer context.AfterFunc(ctx, func() { reader.Close() })() // unblocks Read() below on shutdown

	for {
		if _, err := reader.Read(); err != nil {
			if ctx.Err() != nil {
				return nil // deliberate shutdown
			}
			return err
		}
		select {
		case signals <- struct{}{}:
		case <-ctx.Done():
			return nil
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
