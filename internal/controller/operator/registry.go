package operator

import (
	"fmt"
	"sync"

	"github.com/hanapedia/mooring/internal/allocator"
	"github.com/hanapedia/mooring/internal/metrics"
)

// AllocatorRegistry holds one BlockAllocator per NATConfig and gates reconcilers
// until startup reconstruction is complete.
type AllocatorRegistry struct {
	mu            sync.RWMutex
	allocators    map[string]*allocator.BlockAllocator
	reconstructed chan struct{}
}

func NewAllocatorRegistry() *AllocatorRegistry {
	return &AllocatorRegistry{
		allocators:    make(map[string]*allocator.BlockAllocator),
		reconstructed: make(chan struct{}),
	}
}

// EnsureAllocator returns the existing allocator for natConfigName, or creates one
// with blockSize. The allocator uses [allocator.MinPort, allocator.MaxPort] as its
// port space. Returns an error only if the port space is invalid for blockSize.
//
// If an allocator already exists, blockSize is ignored — changing NATConfig.Spec.PortRangeSize
// on a live NATConfig is not supported and requires a full delete+recreate of the NATConfig
// and all its NATPortRanges.
func (r *AllocatorRegistry) EnsureAllocator(natConfigName string, blockSize uint16) (*allocator.BlockAllocator, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if a, ok := r.allocators[natConfigName]; ok {
		return a, nil
	}
	a, err := allocator.New(blockSize, allocator.MinPort, allocator.MaxPort, natConfigName,
		func() { metrics.NATConfigPortAllocationFailuresTotal.WithLabelValues(natConfigName).Inc() })
	if err != nil {
		return nil, fmt.Errorf("create allocator for NATConfig %s: %w", natConfigName, err)
	}
	r.allocators[natConfigName] = a
	return a, nil
}

// RecordAvailability updates the ports-free/ports-total gauges for every
// external IP currently registered with natConfigName's allocator. It is a
// no-op if no allocator exists for natConfigName. Callers are responsible for
// deleting gauge entries for IPs removed from the pool (RecordAvailability
// only ever sets values for IPs the allocator still knows about).
func (r *AllocatorRegistry) RecordAvailability(natConfigName string) {
	alloc, ok := r.Get(natConfigName)
	if !ok {
		return
	}
	blockSize := alloc.BlockSize()
	totalPorts := float64(alloc.TotalBlocks()) * float64(blockSize)
	for _, ip := range alloc.ListIPs() {
		freeBlocks, ok := alloc.FreeCount(ip)
		if !ok {
			continue
		}
		metrics.NATConfigPortsFree.WithLabelValues(natConfigName, ip).Set(float64(freeBlocks) * float64(blockSize))
		metrics.NATConfigPortsTotal.WithLabelValues(natConfigName, ip).Set(totalPorts)
	}
}

// Get returns the allocator for natConfigName if it exists.
func (r *AllocatorRegistry) Get(natConfigName string) (*allocator.BlockAllocator, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	a, ok := r.allocators[natConfigName]
	return a, ok
}

// Remove deletes the allocator for natConfigName. Any blocks it tracked are discarded.
func (r *AllocatorRegistry) Remove(natConfigName string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.allocators, natConfigName)
}

// Reconstructed returns a channel closed when startup reconstruction is done.
// All reconcilers block on this channel before processing any items.
func (r *AllocatorRegistry) Reconstructed() <-chan struct{} {
	return r.reconstructed
}

// MarkReconstructed closes the reconstruction gate. Must be called exactly once.
func (r *AllocatorRegistry) MarkReconstructed() {
	close(r.reconstructed)
}
