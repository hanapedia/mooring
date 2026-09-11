package operator

import (
	"fmt"
	"sync"

	"github.com/hanapedia/mooring/internal/allocator"
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
func (r *AllocatorRegistry) EnsureAllocator(natConfigName string, blockSize uint16) (*allocator.BlockAllocator, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if a, ok := r.allocators[natConfigName]; ok {
		return a, nil
	}
	a, err := allocator.New(blockSize, allocator.MinPort, allocator.MaxPort)
	if err != nil {
		return nil, fmt.Errorf("create allocator for NATConfig %s: %w", natConfigName, err)
	}
	r.allocators[natConfigName] = a
	return a, nil
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
