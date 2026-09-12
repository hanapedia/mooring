package allocator

import (
	"fmt"
	"sync"
)

const (
	MinPort = uint16(1024)
	MaxPort = uint16(65535)
)

// Allocation is a single contiguous port range on one external IP.
type Allocation struct {
	PortStart uint16
	PortEnd   uint16
}

// BlockAllocator manages per-IP fixed-size port-range blocks for a single NATConfig.
//
// Each external IP has an independent free-block set. Block index k on a given IP
// maps to ports [minPort + k*blockSize, minPort + (k+1)*blockSize - 1].
//
// Uniqueness rules:
//   - Per (ext-ip, pod): a block is held by at most one pod on each IP.
//   - Per pod across IPs: AllocateForPod ensures no block index repeats across the
//     pod's external IPs, so the pod's port ranges are non-overlapping by construction.
//   - Across pods on different IPs: the same block index may be held simultaneously
//     by different pods on different IPs — this is intentional and efficient.
//
// Free and rollback are idempotent: returning an already-free block is a no-op
// because map key insertion is idempotent.
//
// All methods are safe for concurrent use.
type BlockAllocator struct {
	mu          sync.Mutex
	blockSize   uint16
	minPort     uint16
	totalBlocks uint16
	ips         map[string]map[uint16]struct{} // extIP → free block index set
}

// New creates a BlockAllocator with the given fixed block size and port bounds.
// External IPs must be registered with EnsureIP before any allocation.
func New(blockSize, minPort, maxPort uint16) (*BlockAllocator, error) {
	if blockSize == 0 {
		return nil, fmt.Errorf("blockSize must be > 0")
	}
	if minPort >= maxPort {
		return nil, fmt.Errorf("minPort %d must be < maxPort %d", minPort, maxPort)
	}
	// uint16 arithmetic: (maxPort - minPort + 1) wraps to 0 when maxPort=65535 and
	// minPort=0. That edge case is caught by the totalBlocks==0 check below, but the
	// error message says "too small" rather than "overflow". Caller should use
	// MinPort (1024) or higher to stay well clear of the boundary.
	totalBlocks := (maxPort - minPort + 1) / blockSize
	if totalBlocks == 0 {
		return nil, fmt.Errorf("port space [%d, %d] too small for blockSize %d", minPort, maxPort, blockSize)
	}
	return &BlockAllocator{
		blockSize:   blockSize,
		minPort:     minPort,
		totalBlocks: totalBlocks,
		ips:         make(map[string]map[uint16]struct{}),
	}, nil
}

// EnsureIP registers an external IP with a full free set. No-op if already present.
func (a *BlockAllocator) EnsureIP(extIP string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.ips[extIP]; !ok {
		a.ips[extIP] = a.fullFreeSet()
	}
}

// RemoveIP deregisters an external IP. Any blocks allocated on it are discarded.
func (a *BlockAllocator) RemoveIP(extIP string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.ips, extIP)
}

// MarkUsed marks the block containing portStart as in-use on extIP.
// Call this during startup reconstruction for each allocation in existing NATPortRange
// resources. EnsureIP must be called for extIP before MarkUsed.
// No-op if the block is already absent from the free set.
func (a *BlockAllocator) MarkUsed(extIP string, portStart uint16) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	idx, err := a.blockIndexOf(portStart)
	if err != nil {
		return err
	}
	free, ok := a.ips[extIP]
	if !ok {
		return fmt.Errorf("external IP %s not registered", extIP)
	}
	delete(free, idx)
	return nil
}

// AllocateForPod allocates portRangeCount blocks per IP across all extIPs.
// It guarantees that no block index is repeated across IPs for this pod, so
// the returned port ranges are non-overlapping across all IPs by construction.
// On any failure the entire allocation is rolled back atomically.
// extIPs must not contain duplicates: a repeated IP would cause the first
// iteration's blocks to be overwritten in rolledBack, leaking them permanently.
func (a *BlockAllocator) AllocateForPod(extIPs []string, portRangeCount uint16) (map[string][]Allocation, error) {
	if portRangeCount == 0 {
		return nil, fmt.Errorf("portRangeCount must be > 0")
	}
	seen := make(map[string]struct{}, len(extIPs))
	for _, ip := range extIPs {
		if _, dup := seen[ip]; dup {
			return nil, fmt.Errorf("duplicate external IP %s in extIPs", ip)
		}
		seen[ip] = struct{}{}
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	// podUsed tracks block indices already assigned to this pod on earlier IPs.
	podUsed := make(map[uint16]struct{})
	result := make(map[string][]Allocation, len(extIPs))
	// rolledBack holds chosen indices per IP so we can restore on failure.
	rolledBack := make(map[string][]uint16, len(extIPs))

	for _, ip := range extIPs {
		free, ok := a.ips[ip]
		if !ok {
			a.rollback(rolledBack)
			return nil, fmt.Errorf("external IP %s not registered", ip)
		}

		chosen, err := pickFromSet(free, portRangeCount, podUsed)
		if err != nil {
			a.rollback(rolledBack)
			return nil, fmt.Errorf("IP %s: %w", ip, err)
		}

		rolledBack[ip] = chosen
		allocs := make([]Allocation, len(chosen))
		for i, idx := range chosen {
			delete(free, idx)
			allocs[i] = Allocation{
				PortStart: a.minPort + idx*a.blockSize,
				PortEnd:   a.minPort + (idx+1)*a.blockSize - 1,
			}
			podUsed[idx] = struct{}{}
		}
		result[ip] = allocs
	}
	return result, nil
}

// Free returns blocks to their respective IP free sets.
// allocs maps extIP to the Allocation values previously returned for that IP.
// Only PortStart is used to identify the block; PortEnd is ignored.
// If an IP has been removed since allocation, its blocks are silently discarded.
// Returning an already-free block is a no-op (idempotent against double-free).
// Free is atomic: all portStarts are validated before any block is returned to
// the free set, so a bad portStart does not partially free the input.
func (a *BlockAllocator) Free(allocs map[string][]Allocation) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Validate all indices before mutating any free set.
	type entry struct {
		free map[uint16]struct{}
		idx  uint16
	}
	pending := make([]entry, 0)
	for ip, als := range allocs {
		free, ok := a.ips[ip]
		if !ok {
			continue // IP removed from pool; discard
		}
		for _, al := range als {
			idx, err := a.blockIndexOf(al.PortStart)
			if err != nil {
				return fmt.Errorf("IP %s: %w", ip, err)
			}
			pending = append(pending, entry{free, idx})
		}
	}
	for _, e := range pending {
		e.free[e.idx] = struct{}{} // idempotent: double-free is a no-op
	}
	return nil
}

// AllocateForIP allocates portRangeCount blocks on a single extIP, excluding block
// indices already used by this pod on other external IPs. existingPortStarts contains
// the PortStart values of the pod's current allocations on those other IPs. This is
// used when extending an existing pod's allocations to a newly added external IP.
func (a *BlockAllocator) AllocateForIP(extIP string, portRangeCount uint16, existingPortStarts []uint16) ([]Allocation, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	free, ok := a.ips[extIP]
	if !ok {
		return nil, fmt.Errorf("external IP %s not registered", extIP)
	}

	exclude := make(map[uint16]struct{}, len(existingPortStarts))
	for _, ps := range existingPortStarts {
		idx, err := a.blockIndexOf(ps)
		if err != nil {
			return nil, fmt.Errorf("existing portStart %d: %w", ps, err)
		}
		exclude[idx] = struct{}{}
	}

	chosen, err := pickFromSet(free, portRangeCount, exclude)
	if err != nil {
		return nil, fmt.Errorf("IP %s: %w", extIP, err)
	}

	allocs := make([]Allocation, len(chosen))
	for i, idx := range chosen {
		delete(free, idx)
		allocs[i] = Allocation{
			PortStart: a.minPort + idx*a.blockSize,
			PortEnd:   a.minPort + (idx+1)*a.blockSize - 1,
		}
	}
	return allocs, nil
}

// ListIPs returns the set of currently registered external IPs.
func (a *BlockAllocator) ListIPs() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	ips := make([]string, 0, len(a.ips))
	for ip := range a.ips {
		ips = append(ips, ip)
	}
	return ips
}

// FreeCount returns the number of available blocks for extIP.
func (a *BlockAllocator) FreeCount(extIP string) (uint16, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	free, ok := a.ips[extIP]
	return uint16(len(free)), ok
}

// blockIndexOf computes the block index for portStart. Caller must hold mu.
func (a *BlockAllocator) blockIndexOf(portStart uint16) (uint16, error) {
	if portStart < a.minPort {
		return 0, fmt.Errorf("portStart %d < minPort %d", portStart, a.minPort)
	}
	offset := portStart - a.minPort
	if offset%a.blockSize != 0 {
		return 0, fmt.Errorf("portStart %d not aligned to blockSize %d from minPort %d", portStart, a.blockSize, a.minPort)
	}
	idx := offset / a.blockSize
	if idx >= a.totalBlocks {
		return 0, fmt.Errorf("portStart %d out of range (max block index %d)", portStart, a.totalBlocks-1)
	}
	return idx, nil
}

// fullFreeSet returns a map containing all block indices [0, totalBlocks).
func (a *BlockAllocator) fullFreeSet() map[uint16]struct{} {
	s := make(map[uint16]struct{}, a.totalBlocks)
	for i := uint16(0); i < a.totalBlocks; i++ {
		s[i] = struct{}{}
	}
	return s
}

// pickFromSet selects count indices from free that are not in exclude.
// It does not modify free; the caller removes chosen indices after a successful pick.
func pickFromSet(free map[uint16]struct{}, count uint16, exclude map[uint16]struct{}) ([]uint16, error) {
	chosen := make([]uint16, 0, count)
	for idx := range free {
		if _, skip := exclude[idx]; !skip {
			chosen = append(chosen, idx)
			if uint16(len(chosen)) == count {
				break
			}
		}
	}
	if uint16(len(chosen)) < count {
		return nil, fmt.Errorf("not enough free blocks: need %d, found %d (excluding %d already used by this pod)", count, len(chosen), len(exclude))
	}
	return chosen, nil
}

// rollback returns chosen indices to their IP free sets. Caller must hold mu.
// Idempotent for the same reason as Free.
func (a *BlockAllocator) rollback(allocated map[string][]uint16) {
	for ip, indices := range allocated {
		for _, idx := range indices {
			a.ips[ip][idx] = struct{}{}
		}
	}
}
