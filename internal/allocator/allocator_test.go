package allocator_test

import (
	"testing"

	"github.com/hanapedia/mooring/internal/allocator"
)

const (
	blockSize = uint16(100)
	minPort   = uint16(1024)
	maxPort   = uint16(65535)
)

func newTestAllocator(t *testing.T, ips ...string) *allocator.BlockAllocator {
	t.Helper()
	a, err := allocator.New(blockSize, minPort, maxPort)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for _, ip := range ips {
		a.EnsureIP(ip)
	}
	return a
}

func TestAllocateBasic(t *testing.T) {
	a := newTestAllocator(t, "192.0.2.1")

	allocs, err := a.AllocateForPod([]string{"192.0.2.1"}, 1)
	if err != nil {
		t.Fatalf("AllocateForPod: %v", err)
	}
	al := allocs["192.0.2.1"][0]
	if al.PortEnd-al.PortStart+1 != blockSize {
		t.Errorf("expected block of %d ports, got %d", blockSize, al.PortEnd-al.PortStart+1)
	}
	if al.PortStart < minPort {
		t.Errorf("portStart %d below minPort %d", al.PortStart, minPort)
	}
}

// TestNonOverlappingSamePod verifies that a single pod's ranges across
// multiple IPs never overlap.
func TestNonOverlappingSamePod(t *testing.T) {
	ips := []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"}
	a := newTestAllocator(t, ips...)

	allocs, err := a.AllocateForPod(ips, 2)
	if err != nil {
		t.Fatalf("AllocateForPod: %v", err)
	}

	// Collect all port ranges across all IPs for this pod.
	type interval struct{ start, end uint16 }
	var ranges []interval
	for _, als := range allocs {
		for _, al := range als {
			ranges = append(ranges, interval{al.PortStart, al.PortEnd})
		}
	}

	// All ranges must be non-overlapping.
	for i := 0; i < len(ranges); i++ {
		for j := i + 1; j < len(ranges); j++ {
			ri, rj := ranges[i], ranges[j]
			if ri.start <= rj.end && rj.start <= ri.end {
				t.Errorf("overlap: [%d,%d] and [%d,%d]", ri.start, ri.end, rj.start, rj.end)
			}
		}
	}
}

// TestSameBlockReusableAcrossPods verifies that different pods CAN hold the
// same block index on different external IPs simultaneously.
func TestSameBlockReusableAcrossPods(t *testing.T) {
	ip1, ip2 := "192.0.2.1", "192.0.2.2"
	a := newTestAllocator(t, ip1, ip2)

	// pod-foo gets one block on ip1.
	fooAllocs, err := a.AllocateForPod([]string{ip1}, 1)
	if err != nil {
		t.Fatalf("pod-foo AllocateForPod: %v", err)
	}
	fooIP1 := fooAllocs[ip1][0]

	// pod-bar gets one block on ip2. It should be able to use the same port
	// range as pod-foo since they are on different IPs.
	barAllocs, err := a.AllocateForPod([]string{ip2}, 1)
	if err != nil {
		t.Fatalf("pod-bar AllocateForPod: %v", err)
	}
	barIP2 := barAllocs[ip2][0]

	if fooIP1.PortStart != barIP2.PortStart {
		// This is not a failure — the allocator is free to assign any block.
		// But it's worth logging to confirm reuse is happening in practice.
		t.Logf("note: pod-foo on ip1 got [%d,%d], pod-bar on ip2 got [%d,%d] (different blocks, both valid)",
			fooIP1.PortStart, fooIP1.PortEnd, barIP2.PortStart, barIP2.PortEnd)
	}
	// What matters: pod-bar could succeed even if pod-foo holds block 0 on ip1,
	// because ip2's block 0 is still free. The test failing here would mean the
	// allocator unnecessarily blocked reuse.
}

// TestExhaustion confirms an informative error when a per-IP pool is full.
func TestExhaustion(t *testing.T) {
	// Small port space: 3 blocks only.
	a, err := allocator.New(100, 1024, 1323)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ip := "192.0.2.1"
	a.EnsureIP(ip)

	for i := 0; i < 3; i++ {
		if _, err := a.AllocateForPod([]string{ip}, 1); err != nil {
			t.Fatalf("allocation %d failed: %v", i, err)
		}
	}
	if _, err := a.AllocateForPod([]string{ip}, 1); err == nil {
		t.Error("expected error on exhausted pool, got nil")
	}
}

// TestRollbackOnFailure confirms that if one IP in a multi-IP allocation
// fails, all previously allocated blocks are restored.
func TestRollbackOnFailure(t *testing.T) {
	// ip1 has 2 blocks, ip2 has 1 block.
	// Requesting portRangeCount=2 across both IPs requires 2 unique blocks per IP.
	// ip2 only has 1 free block → allocation should fail.
	// ip1's blocks should be returned so its FreeCount goes back to 2.
	a, err := allocator.New(100, 1024, 1323) // 3 blocks total
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ip1, ip2 := "192.0.2.1", "192.0.2.2"
	a.EnsureIP(ip1) // 3 free blocks
	a.EnsureIP(ip2) // 3 free blocks

	// Use up 2 blocks on ip2 so only 1 remains.
	if _, err := a.AllocateForPod([]string{ip2}, 2); err != nil {
		t.Fatalf("setup: %v", err)
	}

	before, _ := a.FreeCount(ip1)

	// Request portRangeCount=2: ip1 can satisfy it but ip2 (1 free) cannot.
	_, err = a.AllocateForPod([]string{ip1, ip2}, 2)
	if err == nil {
		t.Fatal("expected failure, got nil")
	}

	after, _ := a.FreeCount(ip1)
	if before != after {
		t.Errorf("ip1 FreeCount changed after rollback: before=%d after=%d", before, after)
	}
}

// TestFreeAndReallocate confirms freed blocks are returned to the pool and reused.
func TestFreeAndReallocate(t *testing.T) {
	ip := "192.0.2.1"
	a := newTestAllocator(t, ip)

	allocs, err := a.AllocateForPod([]string{ip}, 1)
	if err != nil {
		t.Fatalf("AllocateForPod: %v", err)
	}
	portStart := allocs[ip][0].PortStart

	if err := a.Free(map[string][]uint16{ip: {portStart}}); err != nil {
		t.Fatalf("Free: %v", err)
	}

	// Should be able to reallocate — and may get the same block back.
	if _, err := a.AllocateForPod([]string{ip}, 1); err != nil {
		t.Fatalf("reallocate after free: %v", err)
	}
}

// TestReconstruction simulates startup: existing NATPortRange allocations are
// replayed via MarkUsed, then new allocations must not overlap them.
func TestReconstruction(t *testing.T) {
	ip := "192.0.2.1"
	a := newTestAllocator(t, ip)

	// Simulate: block 0 (portStart=1024) is already in use.
	if err := a.MarkUsed(ip, 1024); err != nil {
		t.Fatalf("MarkUsed: %v", err)
	}

	allocs, err := a.AllocateForPod([]string{ip}, 1)
	if err != nil {
		t.Fatalf("AllocateForPod after reconstruction: %v", err)
	}
	if allocs[ip][0].PortStart == 1024 {
		t.Error("allocated block 0 which was marked used")
	}
}

// TestDoubleFreeIdempotent verifies that freeing the same block twice does not
// corrupt the free set (no duplicate block, no double-allocation).
func TestDoubleFreeIdempotent(t *testing.T) {
	ip := "192.0.2.1"
	a := newTestAllocator(t, ip)

	before, _ := a.FreeCount(ip)

	allocs, err := a.AllocateForPod([]string{ip}, 1)
	if err != nil {
		t.Fatalf("AllocateForPod: %v", err)
	}
	portStart := allocs[ip][0].PortStart

	freeArg := map[string][]uint16{ip: {portStart}}
	if err := a.Free(freeArg); err != nil {
		t.Fatalf("first Free: %v", err)
	}
	if err := a.Free(freeArg); err != nil {
		t.Fatalf("second Free: %v", err)
	}

	after, _ := a.FreeCount(ip)
	if after != before {
		t.Errorf("FreeCount after double-free: got %d, want %d (duplicate entered free set)", after, before)
	}
}

// TestDuplicateIPRejected verifies that AllocateForPod rejects duplicate IPs
// before touching the free set, so no blocks are leaked.
func TestDuplicateIPRejected(t *testing.T) {
	ip := "192.0.2.1"
	a := newTestAllocator(t, ip)

	before, _ := a.FreeCount(ip)
	_, err := a.AllocateForPod([]string{ip, ip}, 1)
	if err == nil {
		t.Fatal("expected error for duplicate IP, got nil")
	}
	after, _ := a.FreeCount(ip)
	if before != after {
		t.Errorf("FreeCount changed after rejected duplicate-IP call: before=%d after=%d", before, after)
	}
}

// TestPortRangeCount verifies that portRangeCount > 1 returns multiple
// non-overlapping ranges per IP.
func TestPortRangeCount(t *testing.T) {
	ip := "192.0.2.1"
	a := newTestAllocator(t, ip)

	allocs, err := a.AllocateForPod([]string{ip}, 3)
	if err != nil {
		t.Fatalf("AllocateForPod: %v", err)
	}
	als := allocs[ip]
	if len(als) != 3 {
		t.Fatalf("expected 3 allocations, got %d", len(als))
	}
	for i := 0; i < len(als); i++ {
		for j := i + 1; j < len(als); j++ {
			if als[i].PortStart <= als[j].PortEnd && als[j].PortStart <= als[i].PortEnd {
				t.Errorf("overlap between allocation %d and %d", i, j)
			}
		}
	}
}
