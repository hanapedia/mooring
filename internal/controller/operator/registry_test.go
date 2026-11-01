package operator_test

import (
	"testing"

	"github.com/hanapedia/mooring/internal/allocator"
	"github.com/hanapedia/mooring/internal/controller/operator"
)

func TestEnsureAllocator_AllowRegisteredPortsWidensPortSpace(t *testing.T) {
	const blockSize = uint16(100)

	registry := operator.NewAllocatorRegistry()
	narrow, err := registry.EnsureAllocator("narrow", blockSize, false, nil)
	if err != nil {
		t.Fatalf("EnsureAllocator(narrow): %v", err)
	}
	wide, err := registry.EnsureAllocator("wide", blockSize, true, nil)
	if err != nil {
		t.Fatalf("EnsureAllocator(wide): %v", err)
	}

	wantNarrow := (allocator.MaxPort - allocator.MinPortDynamic + 1) / blockSize
	wantWide := (allocator.MaxPort - allocator.MinPortFull + 1) / blockSize
	if got := narrow.TotalBlocks(); got != wantNarrow {
		t.Errorf("narrow allocator TotalBlocks = %d, want %d", got, wantNarrow)
	}
	if got := wide.TotalBlocks(); got != wantWide {
		t.Errorf("wide allocator TotalBlocks = %d, want %d", got, wantWide)
	}
	if wide.TotalBlocks() <= narrow.TotalBlocks() {
		t.Errorf("wide allocator should have strictly more blocks than narrow: wide=%d narrow=%d",
			wide.TotalBlocks(), narrow.TotalBlocks())
	}
}

func TestEnsureAllocator_AllowRegisteredPortsFrozenAfterCreation(t *testing.T) {
	const blockSize = uint16(100)

	registry := operator.NewAllocatorRegistry()
	first, err := registry.EnsureAllocator("nc", blockSize, false, nil)
	if err != nil {
		t.Fatalf("EnsureAllocator: %v", err)
	}
	before := first.TotalBlocks()

	// A later call with allowRegisteredPorts=true must not widen the
	// already-created allocator, mirroring blockSize's frozen-at-creation behavior.
	again, err := registry.EnsureAllocator("nc", blockSize, true, nil)
	if err != nil {
		t.Fatalf("EnsureAllocator (second call): %v", err)
	}
	if again.TotalBlocks() != before {
		t.Errorf("TotalBlocks changed after re-calling EnsureAllocator with allowRegisteredPorts=true: before=%d after=%d",
			before, again.TotalBlocks())
	}
}
