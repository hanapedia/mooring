package routing

import (
	"context"
	"net"
)

// RouteAdvertiser abstracts the mechanism by which external IP prefixes are
// announced to the network. Implementations may use BGP, L2 advertisement,
// FIB sync, or a no-op for testing.
type RouteAdvertiser interface {
	AdvertisePrefix(ctx context.Context, prefix *net.IPNet) error
	WithdrawPrefix(ctx context.Context, prefix *net.IPNet) error
}

// NoopAdvertiser satisfies RouteAdvertiser without doing anything.
// Use it in unit tests and envtest where no real routing daemon is available.
type NoopAdvertiser struct{}

func (NoopAdvertiser) AdvertisePrefix(_ context.Context, _ *net.IPNet) error { return nil }
func (NoopAdvertiser) WithdrawPrefix(_ context.Context, _ *net.IPNet) error  { return nil }
