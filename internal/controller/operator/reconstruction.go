package operator

import (
	"context"
	"fmt"

	v1alpha1 "github.com/hanapedia/mooring/api/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// ReconstructionRunnable replays all existing NATPortRange allocations into the
// in-memory allocators before any reconciler processes a single item, preventing
// allocation conflicts with NATPortRangeRequests that arrived while the operator
// was down.
//
// It implements manager.LeaderElectionRunnable so it runs only on the elected leader.
type ReconstructionRunnable struct {
	Client   client.Client
	Registry *AllocatorRegistry
}

func (r *ReconstructionRunnable) Start(ctx context.Context) error {
	log := log.FromContext(ctx).WithName("reconstruction")

	// r.Client is the manager's cache-backed client. controller-runtime guarantees
	// that all informer caches are synced and their watches are established before
	// any runnable's Start method is called. This means:
	//   - The List below reads from the same informer store that feeds each
	//     controller's workqueue.
	//   - Any deletion that occurs after the watch starts (which is before we
	//     reach this point) will produce a DELETE event in the workqueue.
	//   - Controllers block on the reconstruction gate, so they cannot process
	//     any event until after MarkReconstructed closes the gate below.
	//
	// Consequence: if an NPR is deleted during reconstruction, its MarkUsed blocks
	// will be freed by the NPR controller once the gate opens — no leak is possible.

	// Step 1: create per-NATConfig allocators and register current pool IPs.
	var configs v1alpha1.NATConfigList
	if err := r.Client.List(ctx, &configs); err != nil {
		return fmt.Errorf("list NATConfigs: %w", err)
	}
	for _, nc := range configs.Items {
		alloc, err := r.Registry.EnsureAllocator(nc.Name, uint16(nc.Spec.PortRangeSize))
		if err != nil {
			return err
		}
		ips, err := expandCIDRs(nc.Spec.ExternalIPPool)
		if err != nil {
			return fmt.Errorf("NATConfig %s: %w", nc.Name, err)
		}
		for _, ip := range ips {
			alloc.EnsureIP(ip)
		}
	}

	// Step 2: replay existing NATPortRange allocations.
	var ranges v1alpha1.NATPortRangeList
	if err := r.Client.List(ctx, &ranges); err != nil {
		return fmt.Errorf("list NATPortRanges: %w", err)
	}
	for _, npr := range ranges.Items {
		if !npr.DeletionTimestamp.IsZero() {
			continue
		}
		alloc, ok := r.Registry.Get(npr.Spec.NATConfig)
		if !ok {
			log.Info("NATPortRange references unknown NATConfig; skipping",
				"natPortRange", npr.Name, "natConfig", npr.Spec.NATConfig)
			continue
		}
		for _, a := range npr.Spec.Allocations {
			if err := alloc.MarkUsed(a.ExternalIP, uint16(a.PortStart)); err != nil {
				// IP may have been removed from the pool since this NPR was written.
				// The NATConfig controller will clean it up on its next reconcile.
				log.Info("skipping stale allocation during reconstruction",
					"natPortRange", npr.Name, "ip", a.ExternalIP,
					"portStart", a.PortStart, "reason", err.Error())
			}
		}
	}

	log.Info("reconstruction complete",
		"natConfigs", len(configs.Items), "natPortRanges", len(ranges.Items))
	r.Registry.MarkReconstructed()
	return nil
}

// NeedLeaderElection ensures this runnable only executes on the leader replica.
func (r *ReconstructionRunnable) NeedLeaderElection() bool { return true }
