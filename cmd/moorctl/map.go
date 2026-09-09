package main

import (
	"fmt"
	"net"

	"github.com/hanapedia/mooring/internal/maps"
	"github.com/spf13/cobra"
)

var mapCmd = &cobra.Command{
	Use:   "map",
	Short: "Manage BPF map entries",
}

// ── snat-config ───────────────────────────────────────────────────────────────

var (
	scPodIP     string
	scExtIP     string
	scPortStart uint16
	scPortEnd   uint16
)

var snatConfigAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Add a SNAT config entry for a pod",
	RunE:  runSnatConfigAdd,
}

func runSnatConfigAdd(_ *cobra.Command, _ []string) error {
	podIP := net.ParseIP(scPodIP).To4()
	if podIP == nil {
		return fmt.Errorf("invalid --pod-ip %q", scPodIP)
	}
	extIP := net.ParseIP(scExtIP).To4()
	if extIP == nil {
		return fmt.Errorf("invalid --ext-ip %q", scExtIP)
	}
	if scPortStart > scPortEnd {
		return fmt.Errorf("--port-start must be <= --port-end")
	}
	return maps.UpsertSnatEntry(podIP, extIP, scPortStart, scPortEnd)
}

// ── target-cidr ───────────────────────────────────────────────────────────────

var tcCIDR string

var targetCIDRAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Add a destination CIDR that triggers SNAT/revNAT",
	RunE:  runTargetCIDRAdd,
}

func runTargetCIDRAdd(_ *cobra.Command, _ []string) error {
	_, cidr, err := net.ParseCIDR(tcCIDR)
	if err != nil {
		return fmt.Errorf("invalid --cidr: %w", err)
	}
	return maps.AddTargetCIDR(cidr)
}

// ── ext-ip ────────────────────────────────────────────────────────────────────

var extIPCIDR string

var extIPAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Add an external IP CIDR to the pool",
	RunE:  runExtIPAdd,
}

func runExtIPAdd(_ *cobra.Command, _ []string) error {
	_, cidr, err := net.ParseCIDR(extIPCIDR)
	if err != nil {
		return fmt.Errorf("invalid --cidr: %w", err)
	}
	return maps.AddExtIP(cidr)
}

// ── port-range ────────────────────────────────────────────────────────────────

var (
	prExtIP     string
	prPodIP     string
	prPortStart uint16
	prPortEnd   uint16
)

var portRangeAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Expand a port range into port_range_lookup (one entry per port)",
	RunE:  runPortRangeAdd,
}

func runPortRangeAdd(_ *cobra.Command, _ []string) error {
	extIP := net.ParseIP(prExtIP).To4()
	if extIP == nil {
		return fmt.Errorf("invalid --ext-ip %q", prExtIP)
	}
	podIP := net.ParseIP(prPodIP).To4()
	if podIP == nil {
		return fmt.Errorf("invalid --pod-ip %q", prPodIP)
	}
	if prPortStart > prPortEnd {
		return fmt.Errorf("--port-start must be <= --port-end")
	}
	return maps.AddPortRange(extIP, podIP, prPortStart, prPortEnd)
}

// ── init ──────────────────────────────────────────────────────────────────────

func init() {
	rootCmd.AddCommand(mapCmd)

	snatConfigCmd := &cobra.Command{Use: "snat-config", Short: "Manage the snat_config map"}
	mapCmd.AddCommand(snatConfigCmd)
	snatConfigCmd.AddCommand(snatConfigAddCmd)
	snatConfigAddCmd.Flags().StringVar(&scPodIP, "pod-ip", "", "pod source IP (required)")
	snatConfigAddCmd.Flags().StringVar(&scExtIP, "ext-ip", "", "external (SNAT) IP (required)")
	snatConfigAddCmd.Flags().Uint16Var(&scPortStart, "port-start", 0, "first port in range (required)")
	snatConfigAddCmd.Flags().Uint16Var(&scPortEnd, "port-end", 0, "last port in range (required)")
	_ = snatConfigAddCmd.MarkFlagRequired("pod-ip")
	_ = snatConfigAddCmd.MarkFlagRequired("ext-ip")
	_ = snatConfigAddCmd.MarkFlagRequired("port-start")
	_ = snatConfigAddCmd.MarkFlagRequired("port-end")

	targetCIDRCmd := &cobra.Command{Use: "target-cidr", Short: "Manage the target_cidrs map"}
	mapCmd.AddCommand(targetCIDRCmd)
	targetCIDRCmd.AddCommand(targetCIDRAddCmd)
	targetCIDRAddCmd.Flags().StringVar(&tcCIDR, "cidr", "", "destination CIDR (required)")
	_ = targetCIDRAddCmd.MarkFlagRequired("cidr")

	extIPCmd := &cobra.Command{Use: "ext-ip", Short: "Manage the ext_ip_pool map"}
	mapCmd.AddCommand(extIPCmd)
	extIPCmd.AddCommand(extIPAddCmd)
	extIPAddCmd.Flags().StringVar(&extIPCIDR, "cidr", "", "external IP CIDR (required)")
	_ = extIPAddCmd.MarkFlagRequired("cidr")

	portRangeCmd := &cobra.Command{Use: "port-range", Short: "Manage the port_range_lookup map"}
	mapCmd.AddCommand(portRangeCmd)
	portRangeCmd.AddCommand(portRangeAddCmd)
	portRangeAddCmd.Flags().StringVar(&prExtIP, "ext-ip", "", "external IP (required)")
	portRangeAddCmd.Flags().StringVar(&prPodIP, "pod-ip", "", "pod IP (required)")
	portRangeAddCmd.Flags().Uint16Var(&prPortStart, "port-start", 0, "first port in range (required)")
	portRangeAddCmd.Flags().Uint16Var(&prPortEnd, "port-end", 0, "last port in range (required)")
	_ = portRangeAddCmd.MarkFlagRequired("ext-ip")
	_ = portRangeAddCmd.MarkFlagRequired("pod-ip")
	_ = portRangeAddCmd.MarkFlagRequired("port-start")
	_ = portRangeAddCmd.MarkFlagRequired("port-end")
}
