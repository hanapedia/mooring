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

// ── nat-config ───────────────────────────────────────────────────────────────

var (
	ncPodIP      string
	ncExtIP      string
	ncTargetCIDR string
	ncPortStart  uint16
	ncPortEnd    uint16
)

var natConfigAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Add a NAT config entry for a pod",
	RunE:  runNatConfigAdd,
}

func runNatConfigAdd(_ *cobra.Command, _ []string) error {
	podIP := net.ParseIP(ncPodIP).To4()
	if podIP == nil {
		return fmt.Errorf("invalid --pod-ip %q", ncPodIP)
	}
	extIP := net.ParseIP(ncExtIP).To4()
	if extIP == nil {
		return fmt.Errorf("invalid --ext-ip %q", ncExtIP)
	}
	_, targetCIDR, err := net.ParseCIDR(ncTargetCIDR)
	if err != nil {
		return fmt.Errorf("invalid --target-cidr: %w", err)
	}
	if ncPortStart > ncPortEnd {
		return fmt.Errorf("--port-start must be <= --port-end")
	}
	return maps.UpsertNatConfigEntry(podIP, targetCIDR, extIP, ncPortStart, ncPortEnd)
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
	prProto     string
)

var portRangeAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Expand a port range into port_range_lookup (one entry per port)",
	RunE:  runPortRangeAdd,
}

var allProtos = []uint8{6, 17, 1} // tcp, udp, icmp

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
	protos := allProtos
	if prProto != "" {
		proto, err := parseProto(prProto)
		if err != nil {
			return err
		}
		protos = []uint8{proto}
	}
	for _, proto := range protos {
		if err := maps.AddPortRange(extIP, podIP, prPortStart, prPortEnd, proto); err != nil {
			return err
		}
	}
	return nil
}

func parseProto(s string) (uint8, error) {
	switch s {
	case "tcp":
		return 6, nil
	case "udp":
		return 17, nil
	case "icmp":
		return 1, nil
	default:
		return 0, fmt.Errorf("invalid --proto %q (want tcp, udp, or icmp)", s)
	}
}

// ── init ──────────────────────────────────────────────────────────────────────

func init() {
	rootCmd.AddCommand(mapCmd)

	natConfigCmd := &cobra.Command{Use: "nat-config", Short: "Manage the nat_config map"}
	mapCmd.AddCommand(natConfigCmd)
	natConfigCmd.AddCommand(natConfigAddCmd)
	natConfigAddCmd.Flags().StringVar(&ncPodIP, "pod-ip", "", "pod source IP (required)")
	natConfigAddCmd.Flags().StringVar(&ncExtIP, "ext-ip", "", "external (SNAT) IP (required)")
	natConfigAddCmd.Flags().StringVar(&ncTargetCIDR, "target-cidr", "", "target CIDR matched by the packet destination (required)")
	natConfigAddCmd.Flags().Uint16Var(&ncPortStart, "port-start", 0, "first port in range (required)")
	natConfigAddCmd.Flags().Uint16Var(&ncPortEnd, "port-end", 0, "last port in range (required)")
	_ = natConfigAddCmd.MarkFlagRequired("pod-ip")
	_ = natConfigAddCmd.MarkFlagRequired("ext-ip")
	_ = natConfigAddCmd.MarkFlagRequired("target-cidr")
	_ = natConfigAddCmd.MarkFlagRequired("port-start")
	_ = natConfigAddCmd.MarkFlagRequired("port-end")

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
	portRangeAddCmd.Flags().StringVar(&prProto, "proto", "", "protocol: tcp, udp, or icmp (default: all)")
	_ = portRangeAddCmd.MarkFlagRequired("ext-ip")
	_ = portRangeAddCmd.MarkFlagRequired("pod-ip")
	_ = portRangeAddCmd.MarkFlagRequired("port-start")
	_ = portRangeAddCmd.MarkFlagRequired("port-end")
}
