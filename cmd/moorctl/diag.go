package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	mooringbpf "github.com/hanapedia/mooring/internal/bpf"
	"github.com/spf13/cobra"
)

const diagMapsDir = "/sys/fs/bpf/mooring/maps"

// ── diag stage1 ───────────────────────────────────────────────────────────────

var (
	diagSrcIP   string
	diagDstIP   string
	diagDstPort uint16
)

var diagCmd = &cobra.Command{
	Use:   "diag",
	Short: "Diagnostic commands",
}

var diagStage1Cmd = &cobra.Command{
	Use:   "stage1",
	Short: "Check revNAT stage-1 map conditions for a given packet header",
	Long: `Simulates the three revnat_ingress stage-1 BPF lookups from userspace:
  1. Is src-ip in target_cidrs?
  2. Is dst-ip in ext_ip_pool?
  3. Is (dst-ip, dst-port) in port_range_lookup?

Example:
  moorctl diag stage1 --src-ip 192.168.10.100 --dst-ip 192.168.10.0 --dst-port 1000`,
	RunE: runDiagStage1,
}

func runDiagStage1(_ *cobra.Command, _ []string) error {
	srcIP := net.ParseIP(diagSrcIP).To4()
	if srcIP == nil {
		return fmt.Errorf("invalid --src-ip %q", diagSrcIP)
	}
	dstIP := net.ParseIP(diagDstIP).To4()
	if dstIP == nil {
		return fmt.Errorf("invalid --dst-ip %q", diagDstIP)
	}

	srcU32 := diagIPToU32(srcIP)
	dstU32 := diagIPToU32(dstIP)

	// ── 1. target_cidrs ───────────────────────────────────────────────────────
	tc, err := ebpf.LoadPinnedMap(diagMapsDir+"/target_cidrs", nil)
	if err != nil {
		return fmt.Errorf("open target_cidrs: %w", err)
	}
	defer tc.Close()

	tcKey := mooringbpf.SnatEgressLpmKey{Prefixlen: 32, Addr: srcU32}
	var tcVal uint8
	tcErr := tc.Lookup(tcKey, &tcVal)
	diagCheck("target_cidrs[src=%s]", tcErr, diagSrcIP)

	// ── 2. ext_ip_pool ────────────────────────────────────────────────────────
	ep, err := ebpf.LoadPinnedMap(diagMapsDir+"/ext_ip_pool", nil)
	if err != nil {
		return fmt.Errorf("open ext_ip_pool: %w", err)
	}
	defer ep.Close()

	epKey := mooringbpf.RevnatIngressLpmKey{Prefixlen: 32, Addr: dstU32}
	var epVal uint8
	epErr := ep.Lookup(epKey, &epVal)
	diagCheck("ext_ip_pool[dst=%s]", epErr, diagDstIP)

	// ── 3. port_range_lookup (HASH_OF_MAPS) ──────────────────────────────────
	pl, err := ebpf.LoadPinnedMap(diagMapsDir+"/port_range_lookup", nil)
	if err != nil {
		return fmt.Errorf("open port_range_lookup: %w", err)
	}
	defer pl.Close()

	// outer lookup: ext_ip → inner map fd
	var innerFD uint32
	innerErr := pl.Lookup(dstU32, &innerFD)
	diagCheck("port_range_lookup outer[dst=%s]", innerErr, diagDstIP)
	if innerErr == nil {
		inner, err := ebpf.NewMapFromFD(int(innerFD))
		if err != nil {
			return fmt.Errorf("open inner map: %w", err)
		}
		defer inner.Close()

		// inner lookup: port index (host byte order) → pod_ip
		var podIPRaw uint32
		portIdx := uint32(diagDstPort)
		plErr := inner.Lookup(portIdx, &podIPRaw)
		if plErr == nil && podIPRaw != 0 {
			b := make([]byte, 4)
			binary.LittleEndian.PutUint32(b, podIPRaw)
			fmt.Printf("  port_range_lookup inner[port=%d] → FOUND → pod_ip=%s\n",
				diagDstPort, net.IP(b).String())
		} else if plErr == nil {
			fmt.Printf("  port_range_lookup inner[port=%d] → FOUND but pod_ip=0 ← ✗\n", diagDstPort)
		} else {
			diagCheck("port_range_lookup inner[port=%d]", plErr, diagDstPort)
		}
	}

	return nil
}

// diagIPToU32 packs a 4-byte net.IP in network byte order into a uint32 that,
// when written by the ebpf library in host (LE) byte order, lands in the kernel
// map with the correct network-order bytes — matching what the BPF program reads
// from iph->saddr / iph->daddr.
func diagIPToU32(ip net.IP) uint32 {
	return binary.LittleEndian.Uint32(ip.To4())
}

func diagCheck(fmtStr string, err error, args ...any) {
	label := fmt.Sprintf(fmtStr, args...)
	if err == nil {
		fmt.Printf("  %-55s  FOUND\n", label)
	} else if errors.Is(err, ebpf.ErrKeyNotExist) {
		fmt.Printf("  %-55s  NOT FOUND ← ✗\n", label)
	} else {
		fmt.Printf("  %-55s  ERROR: %v\n", label, err)
	}
}

func init() {
	rootCmd.AddCommand(diagCmd)
	diagCmd.AddCommand(diagStage1Cmd)

	diagStage1Cmd.Flags().StringVar(&diagSrcIP, "src-ip", "", "source IP to check in target_cidrs (required)")
	diagStage1Cmd.Flags().StringVar(&diagDstIP, "dst-ip", "", "destination IP to check in ext_ip_pool and port_range_lookup (required)")
	diagStage1Cmd.Flags().Uint16Var(&diagDstPort, "dst-port", 0, "destination port to check in port_range_lookup (required)")
	_ = diagStage1Cmd.MarkFlagRequired("src-ip")
	_ = diagStage1Cmd.MarkFlagRequired("dst-ip")
	_ = diagStage1Cmd.MarkFlagRequired("dst-port")
}
