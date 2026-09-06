package main

import (
	"github.com/hanapedia/mooring/internal/loader"
	"github.com/spf13/cobra"
)

var loadIface string

var loadCmd = &cobra.Command{
	Use:   "load",
	Short: "Load and attach BPF programs to the node uplink",
	RunE:  runLoad,
}

func init() {
	rootCmd.AddCommand(loadCmd)
	loadCmd.Flags().StringVarP(&loadIface, "iface", "i", "", "node uplink interface name (required)")
	_ = loadCmd.MarkFlagRequired("iface")
}

func runLoad(_ *cobra.Command, _ []string) error {
	return loader.Load(loadIface)
}
