package main

import (
	"github.com/hanapedia/mooring/internal/loader"
	"github.com/spf13/cobra"
)

var unloadCmd = &cobra.Command{
	Use:   "unload",
	Short: "Detach BPF programs and remove all bpffs pins",
	RunE:  runUnload,
}

func init() {
	rootCmd.AddCommand(unloadCmd)
}

func runUnload(_ *cobra.Command, _ []string) error {
	return loader.Unload()
}
