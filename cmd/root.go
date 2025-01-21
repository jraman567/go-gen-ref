package cmd

import (
	"github.com/jraman567/go-gen-ref/cmd/sevsnp"

	"github.com/spf13/cobra"
)

var (
	validArgs = []string{"sevsnp"}
)

var rootCmd = &cobra.Command{
	Use:           "go-gen-ref",
	Short:         "Reference Values Generator",
	Version:       "0.0.1",
	SilenceUsage:  true,
	SilenceErrors: true,
	ValidArgs:     validArgs,
}

func Execute() {
	cobra.CheckErr(rootCmd.Execute())
}

func init() {
	rootCmd.AddCommand(sevsnp.Cmd)
}
