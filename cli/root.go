package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	cfgFile string
	apiURL  string
	jsonOut bool
	quiet   bool
	verbose bool
)

// rootCmd is the base command.
var rootCmd = &cobra.Command{
	Use:   "autopentest",
	Short: "Autonomous AI-Powered Penetration Testing",
	Long: `autopentest is a multi-agent AI system that autonomously performs
full-cycle penetration tests — from continuous recon through exploitation
through professional reporting — powered by specialist AI models
coordinated by an orchestrator agent.`,
}

// Execute runs the root command.
func Execute(version, commit, date string) {
	rootCmd.Version = fmt.Sprintf("%s (commit: %s, built: %s)", version, commit, date)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default: ./config.yaml)")
	rootCmd.PersistentFlags().StringVar(&apiURL, "api", "http://localhost:8080", "API server URL")
	rootCmd.PersistentFlags().BoolVar(&jsonOut, "json", false, "output in JSON format")
	rootCmd.PersistentFlags().BoolVar(&quiet, "quiet", false, "suppress decorative output")
	rootCmd.PersistentFlags().BoolVar(&verbose, "verbose", false, "enable debug logging")

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
