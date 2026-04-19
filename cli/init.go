package cli

import (
	"github.com/spf13/cobra"
)

// initCmd is the one-shot interactive setup a researcher runs once after
// install. Everything else in the CLI assumes init has already been run.
var initCmd = &cobra.Command{
	Use:   "init",
	Short: "One-shot interactive setup — API key, tool probe, config file",
	Long: `init is what you run once after installing the tool.

It does three things:
  1. Prompts for your Claude API key and stores it in the OS native
     keychain (macOS Keychain / linux-secret-service / Windows).
  2. Probes the host for security tools (nmap, sqlmap, nuclei, etc.)
     and prints which are present + install hints for the rest.
  3. Writes a minimal ~/.pentestswarm/config.yaml so future commands
     have sensible defaults.

Safe to re-run: existing values are preserved unless you explicitly
overwrite them.`,
	Example: `  pentestswarm init
  pentestswarm init --non-interactive    # CI-friendly; reads env vars
`,
	RunE: runInit,
}

func runInit(cmd *cobra.Command, args []string) error {
	// Logic lands in follow-up commits so each piece can be reviewed
	// independently: API key capture, tool probe, config writer.
	return nil
}

func init() {
	initCmd.Flags().Bool("non-interactive", false, "skip prompts; read from env vars only (CI mode)")
	initCmd.Flags().Bool("force", false, "overwrite existing config / keychain entries without asking")
	rootCmd.AddCommand(initCmd)
}
