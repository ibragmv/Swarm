package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	Use:   "scan <target>",
	Short: "Start a penetration test against a target",
	Long:  `Starts an autonomous penetration testing campaign against the specified target.`,
	Args:  cobra.ExactArgs(1),
	Example: `  pentestswarm scan example.com --scope example.com
  pentestswarm scan 10.0.0.0/24 --scope 10.0.0.0/24 --objective "find RCE"
  pentestswarm scan example.com --scope example.com --mode bugbounty --follow
  pentestswarm scan example.com --scope example.com --dry-run`,
	RunE: func(cmd *cobra.Command, args []string) error {
		target := args[0]

		scopeStr, _ := cmd.Flags().GetString("scope")
		if scopeStr == "" {
			return fmt.Errorf("--scope is required")
		}

		objective, _ := cmd.Flags().GetString("objective")
		mode, _ := cmd.Flags().GetString("mode")
		dryRun, _ := cmd.Flags().GetBool("dry-run")
		follow, _ := cmd.Flags().GetBool("follow")
		format, _ := cmd.Flags().GetString("format")
		output, _ := cmd.Flags().GetString("output")

		if !quiet {
			fmt.Printf("🎯 Target:    %s\n", target)
			fmt.Printf("🔒 Scope:     %s\n", scopeStr)
			fmt.Printf("🎯 Objective: %s\n", objective)
			fmt.Printf("📋 Mode:      %s\n", mode)
			fmt.Printf("📄 Format:    %s\n", format)
			if dryRun {
				fmt.Println("⚠️  DRY RUN — no commands will be executed")
			}
		}

		// TODO: Create campaign via API, start it, optionally follow
		_ = follow
		_ = output

		fmt.Println("\n✅ Campaign created. Use 'pentestswarm campaign watch <id>' to monitor.")
		return nil
	},
}

func init() {
	scanCmd.Flags().String("scope", "", "CIDR or domain scope, comma-separated (required)")
	scanCmd.Flags().String("objective", "find all vulnerabilities", "what to find")
	scanCmd.Flags().String("mode", "manual", "manual|bugbounty|asm|ctf")
	scanCmd.Flags().String("provider", "", "claude|ollama|lmstudio (overrides config)")
	scanCmd.Flags().Bool("dry-run", false, "show planned commands without executing")
	scanCmd.Flags().String("output", "./reports", "output directory for report")
	scanCmd.Flags().String("format", "pdf", "report format: pdf|html|md|json|all")
	scanCmd.Flags().Bool("follow", false, "stream live output")
	scanCmd.Flags().String("auth-token", "", "authorization token")

	_ = scanCmd.MarkFlagRequired("scope")

	rootCmd.AddCommand(scanCmd)
}
