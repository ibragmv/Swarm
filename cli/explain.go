package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var explainCmd = &cobra.Command{
	Use:   "explain <finding-id|cve-id>",
	Short: "Explain a finding or CVE in plain English",
	Args:  cobra.ExactArgs(1),
	Example: `  pentestswarm explain abc-123
  pentestswarm explain CVE-2024-1234
  pentestswarm explain abc-123 --audience developer
  pentestswarm explain abc-123 --remediate`,
	RunE: func(cmd *cobra.Command, args []string) error {
		id := args[0]
		audience, _ := cmd.Flags().GetString("audience")
		remediate, _ := cmd.Flags().GetBool("remediate")

		fmt.Printf("Explaining %s (audience: %s, remediate: %v)\n", id, audience, remediate)
		// TODO: fetch finding from API, send to LLM with audience-appropriate prompt
		return nil
	},
}

func init() {
	explainCmd.Flags().String("audience", "developer", "developer|manager|executive")
	explainCmd.Flags().Bool("remediate", false, "include step-by-step fix instructions")

	rootCmd.AddCommand(explainCmd)
}
