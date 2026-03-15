package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var campaignCmd = &cobra.Command{
	Use:   "campaign",
	Short: "Manage penetration testing campaigns",
}

var campaignListCmd = &cobra.Command{
	Use:     "list",
	Short:   "List all campaigns",
	Example: "  autopentest campaign list",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("ID                                    STATUS       TARGET              FINDINGS")
		fmt.Println("─────────────────────────────────────────────────────────────────────────────")
		// TODO: fetch from API
		fmt.Println("(no campaigns yet)")
		return nil
	},
}

var campaignStatusCmd = &cobra.Command{
	Use:     "status <id>",
	Short:   "Show detailed status of a campaign",
	Args:    cobra.ExactArgs(1),
	Example: "  autopentest campaign status abc-123",
	RunE: func(cmd *cobra.Command, args []string) error {
		id := args[0]
		fmt.Printf("Campaign: %s\n", id)
		// TODO: fetch from API
		return nil
	},
}

var campaignWatchCmd = &cobra.Command{
	Use:     "watch <id>",
	Short:   "Live stream of agent activity (TUI)",
	Args:    cobra.ExactArgs(1),
	Example: "  autopentest campaign watch abc-123",
	RunE: func(cmd *cobra.Command, args []string) error {
		// TODO: launch bubbletea TUI
		fmt.Printf("Watching campaign %s... (TUI will launch here)\n", args[0])
		return nil
	},
}

var campaignStopCmd = &cobra.Command{
	Use:     "stop <id>",
	Short:   "Emergency stop a running campaign",
	Args:    cobra.ExactArgs(1),
	Example: "  autopentest campaign stop abc-123",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Printf("Stopping campaign %s...\n", args[0])
		// TODO: call API
		fmt.Println("Campaign stopped.")
		return nil
	},
}

var campaignExploreCmd = &cobra.Command{
	Use:     "explore <id>",
	Short:   "Interactive recon data explorer (TUI)",
	Args:    cobra.ExactArgs(1),
	Example: "  autopentest campaign explore abc-123",
	RunE: func(cmd *cobra.Command, args []string) error {
		// TODO: launch bubbletea recon explorer TUI
		fmt.Printf("Exploring attack surface for campaign %s... (TUI will launch here)\n", args[0])
		return nil
	},
}

func init() {
	campaignCmd.AddCommand(campaignListCmd)
	campaignCmd.AddCommand(campaignStatusCmd)
	campaignCmd.AddCommand(campaignWatchCmd)
	campaignCmd.AddCommand(campaignStopCmd)
	campaignCmd.AddCommand(campaignExploreCmd)

	rootCmd.AddCommand(campaignCmd)
}
