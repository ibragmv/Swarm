package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var ctfCmd = &cobra.Command{
	Use:   "ctf",
	Short: "Autonomous CTF machine solving",
}

var ctfSolveCmd = &cobra.Command{
	Use:   "solve <target>",
	Short: "Autonomously solve a CTF machine",
	Args:  cobra.ExactArgs(1),
	Example: `  pentestswarm ctf solve 10.10.10.1
  pentestswarm ctf solve 10.10.10.1 --platform htb --machine Lame
  pentestswarm ctf solve 10.10.10.1 --follow`,
	RunE: func(cmd *cobra.Command, args []string) error {
		target := args[0]
		platform, _ := cmd.Flags().GetString("platform")
		machine, _ := cmd.Flags().GetString("machine")

		fmt.Printf("Solving CTF: %s (platform: %s, machine: %s)\n", target, platform, machine)
		// TODO: Wire to CTF solver
		return nil
	},
}

var ctfListCmd = &cobra.Command{
	Use:     "list",
	Short:   "List available CTF machines",
	Example: "  pentestswarm ctf list --platform htb --difficulty easy",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("Listing CTF machines...")
		// TODO: Wire to platform client
		return nil
	},
}

var ctfWriteupCmd = &cobra.Command{
	Use:     "writeup <campaign-id>",
	Short:   "Generate writeup from a CTF campaign",
	Args:    cobra.ExactArgs(1),
	Example: "  pentestswarm ctf writeup abc-123",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Printf("Generating writeup for campaign %s...\n", args[0])
		return nil
	},
}

func init() {
	ctfSolveCmd.Flags().String("platform", "generic", "htb|thm|generic")
	ctfSolveCmd.Flags().String("machine", "", "machine name (for auto-spawn)")
	ctfSolveCmd.Flags().Bool("follow", false, "stream live output")

	ctfListCmd.Flags().String("platform", "htb", "htb|thm")
	ctfListCmd.Flags().String("difficulty", "", "easy|medium|hard")

	ctfCmd.AddCommand(ctfSolveCmd)
	ctfCmd.AddCommand(ctfListCmd)
	ctfCmd.AddCommand(ctfWriteupCmd)

	rootCmd.AddCommand(ctfCmd)
}
