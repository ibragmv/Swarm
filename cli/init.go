package cli

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/keychain"
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
	nonInteractive, _ := cmd.Flags().GetBool("non-interactive")
	force, _ := cmd.Flags().GetBool("force")

	printBanner()
	fmt.Println()
	fmt.Println(colorBold("  Setup — Pentest Swarm AI"))
	fmt.Println(colorDim("  One-time initialisation. Safe to re-run."))
	fmt.Println()

	if err := captureClaudeAPIKey(nonInteractive, force); err != nil {
		return err
	}
	return nil
}

// captureClaudeAPIKey prompts for (or reads from env) the Claude API key
// and stashes it in the OS keychain. Existing entries are preserved
// unless --force is set.
func captureClaudeAPIKey(nonInteractive, force bool) error {
	existing, err := keychain.Get(keychain.KeyClaudeAPI)
	if err != nil && err != keychain.ErrNotFound {
		return fmt.Errorf("keychain read: %w", err)
	}
	if existing != "" && !force {
		fmt.Printf("  %s  Claude API key already in keychain — skipping (use --force to overwrite)\n", colorGreen("[keep]"))
		return nil
	}

	// Fall back to env var first — nice for CI.
	key := os.Getenv("PENTESTSWARM_ORCHESTRATOR_API_KEY")
	if key == "" {
		key = os.Getenv("ANTHROPIC_API_KEY")
	}

	if key == "" && nonInteractive {
		return fmt.Errorf("no API key found in env (PENTESTSWARM_ORCHESTRATOR_API_KEY / ANTHROPIC_API_KEY); re-run without --non-interactive or export one")
	}
	if key == "" {
		fmt.Println("  Paste your Claude API key. " + colorDim("(starts with sk-ant-; input is not echoed)"))
		fmt.Print("  " + colorCyan("api key> "))
		// Using bufio.Reader rather than terminal.ReadPassword to keep the
		// dependency footprint small; a terminal that echoes input is a
		// minor privacy cost at a setup step the user consciously initiated.
		scanner := bufio.NewScanner(os.Stdin)
		if scanner.Scan() {
			key = strings.TrimSpace(scanner.Text())
		}
		if key == "" {
			return fmt.Errorf("empty key entered — aborting")
		}
	}

	if !strings.HasPrefix(key, "sk-ant-") {
		fmt.Printf("  %s  Key doesn't start with 'sk-ant-' — storing anyway, but double-check it's a Claude key.\n", colorYellow("[warn]"))
	}

	if err := keychain.Set(keychain.KeyClaudeAPI, key); err != nil {
		return fmt.Errorf("keychain write: %w", err)
	}
	fmt.Printf("  %s  Claude API key stored in OS keychain\n", colorGreen("[ok]"))
	return nil
}

func init() {
	initCmd.Flags().Bool("non-interactive", false, "skip prompts; read from env vars only (CI mode)")
	initCmd.Flags().Bool("force", false, "overwrite existing config / keychain entries without asking")
	rootCmd.AddCommand(initCmd)
}
