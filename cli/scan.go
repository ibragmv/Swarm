package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/config"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/engine"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/pipeline"
	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	Use:   "scan <target>",
	Short: "Launch the swarm against a target",
	Long:  `Deploys the AI agent swarm to autonomously pentest the specified target.`,
	Args:  cobra.ExactArgs(1),
	Example: `  pentestswarm scan example.com --scope example.com
  pentestswarm scan 10.0.0.0/24 --scope 10.0.0.0/24 --objective "find RCE"
  pentestswarm scan example.com --scope example.com --mode bugbounty --follow
  pentestswarm scan example.com --scope example.com --dry-run`,
	RunE: runScan,
}

func runScan(cmd *cobra.Command, args []string) error {
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
	providerOverride, _ := cmd.Flags().GetString("provider")

	// Load config
	cfg, err := config.Load(cfgFile)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	// Check for API key in env if not in config
	if cfg.Orchestrator.APIKey == "" {
		if key := os.Getenv("PENTESTSWARM_ORCHESTRATOR_API_KEY"); key != "" {
			cfg.Orchestrator.APIKey = key
		} else if key := os.Getenv("ANTHROPIC_API_KEY"); key != "" {
			cfg.Orchestrator.APIKey = key
		}
	}

	if cfg.Orchestrator.APIKey == "" && cfg.Orchestrator.Provider == "claude" {
		return fmt.Errorf("no API key found. Set PENTESTSWARM_ORCHESTRATOR_API_KEY or ANTHROPIC_API_KEY")
	}

	// Print banner
	if !quiet {
		printBanner()
		fmt.Println()
		fmt.Printf("  Target:     %s\n", colorBold(target))
		fmt.Printf("  Scope:      %s\n", scopeStr)
		fmt.Printf("  Objective:  %s\n", objective)
		fmt.Printf("  Mode:       %s\n", mode)
		fmt.Printf("  Provider:   %s\n", providerOrDefault(providerOverride, cfg.Orchestrator.Provider))
		if dryRun {
			fmt.Printf("  %s\n", colorYellow("DRY RUN — no exploitation commands will execute"))
		}
		fmt.Println()
		fmt.Println(colorDim("─────────────────────────────────────────────────────"))
		fmt.Println()
	}

	// Setup context with signal handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\n" + colorRed("Emergency stop — shutting down swarm..."))
		cancel()
	}()

	// Build campaign config
	cc := engine.CampaignConfig{
		Target:    target,
		Scope:     strings.Split(scopeStr, ","),
		Objective: objective,
		Mode:      mode,
		DryRun:    dryRun,
		OutputDir: output,
		Format:    format,
		Provider:  providerOverride,
	}

	// Event handler for live output
	var onEvent engine.EventCallback
	if follow || !quiet {
		onEvent = func(event pipeline.CampaignEvent) {
			printEvent(event)
		}
	}

	// Run the campaign
	var runnerOpts []engine.Option
	if strict, _ := cmd.Flags().GetBool("strict"); strict {
		runnerOpts = append(runnerOpts, engine.WithStrictLLM())
	}
	runner := engine.NewRunner(cfg, runnerOpts...)
	if err := runner.Run(ctx, cc, onEvent); err != nil {
		if ctx.Err() != nil {
			fmt.Println(colorRed("\nCampaign aborted by user."))
			return nil
		}
		return fmt.Errorf("campaign failed: %w", err)
	}

	if !quiet {
		fmt.Println()
		fmt.Println(colorGreen("Campaign complete."))
	}

	return nil
}

func printEvent(event pipeline.CampaignEvent) {
	ts := event.Timestamp.Format("15:04:05")

	switch event.EventType {
	case pipeline.EventThought:
		fmt.Printf("  %s %s %s\n", colorDim(ts), colorCyan("[think]"), event.Detail)
	case pipeline.EventToolCall:
		fmt.Printf("  %s %s %s\n", colorDim(ts), colorYellow("[>>]"), event.Detail)
	case pipeline.EventToolResult:
		fmt.Printf("  %s %s %s\n", colorDim(ts), colorGreen("[<<]"), event.Detail)
	case pipeline.EventFindingDiscovered:
		fmt.Printf("  %s %s %s\n", colorDim(ts), colorRed("[!]"), event.Detail)
	case pipeline.EventStateChange:
		fmt.Printf("  %s %s %s\n", colorDim(ts), colorMagenta("[*]"), event.Detail)
	case pipeline.EventStepExecuted:
		fmt.Printf("  %s %s %s\n", colorDim(ts), colorYellow("[>]"), event.Detail)
	case pipeline.EventError:
		fmt.Printf("  %s %s %s\n", colorDim(ts), colorRed("[ERR]"), event.Detail)
	case pipeline.EventMilestone:
		fmt.Printf("\n  %s %s\n", colorGreen("[DONE]"), colorBold(event.Detail))
	default:
		fmt.Printf("  %s [%s] %s\n", colorDim(ts), event.EventType, event.Detail)
	}
}

func printBanner() {
	fmt.Println(colorCyan(`
  ██████  ██     ██  █████  ██████  ███    ███
  ██      ██     ██ ██   ██ ██   ██ ████  ████
  ███████ ██  █  ██ ███████ ██████  ██ ████ ██
       ██ ██ ███ ██ ██   ██ ██   ██ ██  ██  ██
  ███████  ███ ███  ██   ██ ██   ██ ██      ██`))
	fmt.Println(colorDim("  Pentest Swarm AI — swarms of agents, one mission"))
}

func colorBold(s string) string    { return "\033[1m" + s + "\033[0m" }
func colorDim(s string) string     { return "\033[2m" + s + "\033[0m" }
func colorRed(s string) string     { return "\033[31m" + s + "\033[0m" }
func colorGreen(s string) string   { return "\033[32m" + s + "\033[0m" }
func colorYellow(s string) string  { return "\033[33m" + s + "\033[0m" }
func colorCyan(s string) string    { return "\033[36m" + s + "\033[0m" }
func colorMagenta(s string) string { return "\033[35m" + s + "\033[0m" }

func providerOrDefault(override, def string) string {
	if override != "" {
		return override
	}
	return def
}

func init() {
	scanCmd.Flags().String("scope", "", "CIDR or domain scope, comma-separated (required)")
	scanCmd.Flags().String("objective", "find all vulnerabilities", "what to find")
	scanCmd.Flags().String("mode", "manual", "manual|bugbounty|asm|ctf")
	scanCmd.Flags().String("provider", "", "claude|ollama|lmstudio (overrides config)")
	scanCmd.Flags().Bool("dry-run", false, "show planned commands without executing")
	scanCmd.Flags().String("output", "./reports", "output directory for report")
	scanCmd.Flags().String("format", "md", "report format: md|html|json|all")
	scanCmd.Flags().Bool("follow", false, "stream live output (default when interactive)")
	scanCmd.Flags().Bool("strict", false, "abort on any LLM error instead of degrading to heuristics")
	scanCmd.Flags().String("auth-token", "", "authorization token")

	_ = scanCmd.MarkFlagRequired("scope")

	rootCmd.AddCommand(scanCmd)
}
