package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/keychain"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope/importer"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope/importer/bugcrowd"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope/importer/hackerone"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope/importer/intigriti"
	"github.com/spf13/cobra"
	"go.yaml.in/yaml/v3"
)

var scopeCmd = &cobra.Command{
	Use:   "scope",
	Short: "Manage bug-bounty program scope — import, diff, validate",
}

var scopeImportCmd = &cobra.Command{
	Use:   "import <platform> <program-slug>",
	Short: "Import scope from a bug-bounty platform",
	Long: `Pulls the in-scope asset list for a program from the named platform
and writes it to scope.yaml (or the path given by --out).

Platforms: h1 | bugcrowd | intigriti

Tokens come from the OS keychain (see 'pentestswarm init' and
'pentestswarm scope login'). Falls back to HACKERONE_* /
BUGCROWD_API_TOKEN / INTIGRITI_API_TOKEN env vars for CI.`,
	Args: cobra.ExactArgs(2),
	Example: `  pentestswarm scope import h1 shopify
  pentestswarm scope import bugcrowd tesla --out /tmp/tesla.yaml
  pentestswarm scope import intigriti acme-corp`,
	RunE: runScopeImport,
}

func runScopeImport(cmd *cobra.Command, args []string) error {
	platform := args[0]
	slug := args[1]
	outPath, _ := cmd.Flags().GetString("out")
	if outPath == "" {
		outPath = "scope.yaml"
	}

	imp, err := buildImporter(platform)
	if err != nil {
		return err
	}
	fmt.Printf("  %s importing %s/%s ...\n", colorCyan("[scope]"), platform, slug)
	def, err := imp.Import(context.Background(), slug)
	if err != nil {
		return fmt.Errorf("import: %w", err)
	}

	buf, err := yaml.Marshal(def)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	if err := os.WriteFile(outPath, buf, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", outPath, err)
	}

	fmt.Printf("  %s wrote %d domains + %d CIDRs to %s\n",
		colorGreen("[ok]"),
		len(def.AllowedDomains), len(def.AllowedCIDRs),
		colorCyan(outPath))
	fmt.Println()
	fmt.Println("  Next:")
	fmt.Printf("    %s\n", colorCyan("pentestswarm scan "+firstHost(def.AllowedDomains)+" --scope "+outPath+" --swarm"))
	return nil
}

// buildImporter returns the right Importer for a platform slug + auth.
// Auth order matches the scan command's API key resolution: env first
// (CI-friendly), then OS keychain (what 'init' stashes to).
func buildImporter(platform string) (importer.Importer, error) {
	switch platform {
	case "h1", "hackerone":
		user := os.Getenv("HACKERONE_API_USER")
		token := os.Getenv("HACKERONE_API_TOKEN")
		if token == "" {
			if v, err := keychain.Get(keychain.KeyHackerOneToken); err == nil {
				token = v
			}
		}
		return hackerone.NewClient(hackerone.Config{APIUser: user, APIToken: token}), nil

	case "bugcrowd":
		token := os.Getenv("BUGCROWD_API_TOKEN")
		if token == "" {
			if v, err := keychain.Get(keychain.KeyBugcrowdToken); err == nil {
				token = v
			}
		}
		return bugcrowd.NewClient(bugcrowd.Config{Token: token}), nil

	case "intigriti":
		token := os.Getenv("INTIGRITI_API_TOKEN")
		if token == "" {
			if v, err := keychain.Get(keychain.KeyIntigritiToken); err == nil {
				token = v
			}
		}
		return intigriti.NewClient(intigriti.Config{Token: token}), nil

	default:
		return nil, fmt.Errorf("unknown platform %q — use h1, bugcrowd, or intigriti", platform)
	}
}

func firstHost(domains []string) string {
	if len(domains) > 0 {
		return domains[0]
	}
	return "example.com"
}

func init() {
	scopeImportCmd.Flags().String("out", "scope.yaml", "output scope file path")
	scopeCmd.AddCommand(scopeImportCmd)
	rootCmd.AddCommand(scopeCmd)
}
