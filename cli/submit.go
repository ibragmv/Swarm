package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/agent/report"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/pipeline"
	"github.com/spf13/cobra"
)

var submitCmd = &cobra.Command{
	Use:   "submit",
	Short: "Turn a campaign report into platform-specific submission drafts",
	Long: `Reads a campaign report (JSON emitted by 'scan --format json') and
writes one ready-to-paste markdown file per finding, formatted for the
chosen bug-bounty platform.

By default this is a dry-run that writes to ./submissions/<id>.md —
the actual 'press submit on your behalf' path is intentionally gated
behind --live and currently disabled pending H1/Bugcrowd API review.
You can't accidentally post an AI-generated report to a real program
with this command.`,
	Example: `  pentestswarm submit --platform h1 --report ./reports/scan.json
  pentestswarm submit --platform bugcrowd --report ./reports/scan.json --program acme
`,
	RunE: runSubmit,
}

func runSubmit(cmd *cobra.Command, args []string) error {
	platform, _ := cmd.Flags().GetString("platform")
	reportPath, _ := cmd.Flags().GetString("report")
	outDir, _ := cmd.Flags().GetString("out")
	live, _ := cmd.Flags().GetBool("live")
	program, _ := cmd.Flags().GetString("program")

	if platform == "" {
		return fmt.Errorf("--platform is required (h1 | bugcrowd | intigriti)")
	}
	if reportPath == "" {
		return fmt.Errorf("--report <path-to-report.json> is required")
	}
	if live {
		return fmt.Errorf("--live submission is not yet implemented — drop the flag to preview submissions locally")
	}
	if outDir == "" {
		outDir = "./submissions"
	}

	data, err := os.ReadFile(reportPath)
	if err != nil {
		return fmt.Errorf("read report: %w", err)
	}
	var pr pipeline.PentestReport
	if err := json.Unmarshal(data, &pr); err != nil {
		return fmt.Errorf("parse report: %w", err)
	}

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", outDir, err)
	}

	fmt.Println()
	fmt.Printf("  %s %d findings → %s format\n", colorCyan("[submit]"),
		len(pr.Findings), platform)
	if program != "" {
		fmt.Printf("  %s program slug: %s\n", colorCyan("[submit]"), program)
	}
	fmt.Println()

	written := 0
	for _, rf := range pr.Findings {
		// In the future we'll cross-reference classifier output; for now
		// the report finding is enough to render a decent submission.
		v := report.BuildSubmissionView(rf, nil, nil)
		body, err := report.RenderSubmission(platform, v)
		if err != nil {
			fmt.Printf("  %s %s — %s\n", colorRed("[skip]"), rf.Title, err)
			continue
		}
		fname := filepath.Join(outDir, sanitiseFilename(rf.Title)+".md")
		if err := os.WriteFile(fname, body, 0o644); err != nil {
			return fmt.Errorf("write %s: %w", fname, err)
		}
		fmt.Printf("  %s %-50s → %s\n", colorGreen("[draft]"), truncateCLI(rf.Title, 50), colorCyan(fname))
		written++
	}
	fmt.Println()
	fmt.Printf("  Wrote %d submission drafts to %s\n", written, colorCyan(outDir))
	fmt.Println(colorDim("  Review each draft, then paste into the platform's submission form."))
	fmt.Println(colorDim("  (--live will post via the platform API in a future release.)"))
	return nil
}

func sanitiseFilename(s string) string {
	out := make([]byte, 0, len(s))
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			out = append(out, byte(r))
		case r == ' ', r == '-', r == '_':
			out = append(out, '-')
		}
	}
	// Trim trailing hyphens and cap length.
	s2 := strings.Trim(string(out), "-")
	if len(s2) > 60 {
		s2 = s2[:60]
	}
	if s2 == "" {
		s2 = "finding"
	}
	return s2
}

func truncateCLI(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func init() {
	submitCmd.Flags().String("platform", "", "target platform: h1 | bugcrowd | intigriti")
	submitCmd.Flags().String("report", "", "path to the scan's JSON report")
	submitCmd.Flags().String("out", "./submissions", "directory to write submission drafts into")
	submitCmd.Flags().String("program", "", "program slug (only used by --live, not dry-run)")
	submitCmd.Flags().Bool("live", false, "actually POST submissions via the platform API (not yet implemented)")
	rootCmd.AddCommand(submitCmd)
}
