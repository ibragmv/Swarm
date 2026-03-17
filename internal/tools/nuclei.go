package tools

import (
	"context"
	"fmt"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope"
)

// NucleiTool wraps nuclei for template-based vulnerability scanning.
type NucleiTool struct{}

func NewNucleiTool() *NucleiTool { return &NucleiTool{} }

func (n *NucleiTool) Name() string { return "nuclei" }

func (n *NucleiTool) IsAvailable() bool { return true }

func (n *NucleiTool) Run(ctx context.Context, target string, opts Options) (*ToolResult, error) {
	start := time.Now()

	scopeDef := getScopeFromContext(ctx)
	if scopeDef != nil {
		if err := scope.Validate(target, *scopeDef); err != nil {
			return nil, fmt.Errorf("scope violation in nuclei: %w", err)
		}
	}

	// In production, uses nuclei v3 as a Go library.
	// Default template categories for recon: technologies, exposures, misconfiguration

	severity := opts.GetStringSlice("severity")
	if severity == nil {
		severity = []string{"critical", "high", "medium"}
	}

	return &ToolResult{
		ToolName:  "nuclei",
		Target:    target,
		RawOutput: fmt.Sprintf("nuclei -u %s -severity %v -json", target, severity),
		Duration:  time.Since(start),
	}, nil
}
