package tools

import (
	"context"
	"fmt"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope"
)

// GauTool wraps gau for fetching known URLs from Wayback Machine, Common Crawl, etc.
type GauTool struct{}

func NewGauTool() *GauTool { return &GauTool{} }

func (g *GauTool) Name() string { return "gau" }

func (g *GauTool) IsAvailable() bool { return true }

func (g *GauTool) Run(ctx context.Context, target string, opts Options) (*ToolResult, error) {
	start := time.Now()

	scopeDef := getScopeFromContext(ctx)
	if scopeDef != nil {
		if err := scope.Validate(target, *scopeDef); err != nil {
			return nil, fmt.Errorf("scope violation in gau: %w", err)
		}
	}

	return &ToolResult{
		ToolName:  "gau",
		Target:    target,
		RawOutput: fmt.Sprintf("gau %s --providers wayback,commoncrawl,otx,urlscan --json", target),
		Duration:  time.Since(start),
	}, nil
}
