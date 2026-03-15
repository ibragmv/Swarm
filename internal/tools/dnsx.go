package tools

import (
	"context"
	"fmt"
	"time"

	"github.com/Armur-Ai/autopentest/internal/scope"
)

// DnsxTool wraps dnsx for DNS resolution and reverse lookups.
type DnsxTool struct{}

func NewDnsxTool() *DnsxTool { return &DnsxTool{} }

func (d *DnsxTool) Name() string { return "dnsx" }

func (d *DnsxTool) IsAvailable() bool { return true }

func (d *DnsxTool) Run(ctx context.Context, target string, opts Options) (*ToolResult, error) {
	start := time.Now()

	scopeDef := getScopeFromContext(ctx)
	if scopeDef != nil {
		if err := scope.Validate(target, *scopeDef); err != nil {
			return nil, fmt.Errorf("scope violation in dnsx: %w", err)
		}
	}

	return &ToolResult{
		ToolName:  "dnsx",
		Target:    target,
		RawOutput: fmt.Sprintf("dnsx -d %s -a -aaaa -cname -resp -json", target),
		Duration:  time.Since(start),
	}, nil
}
