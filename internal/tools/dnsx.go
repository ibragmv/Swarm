package tools

import (
	"context"
	"fmt"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope"
)

// DnsxTool wraps dnsx for DNS resolution and reverse lookups.
type DnsxTool struct{}

func NewDnsxTool() *DnsxTool { return &DnsxTool{} }

func (d *DnsxTool) Name() string { return "dnsx" }

func (d *DnsxTool) IsAvailable() bool { return IsCommandAvailable("dnsx") }

func (d *DnsxTool) Run(ctx context.Context, target string, opts Options) (*ToolResult, error) {
	scopeDef := getScopeFromContext(ctx)
	if scopeDef != nil {
		if err := scope.ValidateAndLog("dnsx", target, *scopeDef); err != nil {
			return nil, fmt.Errorf("scope violation in dnsx: %w", err)
		}
	}

	timeout := time.Duration(opts.GetInt("timeout", 30)) * time.Second

	args := []string{"-d", target, "-json", "-silent", "-a", "-aaaa", "-cname", "-resp"}

	result := RunToolCommand(ctx, "dnsx", target, timeout, "dnsx", args...)
	return result, result.Error
}
