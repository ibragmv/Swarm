package tools

import (
	"context"
	"fmt"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope"
)

// NaabuTool wraps naabu for port scanning.
type NaabuTool struct{}

func NewNaabuTool() *NaabuTool { return &NaabuTool{} }

func (n *NaabuTool) Name() string { return "naabu" }

func (n *NaabuTool) IsAvailable() bool { return IsCommandAvailable("naabu") }

func (n *NaabuTool) Run(ctx context.Context, target string, opts Options) (*ToolResult, error) {
	scopeDef := getScopeFromContext(ctx)
	if scopeDef != nil {
		if err := scope.Validate(target, *scopeDef); err != nil {
			return nil, fmt.Errorf("scope violation in naabu: %w", err)
		}
	}

	timeout := time.Duration(opts.GetInt("timeout", 60)) * time.Second
	ports := opts.GetString("ports", "top-1000")

	args := []string{"-host", target, "-json", "-silent", "-p", ports}

	result := RunToolCommand(ctx, "naabu", target, timeout, "naabu", args...)
	return result, result.Error
}
