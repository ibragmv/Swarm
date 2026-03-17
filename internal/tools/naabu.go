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

func (n *NaabuTool) IsAvailable() bool { return true }

func (n *NaabuTool) Run(ctx context.Context, target string, opts Options) (*ToolResult, error) {
	start := time.Now()

	scopeDef := getScopeFromContext(ctx)
	if scopeDef != nil {
		if err := scope.Validate(target, *scopeDef); err != nil {
			return nil, fmt.Errorf("scope violation in naabu: %w", err)
		}
	}

	ports := opts.GetString("ports", "top-1000")

	return &ToolResult{
		ToolName:  "naabu",
		Target:    target,
		RawOutput: fmt.Sprintf("naabu -host %s -p %s -json", target, ports),
		Duration:  time.Since(start),
	}, nil
}
