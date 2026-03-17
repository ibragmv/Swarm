package tools

import (
	"context"
	"fmt"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope"
)

// HttpxTool wraps httpx for HTTP probing and technology detection.
type HttpxTool struct{}

func NewHttpxTool() *HttpxTool { return &HttpxTool{} }

func (h *HttpxTool) Name() string { return "httpx" }

func (h *HttpxTool) IsAvailable() bool { return true }

func (h *HttpxTool) Run(ctx context.Context, target string, opts Options) (*ToolResult, error) {
	start := time.Now()

	scopeDef := getScopeFromContext(ctx)
	if scopeDef != nil {
		if err := scope.Validate(target, *scopeDef); err != nil {
			return nil, fmt.Errorf("scope violation in httpx: %w", err)
		}
	}

	// In production, this calls httpx as a Go library:
	//   runner, _ := httpx.New(&httpx.Options{...})
	//   results := runner.Run(targets)
	//
	// Placeholder for now.

	return &ToolResult{
		ToolName:  "httpx",
		Target:    target,
		RawOutput: fmt.Sprintf("httpx -u %s -json -tech-detect -status-code -title", target),
		Duration:  time.Since(start),
	}, nil
}
