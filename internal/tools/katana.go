package tools

import (
	"context"
	"fmt"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope"
)

// KatanaTool wraps katana for web crawling and endpoint discovery.
type KatanaTool struct{}

func NewKatanaTool() *KatanaTool { return &KatanaTool{} }

func (k *KatanaTool) Name() string { return "katana" }

func (k *KatanaTool) IsAvailable() bool { return true }

func (k *KatanaTool) Run(ctx context.Context, target string, opts Options) (*ToolResult, error) {
	start := time.Now()

	scopeDef := getScopeFromContext(ctx)
	if scopeDef != nil {
		if err := scope.Validate(target, *scopeDef); err != nil {
			return nil, fmt.Errorf("scope violation in katana: %w", err)
		}
	}

	depth := opts.GetInt("depth", 3)

	return &ToolResult{
		ToolName:  "katana",
		Target:    target,
		RawOutput: fmt.Sprintf("katana -u %s -d %d -json -js-crawl", target, depth),
		Duration:  time.Since(start),
	}, nil
}
