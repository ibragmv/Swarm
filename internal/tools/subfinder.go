package tools

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope"
)

// SubfinderTool wraps subfinder for passive subdomain discovery.
type SubfinderTool struct{}

func NewSubfinderTool() *SubfinderTool { return &SubfinderTool{} }

func (s *SubfinderTool) Name() string { return "subfinder" }

func (s *SubfinderTool) IsAvailable() bool { return true }

func (s *SubfinderTool) Run(ctx context.Context, target string, opts Options) (*ToolResult, error) {
	start := time.Now()

	// Scope validation
	scopeDef := getScopeFromContext(ctx)
	if scopeDef != nil {
		if err := scope.Validate(target, *scopeDef); err != nil {
			return nil, fmt.Errorf("scope violation in subfinder: %w", err)
		}
	}

	// In production, this calls subfinder as a Go library:
	//   runner, _ := subfinder.NewRunner(&runner.Options{...})
	//   results := runner.EnumerateMultipleDomains(ctx, []string{target})
	//
	// For now, return a placeholder result that follows the correct structure.
	// The actual library integration will replace this body when we add
	// the projectdiscovery dependency.

	result := &ToolResult{
		ToolName:  "subfinder",
		Target:    target,
		RawOutput: fmt.Sprintf("subfinder -d %s -silent", target),
		Duration:  time.Since(start),
	}

	return result, nil
}

// getScopeFromContext extracts scope definition from context.
// This is set by the coordinator before running any tool.
func getScopeFromContext(ctx context.Context) *scope.ScopeDefinition {
	if v := ctx.Value(scopeContextKey); v != nil {
		if s, ok := v.(*scope.ScopeDefinition); ok {
			return s
		}
	}
	return nil
}

type contextKeyType string

const scopeContextKey contextKeyType = "scope"

// WithScope returns a context with scope attached for tool validation.
func WithScope(ctx context.Context, s *scope.ScopeDefinition) context.Context {
	return context.WithValue(ctx, scopeContextKey, s)
}

// splitLines splits output by newlines, filtering empty lines.
func splitLines(s string) []string {
	var lines []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}
