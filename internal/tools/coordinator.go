package tools

import (
	"context"
	"sync"
	"time"

	"github.com/Armur-Ai/autopentest/internal/scope"
)

// ToolRunSummary aggregates results from running multiple tools.
type ToolRunSummary struct {
	Results    []*ToolResult `json:"results"`
	TotalTime  time.Duration `json:"total_time"`
	Succeeded  int           `json:"succeeded"`
	Failed     int           `json:"failed"`
}

// Coordinator manages parallel tool execution.
type Coordinator struct {
	tools map[string]Tool
}

// NewCoordinator creates a coordinator with all registered tools.
func NewCoordinator() *Coordinator {
	c := &Coordinator{
		tools: make(map[string]Tool),
	}

	// Register all built-in tools
	allTools := []Tool{
		NewSubfinderTool(),
		NewHttpxTool(),
		NewNucleiTool(),
		NewNaabuTool(),
		NewKatanaTool(),
		NewDnsxTool(),
		NewGauTool(),
	}

	for _, t := range allTools {
		c.tools[t.Name()] = t
	}

	return c
}

// RunAll executes all tools concurrently against the target.
// Results are streamed to the results channel as each tool completes.
func (c *Coordinator) RunAll(ctx context.Context, target string, scopeDef *scope.ScopeDefinition, opts Options) (*ToolRunSummary, <-chan *ToolResult) {
	resultCh := make(chan *ToolResult, len(c.tools))
	summary := &ToolRunSummary{}

	// Attach scope to context for tool validation
	toolCtx := WithScope(ctx, scopeDef)
	start := time.Now()

	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, tool := range c.tools {
		if !tool.IsAvailable() {
			continue
		}

		wg.Add(1)
		go func(t Tool) {
			defer wg.Done()

			result, err := t.Run(toolCtx, target, opts)
			if err != nil {
				result = &ToolResult{
					ToolName: t.Name(),
					Target:   target,
					Error:    err,
				}
				mu.Lock()
				summary.Failed++
				mu.Unlock()
			} else {
				mu.Lock()
				summary.Succeeded++
				mu.Unlock()
			}

			mu.Lock()
			summary.Results = append(summary.Results, result)
			mu.Unlock()

			// Stream result as it completes
			select {
			case resultCh <- result:
			case <-ctx.Done():
			}
		}(tool)
	}

	// Close channel when all tools complete
	go func() {
		wg.Wait()
		summary.TotalTime = time.Since(start)
		close(resultCh)
	}()

	return summary, resultCh
}

// RunSelected executes only the specified tools.
func (c *Coordinator) RunSelected(ctx context.Context, toolNames []string, target string, scopeDef *scope.ScopeDefinition, opts Options) (*ToolRunSummary, <-chan *ToolResult) {
	resultCh := make(chan *ToolResult, len(toolNames))
	summary := &ToolRunSummary{}

	toolCtx := WithScope(ctx, scopeDef)
	start := time.Now()

	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, name := range toolNames {
		t, ok := c.tools[name]
		if !ok || !t.IsAvailable() {
			continue
		}

		wg.Add(1)
		go func(tool Tool) {
			defer wg.Done()

			result, err := tool.Run(toolCtx, target, opts)
			if err != nil {
				result = &ToolResult{
					ToolName: tool.Name(),
					Target:   target,
					Error:    err,
				}
				mu.Lock()
				summary.Failed++
				mu.Unlock()
			} else {
				mu.Lock()
				summary.Succeeded++
				mu.Unlock()
			}

			mu.Lock()
			summary.Results = append(summary.Results, result)
			mu.Unlock()

			select {
			case resultCh <- result:
			case <-ctx.Done():
			}
		}(t)
	}

	go func() {
		wg.Wait()
		summary.TotalTime = time.Since(start)
		close(resultCh)
	}()

	return summary, resultCh
}

// AvailableTools returns names of all registered and available tools.
func (c *Coordinator) AvailableTools() []string {
	var names []string
	for name, t := range c.tools {
		if t.IsAvailable() {
			names = append(names, name)
		}
	}
	return names
}
