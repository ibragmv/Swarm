package tools

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// RunCommand executes a shell command and returns the output.
// This is the fallback for tools not available as Go libraries.
func RunCommand(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		// Include stderr in error for debugging
		if stderr.Len() > 0 {
			return stdout.String(), fmt.Errorf("%s: %w (stderr: %s)", name, err, stderr.String())
		}
		return stdout.String(), fmt.Errorf("%s: %w", name, err)
	}

	return stdout.String(), nil
}

// IsCommandAvailable checks if a command exists in PATH.
func IsCommandAvailable(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// RunToolCommand runs a security tool with timeout and returns a ToolResult.
func RunToolCommand(ctx context.Context, toolName, target string, timeout time.Duration, cmdName string, args ...string) *ToolResult {
	start := time.Now()

	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	output, err := RunCommand(ctx, cmdName, args...)

	result := &ToolResult{
		ToolName: toolName,
		Target:   target,
		Duration: time.Since(start),
	}

	if err != nil {
		result.Error = err
		result.RawOutput = output // may have partial output
		return result
	}

	result.RawOutput = output

	// Try to parse JSON lines from output
	result.ParsedFindings = parseJSONLines(output)

	return result
}

// parseJSONLines extracts JSON objects from newline-delimited output.
func parseJSONLines(output string) []map[string]any {
	var findings []map[string]any
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] != '{' {
			continue
		}
		// Simple check — in production, use json.Unmarshal
		findings = append(findings, map[string]any{"raw": line})
	}
	return findings
}
