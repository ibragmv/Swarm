package ctf

import (
	"context"
	"fmt"
	"time"
)

// Flag represents a captured CTF flag.
type Flag struct {
	Type   string `json:"type"` // user, root
	Value  string `json:"value"`
	Path   string `json:"path"`
	Method string `json:"method"`
}

// CTFResult holds the outcome of a CTF solve attempt.
type CTFResult struct {
	Flags          []Flag        `json:"flags"`
	AttackNarrative string       `json:"attack_narrative"`
	Writeup        string        `json:"writeup"`
	TimeElapsed    time.Duration `json:"time_elapsed"`
	Success        bool          `json:"success"`
}

// Solver orchestrates autonomous CTF machine solving.
type Solver struct {
	platform string // htb, thm, generic
}

// NewSolver creates a new CTF solver.
func NewSolver(platform string) *Solver {
	return &Solver{platform: platform}
}

// Solve attempts to capture all flags on a CTF machine.
func (s *Solver) Solve(ctx context.Context, target, machineName string) (*CTFResult, error) {
	start := time.Now()

	result := &CTFResult{}

	// The solver uses the orchestrator with CTF-specific prompts and objectives:
	// 1. Objective: "Find all flags (user.txt and root.txt)"
	// 2. CTF-tuned instructions: focus on privesc, common CTF patterns
	// 3. Flag validation: check format, record path and method

	// TODO: Wire to orchestrator with CTF-specific system prompt
	_ = target
	_ = machineName

	result.TimeElapsed = time.Since(start)
	return result, nil
}

// GenerateWriteup creates a standard CTF writeup from the solve result.
func GenerateWriteup(machineName, platform string, result *CTFResult) string {
	w := fmt.Sprintf("# %s — %s Writeup\n\n", machineName, platform)
	w += fmt.Sprintf("**Time:** %s\n\n", result.TimeElapsed.Round(time.Second))
	w += "## Enumeration\n\n(auto-generated from scan results)\n\n"
	w += "## Initial Foothold\n\n(auto-generated from attack narrative)\n\n"
	w += "## Privilege Escalation\n\n(auto-generated from attack narrative)\n\n"
	w += "## Flags\n\n"

	for _, f := range result.Flags {
		w += fmt.Sprintf("- **%s**: `%s` (via %s at %s)\n", f.Type, f.Value, f.Method, f.Path)
	}

	if len(result.Flags) == 0 {
		w += "No flags captured.\n"
	}

	return w
}
