package plugins

import (
	"context"
	"fmt"
	"strings"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/config"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/engine"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/pipeline"
)

// PlaybookRunner executes a playbook using the campaign engine.
type PlaybookRunner struct {
	cfg *config.Config
}

// NewPlaybookRunner creates a playbook runner.
func NewPlaybookRunner(cfg *config.Config) *PlaybookRunner {
	return &PlaybookRunner{cfg: cfg}
}

// Run executes a playbook against a target.
func (r *PlaybookRunner) Run(ctx context.Context, pb *Playbook, target string, variables map[string]string, onEvent engine.EventCallback) error {
	// Resolve variables
	for key, v := range pb.Variables {
		if _, ok := variables[key]; !ok && v.Required {
			if v.Default != "" {
				variables[key] = v.Default
			} else {
				return fmt.Errorf("required variable %q not provided", key)
			}
		}
	}

	// Build objective from playbook phases
	var objectives []string
	for _, phase := range pb.Phases {
		desc := phase.Name
		if phase.PostAnalysis != "" {
			desc += ": " + strings.TrimSpace(phase.PostAnalysis)
		}
		if phase.Strategy != "" {
			desc += " Strategy: " + strings.TrimSpace(phase.Strategy)
		}
		objectives = append(objectives, desc)
	}

	objective := fmt.Sprintf("Execute playbook '%s': %s", pb.Name, strings.Join(objectives, " → "))

	// Build scope from target
	scope := []string{target}
	if targetVar, ok := variables["target_domain"]; ok {
		scope = []string{targetVar}
	}

	cc := engine.CampaignConfig{
		Target:    target,
		Scope:     scope,
		Objective: objective,
		Mode:      "manual",
		Format:    "md",
		OutputDir: "./reports",
	}

	if onEvent != nil {
		onEvent(pipeline.CampaignEvent{
			EventType: pipeline.EventThought,
			AgentName: "playbook",
			Detail:    fmt.Sprintf("Running playbook: %s by %s", pb.Name, pb.Author.Name),
		})
	}

	runner := engine.NewRunner(r.cfg)
	return runner.Run(ctx, cc, onEvent)
}
