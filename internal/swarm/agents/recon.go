package agents

import (
	"context"
	"encoding/json"
	"fmt"

	reconpkg "github.com/Armur-Ai/Pentest-Swarm-AI/internal/agent/recon"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/scope"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/swarm/blackboard"
	"github.com/google/uuid"
)

// ReconAgent wakes on TARGET_REGISTERED and publishes one finding per
// discovered subdomain / port / endpoint / technology. Batched tool
// execution is retained inside the underlying recon agent — the swarm
// value is that downstream agents can react to each finding independently,
// without waiting for the full surface to be assembled.
type ReconAgent struct {
	recon      *reconpkg.ReconAgent
	scopeDef   *scope.ScopeDefinition
	campaignID uuid.UUID
	parallel   int
}

// NewReconAgent constructs a swarm wrapper around the existing recon agent.
func NewReconAgent(inner *reconpkg.ReconAgent, scopeDef *scope.ScopeDefinition, campaignID uuid.UUID, parallel int) *ReconAgent {
	if parallel <= 0 {
		parallel = 1
	}
	return &ReconAgent{recon: inner, scopeDef: scopeDef, campaignID: campaignID, parallel: parallel}
}

// Name implements swarm.Agent.
func (a *ReconAgent) Name() string { return "recon" }

// Trigger implements swarm.Agent — recon wakes on newly-registered targets.
func (a *ReconAgent) Trigger() blackboard.Predicate {
	return blackboard.Predicate{Types: []blackboard.FindingType{blackboard.TypeTargetRegistered}}
}

// MaxConcurrency implements swarm.Agent.
func (a *ReconAgent) MaxConcurrency() int { return a.parallel }

// Handle runs recon against the target and fans out findings to the blackboard.
func (a *ReconAgent) Handle(ctx context.Context, f blackboard.Finding, board blackboard.Board) error {
	plan := a.recon.PlanRecon(f.Target)
	surface, err := a.recon.Execute(ctx, plan, a.scopeDef, a.campaignID)
	if err != nil {
		return fmt.Errorf("recon execute: %w", err)
	}

	write := func(t blackboard.FindingType, target string, payload any, pheromone float64, halfLife int) {
		data, _ := json.Marshal(payload)
		_, _ = board.Write(ctx, blackboard.Finding{
			CampaignID:    a.campaignID,
			AgentName:     a.Name(),
			Type:          t,
			Target:        target,
			Data:          data,
			PheromoneBase: pheromone,
			HalfLifeSec:   halfLife,
		})
	}

	for _, sd := range surface.Subdomains {
		write(blackboard.TypeSubdomain, sd.Domain, sd, 0.7, 7200)
	}
	for _, host := range surface.Hosts {
		for _, port := range host.OpenPorts {
			write(blackboard.TypePortOpen, fmt.Sprintf("%s:%d", host.IP, port),
				map[string]any{"ip": host.IP, "port": port, "service": host.Services[port]},
				0.8, 3600)
			if svc, ok := host.Services[port]; ok && svc.Name != "" {
				write(blackboard.TypeService, fmt.Sprintf("%s:%d/%s", host.IP, port, svc.Name),
					svc, 0.8, 3600)
			}
		}
	}
	for _, ep := range surface.Endpoints {
		pheromone := 0.6
		if ep.Interesting {
			pheromone = 0.9
		}
		write(blackboard.TypeHTTPEndpoint, ep.URL, ep, pheromone, 7200)
	}
	for tech, version := range surface.Technologies {
		write(blackboard.TypeTechnology, tech,
			map[string]string{"technology": tech, "version": version}, 0.5, 7200)
	}

	return nil
}
