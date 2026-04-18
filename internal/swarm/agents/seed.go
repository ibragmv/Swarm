// Package agents contains the swarm adapters that bridge the existing
// specialist agents (recon, classifier, exploit, report) into the
// blackboard + scheduler model. Each adapter implements swarm.Agent.
package agents

import (
	"context"
	"encoding/json"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/swarm/blackboard"
	"github.com/google/uuid"
)

// Seed writes the initial TARGET_REGISTERED finding that kicks the swarm off.
// Without a seed there is nothing on the board, so no trigger fires.
func Seed(ctx context.Context, board blackboard.Board, campaignID uuid.UUID, target, objective string) error {
	data, _ := json.Marshal(map[string]any{
		"target":    target,
		"objective": objective,
	})
	_, err := board.Write(ctx, blackboard.Finding{
		CampaignID:    campaignID,
		AgentName:     "engine",
		Type:          blackboard.TypeTargetRegistered,
		Target:        target,
		Data:          data,
		PheromoneBase: 1.0,
		HalfLifeSec:   86400, // targets stay hot for a full day
	})
	return err
}
