package blackboard

import (
	"context"

	"github.com/google/uuid"
)

// Board is the interface every blackboard implementation must satisfy.
// Agents depend only on this interface — the Postgres backing store,
// an in-memory fake, or a future distributed store can be swapped freely.
type Board interface {
	// Write appends a finding to the blackboard. Returns the assigned ID.
	Write(ctx context.Context, f Finding, opts ...WriteOption) (uuid.UUID, error)

	// Query returns findings matching the predicate, newest first.
	// Pheromone field on each returned Finding is populated with the
	// current decayed weight.
	Query(ctx context.Context, p Predicate) ([]Finding, error)

	// Subscribe returns a channel that receives findings matching the
	// predicate as they are written. Cancellation of ctx closes the channel.
	//
	// Delivery semantics: at-least-once. Agents persist their cursor
	// (last processed ID) via CommitCursor to guarantee exactly-once
	// across restarts.
	Subscribe(ctx context.Context, p Predicate) (<-chan Finding, error)

	// Cursor returns the last-seen finding ID for an agent within a campaign.
	// Returns uuid.Nil if no cursor has been committed.
	Cursor(ctx context.Context, campaignID uuid.UUID, agentName string) (uuid.UUID, error)

	// CommitCursor persists the last-seen finding ID for an agent.
	CommitCursor(ctx context.Context, campaignID uuid.UUID, agentName string, findingID uuid.UUID) error

	// Pheromone returns the current decayed weight of a single finding.
	Pheromone(ctx context.Context, findingID uuid.UUID) (float64, error)

	// Supersede marks oldID as superseded by newID (both must exist).
	Supersede(ctx context.Context, oldID, newID uuid.UUID) error

	// Budget operations. Used by the scheduler to enforce per-campaign caps.
	Budget(ctx context.Context, campaignID uuid.UUID) (Budget, error)
	UpdateBudget(ctx context.Context, campaignID uuid.UUID, deltaHours float64, deltaTokens int64) error
	SetBudgetLimits(ctx context.Context, campaignID uuid.UUID, maxHours float64, maxTokens int64) error
}

// Budget tracks per-campaign resource usage against hard limits.
type Budget struct {
	CampaignID     uuid.UUID
	MaxAgentHours  float64
	MaxTokens      int64
	AgentHoursUsed float64
	TokensUsed     int64
}

// Exceeded reports whether this budget has blown any limit.
func (b Budget) Exceeded() bool {
	return b.AgentHoursUsed >= b.MaxAgentHours || b.TokensUsed >= b.MaxTokens
}

// Remaining returns the headroom on each dimension.
func (b Budget) Remaining() (hours float64, tokens int64) {
	return b.MaxAgentHours - b.AgentHoursUsed, b.MaxTokens - b.TokensUsed
}
