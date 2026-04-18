package blackboard

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// MemoryBoard is an in-process implementation of Board. Useful for tests
// and for running a campaign without a database. Not durable across restarts.
type MemoryBoard struct {
	mu       sync.RWMutex
	now      func() time.Time
	findings []Finding
	cursors  map[cursorKey]uuid.UUID
	budgets  map[uuid.UUID]Budget
	subs     []*memSub
}

type cursorKey struct {
	campaignID uuid.UUID
	agent      string
}

type memSub struct {
	ctx  context.Context
	pred Predicate
	ch   chan Finding
	last uuid.UUID
}

// NewMemoryBoard creates an empty in-process blackboard.
// now defaults to time.Now if nil — tests can inject a fake clock.
func NewMemoryBoard(now func() time.Time) *MemoryBoard {
	if now == nil {
		now = time.Now
	}
	return &MemoryBoard{
		now:     now,
		cursors: map[cursorKey]uuid.UUID{},
		budgets: map[uuid.UUID]Budget{},
	}
}

func (b *MemoryBoard) Write(ctx context.Context, f Finding, opts ...WriteOption) (uuid.UUID, error) {
	o := writeOpts{pheromoneBase: 1.0, halfLifeSec: 3600}
	if f.PheromoneBase != 0 {
		o.pheromoneBase = f.PheromoneBase
	}
	if f.HalfLifeSec != 0 {
		o.halfLifeSec = f.HalfLifeSec
	}
	for _, opt := range opts {
		opt(&o)
	}

	if f.CampaignID == uuid.Nil || f.Type == "" || f.AgentName == "" {
		return uuid.Nil, fmt.Errorf("finding requires campaign_id, type, and agent_name")
	}
	if len(f.Data) == 0 {
		f.Data = []byte(`{}`)
	}

	f.ID = uuid.New()
	f.CreatedAt = b.now()
	f.PheromoneBase = o.pheromoneBase
	f.HalfLifeSec = o.halfLifeSec

	b.mu.Lock()
	b.findings = append(b.findings, f)
	if o.supersedes != nil {
		for i := range b.findings {
			if b.findings[i].ID == *o.supersedes {
				id := f.ID
				b.findings[i].SupersededBy = &id
				break
			}
		}
	}
	// Fan out to live subscribers that match.
	for _, s := range b.subs {
		if b.matches(f, s.pred) {
			select {
			case s.ch <- b.withPheromone(f):
			default:
			}
		}
	}
	b.mu.Unlock()
	return f.ID, nil
}

func (b *MemoryBoard) Query(ctx context.Context, p Predicate) ([]Finding, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	var since time.Time
	if p.SinceID != uuid.Nil {
		for _, f := range b.findings {
			if f.ID == p.SinceID {
				since = f.CreatedAt
				break
			}
		}
	}

	out := make([]Finding, 0, len(b.findings))
	for _, f := range b.findings {
		if f.SupersededBy != nil {
			continue
		}
		if !b.matchesPredInternal(f, p, since) {
			continue
		}
		out = append(out, b.withPheromone(f))
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	if p.Limit > 0 && len(out) > p.Limit {
		out = out[:p.Limit]
	}
	return out, nil
}

func (b *MemoryBoard) Subscribe(ctx context.Context, p Predicate) (<-chan Finding, error) {
	ch := make(chan Finding, 32)
	sub := &memSub{ctx: ctx, pred: p, ch: ch, last: p.SinceID}

	b.mu.Lock()
	b.subs = append(b.subs, sub)
	// Replay any existing findings that match.
	for _, f := range b.findings {
		if f.SupersededBy != nil {
			continue
		}
		if b.matches(f, p) {
			select {
			case ch <- b.withPheromone(f):
			default:
			}
		}
	}
	b.mu.Unlock()

	go func() {
		<-ctx.Done()
		b.mu.Lock()
		defer b.mu.Unlock()
		for i, s := range b.subs {
			if s == sub {
				b.subs = append(b.subs[:i], b.subs[i+1:]...)
				close(ch)
				return
			}
		}
	}()
	return ch, nil
}

func (b *MemoryBoard) Cursor(ctx context.Context, campaignID uuid.UUID, agentName string) (uuid.UUID, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.cursors[cursorKey{campaignID, agentName}], nil
}

func (b *MemoryBoard) CommitCursor(ctx context.Context, campaignID uuid.UUID, agentName string, findingID uuid.UUID) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.cursors[cursorKey{campaignID, agentName}] = findingID
	return nil
}

func (b *MemoryBoard) Pheromone(ctx context.Context, findingID uuid.UUID) (float64, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	for _, f := range b.findings {
		if f.ID == findingID {
			return b.pheromone(f), nil
		}
	}
	return 0, fmt.Errorf("finding not found: %s", findingID)
}

func (b *MemoryBoard) Supersede(ctx context.Context, oldID, newID uuid.UUID) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	for i := range b.findings {
		if b.findings[i].ID == oldID {
			b.findings[i].SupersededBy = &newID
			return nil
		}
	}
	return fmt.Errorf("finding not found: %s", oldID)
}

func (b *MemoryBoard) Budget(ctx context.Context, campaignID uuid.UUID) (Budget, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	bud, ok := b.budgets[campaignID]
	if !ok {
		bud = Budget{CampaignID: campaignID, MaxAgentHours: 2.0, MaxTokens: 2_000_000}
		b.budgets[campaignID] = bud
	}
	return bud, nil
}

func (b *MemoryBoard) UpdateBudget(ctx context.Context, campaignID uuid.UUID, deltaHours float64, deltaTokens int64) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	bud := b.budgets[campaignID]
	if bud.CampaignID == uuid.Nil {
		bud = Budget{CampaignID: campaignID, MaxAgentHours: 2.0, MaxTokens: 2_000_000}
	}
	bud.AgentHoursUsed += deltaHours
	bud.TokensUsed += deltaTokens
	b.budgets[campaignID] = bud
	return nil
}

func (b *MemoryBoard) SetBudgetLimits(ctx context.Context, campaignID uuid.UUID, maxHours float64, maxTokens int64) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	bud := b.budgets[campaignID]
	bud.CampaignID = campaignID
	bud.MaxAgentHours = maxHours
	bud.MaxTokens = maxTokens
	b.budgets[campaignID] = bud
	return nil
}

// --- internals ---

func (b *MemoryBoard) matches(f Finding, p Predicate) bool {
	// Called with lock held.
	var since time.Time
	if p.SinceID != uuid.Nil {
		for _, ff := range b.findings {
			if ff.ID == p.SinceID {
				since = ff.CreatedAt
				break
			}
		}
	}
	return b.matchesPredInternal(f, p, since)
}

func (b *MemoryBoard) matchesPredInternal(f Finding, p Predicate, since time.Time) bool {
	if len(p.Types) > 0 {
		ok := false
		for _, t := range p.Types {
			if t == f.Type {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if p.TargetPrefix != "" && !strings.HasPrefix(f.Target, p.TargetPrefix) {
		return false
	}
	if !since.IsZero() && !f.CreatedAt.After(since) {
		return false
	}
	if p.MinPheromone > 0 && b.pheromone(f) < p.MinPheromone {
		return false
	}
	return true
}

func (b *MemoryBoard) pheromone(f Finding) float64 {
	if f.HalfLifeSec <= 0 {
		return f.PheromoneBase
	}
	age := b.now().Sub(f.CreatedAt).Seconds()
	return f.PheromoneBase * math.Pow(0.5, age/float64(f.HalfLifeSec))
}

func (b *MemoryBoard) withPheromone(f Finding) Finding {
	f.Pheromone = b.pheromone(f)
	return f
}
