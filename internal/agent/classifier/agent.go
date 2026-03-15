package classifier

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/Armur-Ai/autopentest/internal/llm"
	"github.com/Armur-Ai/autopentest/internal/pipeline"
	"github.com/google/uuid"
)

// ClassifierAgent enriches raw findings with CVE mappings, CVSS scores, and severity.
type ClassifierAgent struct {
	provider llm.Provider
	fpFilter *FPFilter
}

// NewClassifierAgent creates a new classifier agent.
func NewClassifierAgent(provider llm.Provider) *ClassifierAgent {
	return &ClassifierAgent{
		provider: provider,
		fpFilter: NewFPFilter(),
	}
}

// Classify takes raw findings and produces classified, scored, ranked findings.
func (c *ClassifierAgent) Classify(ctx context.Context, campaignID uuid.UUID, rawFindings []pipeline.RawFinding) (*pipeline.ClassifiedFindingSet, error) {
	var classified []pipeline.ClassifiedFinding
	filteredCount := 0

	for _, raw := range rawFindings {
		// Check false positive probability
		if c.fpFilter.ShouldFilter(raw) {
			filteredCount++
			continue
		}

		fpProb := c.fpFilter.Score(raw)

		classified = append(classified, pipeline.ClassifiedFinding{
			ID:                       uuid.New(),
			RawFindingID:             raw.ID,
			CampaignID:               campaignID,
			Title:                    raw.Detail,
			Description:              raw.Detail,
			Severity:                 pipeline.SeverityMedium, // will be updated by LLM
			Confidence:               pipeline.ConfidenceUnverified,
			FalsePositiveProbability: fpProb,
			Target:                   raw.Target,
			ClassifiedAt:             time.Now(),
		})
	}

	// Batch classify with LLM (groups of 20)
	batchSize := 20
	for i := 0; i < len(classified); i += batchSize {
		end := i + batchSize
		if end > len(classified) {
			end = len(classified)
		}

		batch := classified[i:end]
		enriched, err := c.classifyBatch(ctx, batch)
		if err != nil {
			// On LLM failure, keep the heuristic classification
			continue
		}

		// Merge LLM results back
		for j, e := range enriched {
			if i+j < len(classified) {
				classified[i+j].Title = e.Title
				classified[i+j].Description = e.Description
				classified[i+j].CVEIDs = e.CVEIDs
				classified[i+j].CVSSScore = e.CVSSScore
				classified[i+j].CVSSVector = e.CVSSVector
				classified[i+j].Severity = e.Severity
				classified[i+j].AttackCategory = e.AttackCategory
				classified[i+j].Confidence = e.Confidence
				classified[i+j].ChainCandidates = e.ChainCandidates
			}
		}
	}

	// Sort by CVSS score descending
	sort.Slice(classified, func(i, j int) bool {
		return classified[i].CVSSScore > classified[j].CVSSScore
	})

	// Build summary
	bySeverity := make(map[pipeline.Severity]int)
	categoryCount := make(map[string]int)
	for _, f := range classified {
		bySeverity[f.Severity]++
		if f.AttackCategory != "" {
			categoryCount[f.AttackCategory]++
		}
	}

	var topCategories []string
	for cat := range categoryCount {
		topCategories = append(topCategories, cat)
	}
	sort.Slice(topCategories, func(i, j int) bool {
		return categoryCount[topCategories[i]] > categoryCount[topCategories[j]]
	})
	if len(topCategories) > 5 {
		topCategories = topCategories[:5]
	}

	return &pipeline.ClassifiedFindingSet{
		CampaignID: campaignID,
		Findings:   classified,
		Summary: pipeline.ClassificationSummary{
			TotalFindings: len(classified),
			BySeverity:    bySeverity,
			TopCategories: topCategories,
			FilteredAsFP:  filteredCount,
		},
		CreatedAt: time.Now(),
	}, nil
}

// classifyBatch sends a batch of findings to the LLM for enrichment.
func (c *ClassifierAgent) classifyBatch(ctx context.Context, findings []pipeline.ClassifiedFinding) ([]pipeline.ClassifiedFinding, error) {
	findingsJSON, _ := json.Marshal(findings)

	req := llm.CompletionRequest{
		SystemPrompt: classifierSystemPrompt,
		Messages: []llm.Message{
			{
				Role: "user",
				Content: fmt.Sprintf(
					"Classify and enrich these security findings with CVE IDs, CVSS scores, severity, attack category, and confidence. Return a JSON array of classified findings.\n\n%s",
					string(findingsJSON),
				),
			},
		},
		MaxTokens:   4096,
		Temperature: 0.1,
	}

	resp, err := c.provider.Complete(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("classifier LLM call failed: %w", err)
	}

	// Parse response
	content := stripCodeFence(resp.Content)
	var enriched []pipeline.ClassifiedFinding
	if err := json.Unmarshal([]byte(content), &enriched); err != nil {
		return nil, fmt.Errorf("parsing classifier response: %w", err)
	}

	return enriched, nil
}

const classifierSystemPrompt = `You are a security vulnerability classifier. For each finding:

1. Map to relevant CVE IDs if applicable
2. Compute or assign a CVSS v3.1 score
3. Assign severity: critical (9.0-10.0), high (7.0-8.9), medium (4.0-6.9), low (0.1-3.9), informational (0.0)
4. Categorize: sqli, xss, ssrf, rce, auth_bypass, info_disclosure, misconfig, etc.
5. Assess confidence: high, medium, low, unverified
6. Identify chain candidates: which other findings could this chain with

Respond with a JSON array of classified findings. Each finding must have:
title, description, cve_ids, cvss_score, cvss_vector, severity, attack_category, confidence, chain_candidates`

func stripCodeFence(s string) string {
	s = trimString(s)
	if len(s) > 7 && s[:7] == "```json" {
		s = s[7:]
	} else if len(s) > 3 && s[:3] == "```" {
		s = s[3:]
	}
	if len(s) > 3 && s[len(s)-3:] == "```" {
		s = s[:len(s)-3]
	}
	return trimString(s)
}

func trimString(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\n' || s[0] == '\r' || s[0] == '\t') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\n' || s[len(s)-1] == '\r' || s[len(s)-1] == '\t') {
		s = s[:len(s)-1]
	}
	return s
}
