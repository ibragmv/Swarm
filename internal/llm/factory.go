package llm

import (
	"context"
	"fmt"

	"github.com/Armur-Ai/autopentest/internal/config"
)

// NewProvider creates the appropriate LLM provider based on configuration.
func NewProvider(cfg config.OrchestratorConfig) (Provider, error) {
	switch cfg.Provider {
	case "claude":
		if cfg.APIKey == "" {
			return nil, fmt.Errorf("claude provider requires api_key to be set")
		}
		return NewClaudeProvider(ClaudeProviderConfig{
			APIKey:        cfg.APIKey,
			Model:         cfg.Model,
			ContextWindow: cfg.ContextWindow,
		}), nil

	case "ollama":
		endpoint := cfg.Endpoint
		if endpoint == "" {
			endpoint = "http://localhost:11434"
		}
		return NewOllamaProvider(OllamaProviderConfig{
			Endpoint:      endpoint,
			Model:         cfg.Model,
			ContextWindow: cfg.ContextWindow,
		}), nil

	case "lmstudio":
		endpoint := cfg.Endpoint
		if endpoint == "" {
			endpoint = "http://localhost:1234"
		}
		return NewLMStudioProvider(LMStudioProviderConfig{
			Endpoint:      endpoint,
			Model:         cfg.Model,
			ContextWindow: cfg.ContextWindow,
		}), nil

	default:
		return nil, fmt.Errorf("unknown provider %q — use claude, ollama, or lmstudio", cfg.Provider)
	}
}

// NewAgentProvider creates an LLM provider for a specialist agent.
// Agents always use Ollama for local model inference.
func NewAgentProvider(cfg config.AgentModelConfig) Provider {
	endpoint := cfg.Endpoint
	if endpoint == "" {
		endpoint = "http://localhost:11434"
	}
	return NewOllamaProvider(OllamaProviderConfig{
		Endpoint:      endpoint,
		Model:         cfg.Model,
		ContextWindow: 32000,
	})
}

// ValidateProvider verifies a provider is reachable and meets minimum requirements.
func ValidateProvider(ctx context.Context, p Provider) error {
	if err := p.HealthCheck(ctx); err != nil {
		return fmt.Errorf("provider health check failed: %w", err)
	}

	if p.ContextWindow() < 32000 {
		return fmt.Errorf("provider context window (%d) is below minimum 32,000 tokens", p.ContextWindow())
	}

	return nil
}
