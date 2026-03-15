# Auto-Pentest-GPT-AI
### Autonomous AI-Powered Penetration Testing Platform

> A multi-agent AI system built in Go that autonomously performs full-cycle penetration tests — from continuous recon through exploitation through professional reporting — powered by four specialized fine-tuned open source models coordinated by an orchestrator agent.

---

## Vision

Most security tools collect data or execute commands. None of them *think*. Auto-Pentest-GPT-AI is the first Go-native platform built around a multi-agent AI architecture where each agent is a specialist — fine-tuned on a best-in-class open source model for its specific task — coordinated by an orchestrator that plans the campaign, adapts in real-time, and produces evidence-backed findings.

**What makes this different from every existing tool:**
- Four proprietary fine-tuned models purpose-built for security tasks (not general LLMs with a system prompt)
- Go-native: single binary, fast, concurrent, ships as `brew install`
- Continuous ASM: watches your scope, detects new assets, auto-triggers targeted tests
- Bug bounty workflow: reads HackerOne/Bugcrowd scope, avoids duplicate submissions, generates program-compliant reports
- Full privacy: runs 100% locally with Ollama — nothing leaves your machine

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                     DISTRIBUTION LAYER                            │
│   brew install | curl install.sh | docker compose | npx           │
└───────────────────────────────┬──────────────────────────────────┘
                                 │
┌───────────────────────────────▼──────────────────────────────────┐
│                      Go CLI (Cobra)                               │
│   autopentest scan | campaign | watch | report | doctor           │
└───────────────────────────────┬──────────────────────────────────┘
                                 │ HTTP/WebSocket
┌───────────────────────────────▼──────────────────────────────────┐
│                   Go Backend (single binary)                      │
│                                                                   │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │                  ORCHESTRATOR AGENT                          │ │
│  │         Claude API  OR  Large Local LLM via Ollama           │ │
│  │  ReAct loop · Campaign planning · Agent coordination         │ │
│  └────────┬──────────┬──────────┬──────────┬───────────────────┘ │
│           │          │          │          │                      │
│           ▼          ▼          ▼          ▼                      │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐           │
│  │  RECON   │ │CLASSIFIER│ │ EXPLOIT  │ │  REPORT  │           │
│  │  AGENT   │ │  AGENT   │ │  AGENT   │ │  AGENT   │           │
│  │ Qwen 2.5 │ │Mistral 7B│ │DeepSeek  │ │Llama 3.1 │           │
│  │   7B     │ │fine-tuned│ │R1 8B     │ │  8B      │           │
│  │fine-tuned│ │          │ │fine-tuned│ │fine-tuned│           │
│  └────┬─────┘ └──────────┘ └──────────┘ └──────────┘           │
│       │                                                           │
│       ▼  (native Go libraries, no subprocess)                    │
│  subfinder · httpx · nuclei · naabu · katana · dnsx · gau        │
│                                                                   │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  Continuous ASM Engine                                    │   │
│  │  scope watcher · asset diff · auto-trigger               │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                   │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  Bug Bounty Workflow                                      │   │
│  │  HackerOne API · Bugcrowd API · dedup · report format    │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                   │
│  FastHTTP API · PostgreSQL + pgvector · Redis · Docker API        │
└──────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────┐
│              React + TypeScript Web Dashboard                     │
│   Live agent thoughts · Attack surface map · Campaign history    │
└──────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────┐
│                    EXTENSION LAYER                                │
│                                                                   │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────────────────┐ │
│  │ MCP Server   │ │ GitHub Action│ │ Plugin System             │ │
│  │ Claude Desktop│ │ CI/CD scans │ │ YAML playbooks · custom  │ │
│  │ Cursor · IDEs│ │ per PR/push  │ │ tools · report templates │ │
│  └──────────────┘ └──────────────┘ └──────────────────────────┘ │
│                                                                   │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────────────────┐ │
│  │ CTF Mode     │ │ Integrations │ │ Agent Memory              │ │
│  │ HTB · THM    │ │ Jira · Slack │ │ Cross-engagement learning│ │
│  │ auto-solve   │ │ SIEM · SOAR  │ │ per-user intelligence    │ │
│  └──────────────┘ └──────────────┘ └──────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────┐
│         Python (offline · separate · one-time only)              │
│   Fine-tuning pipeline → ArmurAI/* on HuggingFace Hub           │
└──────────────────────────────────────────────────────────────────┘
```

---

## Agent Roster

| Agent | Model | Role |
|---|---|---|
| **Orchestrator** | Claude API or large local LLM (user's choice) | Plans campaign, coordinates agents, synthesizes results, adapts to findings |
| **Recon Agent** | `ArmurAI/recon-agent-qwen2.5-7b` | Runs and interprets recon tools, builds structured attack surface model |
| **Classifier Agent** | `ArmurAI/classifier-agent-mistral-7b` | Maps findings to CVEs, CVSS scoring, false positive filtering, severity ranking |
| **Exploit Agent** | `ArmurAI/exploit-agent-deepseek-r1-8b` | Constructs multi-step attack chains, suggests exploitation techniques, adapts on feedback |
| **Report Agent** | `ArmurAI/report-agent-llama3.1-8b` | Generates professional pentest reports in multiple formats |

---

## Technology Stack

| Component | Technology | Reason |
|---|---|---|
| Platform language | Go 1.22 | Single binary, goroutine concurrency, native security tool libraries |
| Agent framework | Custom (~400 lines) | Full control, no framework overhead, cleaner architecture |
| LLM — Claude | `anthropic-sdk-go` | Official Go SDK |
| LLM — Local | Ollama REST API (`/api/chat`) | Standard local model serving |
| Security tools | Native Go libraries | subfinder, httpx, nuclei, naabu, katana — no subprocess overhead |
| API | `fasthttp` + `fiber` | High performance HTTP |
| Real-time | WebSocket (gorilla/websocket) | Agent thought streaming to CLI + UI |
| Database | PostgreSQL 16 + pgvector | Campaign history + semantic search |
| Cache | Redis 7 | Session state, rate limiting |
| Container execution | Docker API (docker/docker client-go) | Isolated tool execution |
| Web dashboard | React 18 + TypeScript + shadcn/ui | Clean, fast, embeddable |
| CLI | Cobra + lipgloss + bubbletea | Beautiful terminal UI |
| Fine-tuning | Python + Unsloth + QLoRA | Offline, GPU machine only |
| Model hosting | HuggingFace Hub (`ArmurAI` org) | Consistent with existing `ArmurAI/Pentest_AI` |
| Distribution | Homebrew + Docker Compose + npx + pip SDK | All tiers covered |

---

## Repository Structure

```
auto-pentest-gpt-ai/
├── cmd/
│   └── autopentest/
│       └── main.go              # CLI entrypoint
├── internal/
│   ├── agent/
│   │   ├── orchestrator/        # Orchestrator ReAct loop
│   │   │   ├── agent.go
│   │   │   ├── planner.go
│   │   │   ├── coordinator.go
│   │   │   └── memory.go
│   │   ├── recon/               # Recon agent
│   │   │   ├── agent.go
│   │   │   └── parser.go
│   │   ├── classifier/          # Classifier agent
│   │   │   ├── agent.go
│   │   │   ├── cve.go
│   │   │   └── scorer.go
│   │   ├── exploit/             # Exploit agent
│   │   │   ├── agent.go
│   │   │   ├── pathbuilder.go
│   │   │   └── executor.go
│   │   └── report/              # Report agent
│   │       ├── agent.go
│   │       └── renderer.go
│   ├── llm/
│   │   ├── provider.go          # LLMProvider interface
│   │   ├── claude.go            # Anthropic SDK
│   │   ├── ollama.go            # Ollama REST
│   │   └── lmstudio.go          # LM Studio OpenAI-compat
│   ├── tools/                   # Native Go security tool wrappers
│   │   ├── subfinder.go
│   │   ├── httpx.go
│   │   ├── nuclei.go
│   │   ├── naabu.go
│   │   ├── katana.go
│   │   ├── dnsx.go
│   │   └── gau.go
│   ├── pipeline/
│   │   ├── campaign.go          # Campaign state machine
│   │   ├── context.go           # Shared campaign context + data models
│   │   └── cleanup.go           # Cleanup registry
│   ├── asm/
│   │   ├── watcher.go           # Continuous ASM scope watcher
│   │   ├── diff.go              # Asset diff engine
│   │   └── trigger.go           # Auto-campaign trigger
│   ├── bugbounty/
│   │   ├── hackerone.go         # HackerOne API client
│   │   ├── bugcrowd.go          # Bugcrowd API client
│   │   ├── dedup.go             # Duplicate finding detection
│   │   └── formatter.go         # Program-compliant report format
│   ├── plugins/
│   │   ├── loader.go            # Plugin discovery & loading
│   │   ├── playbook.go          # YAML playbook parser & executor
│   │   ├── registry.go          # Community playbook registry client
│   │   └── types.go             # Plugin interfaces
│   ├── memory/
│   │   ├── store.go             # Cross-engagement memory store
│   │   ├── patterns.go          # Attack pattern learning
│   │   └── embeddings.go        # Semantic memory with pgvector
│   ├── mcp/
│   │   ├── server.go            # MCP protocol server
│   │   ├── tools.go             # MCP tool definitions
│   │   └── resources.go         # MCP resource providers
│   ├── ctf/
│   │   ├── solver.go            # CTF auto-solve orchestration
│   │   ├── platforms.go         # HTB/THM API clients
│   │   └── writeup.go           # Auto-writeup generation
│   ├── integrations/
│   │   ├── jira.go              # Jira issue creation
│   │   ├── slack.go             # Slack notifications & bot
│   │   ├── siem.go              # SIEM event forwarding
│   │   └── webhook.go           # Generic webhook integration
│   ├── scope/
│   │   ├── validator.go         # Target scope validation
│   │   └── auth.go              # Authorization tokens
│   ├── api/
│   │   ├── server.go            # Fiber HTTP server
│   │   ├── routes.go
│   │   ├── handlers/
│   │   └── ws/                  # WebSocket hub
│   ├── db/
│   │   ├── postgres.go
│   │   ├── migrations/
│   │   └── queries/             # sqlc-generated query code
│   └── config/
│       └── config.go            # Config loading + validation
├── cli/
│   ├── root.go
│   ├── campaign.go
│   ├── scan.go
│   ├── report.go
│   ├── models.go
│   ├── doctor.go
│   ├── explain.go               # Explain findings in plain English
│   ├── ctf.go                   # CTF mode commands
│   ├── plugins.go               # Plugin management commands
│   └── ui/                      # bubbletea TUI components
├── playbooks/                   # Community attack playbooks (YAML)
│   ├── aws-cloud-audit.yaml
│   ├── oauth2-assessment.yaml
│   ├── api-security.yaml
│   ├── wordpress-full.yaml
│   └── README.md                # How to write & contribute playbooks
├── web/                         # React dashboard
│   ├── src/
│   │   ├── pages/
│   │   ├── components/
│   │   └── hooks/
│   └── dist/                    # Built assets, embedded in Go binary
├── training/                    # Python fine-tuning (offline)
│   ├── generate_data.py
│   ├── train_recon.py
│   ├── train_classifier.py
│   ├── train_exploit.py
│   └── train_report.py
├── data/                        # Synthetic training datasets
│   ├── recon/
│   ├── classifier/
│   ├── exploit/
│   └── report/
├── docs/                        # Documentation
│   ├── quickstart.md
│   ├── architecture.md
│   ├── cli-reference.md
│   ├── api-reference.md
│   ├── configuration.md
│   ├── providers.md
│   ├── bug-bounty.md
│   ├── continuous-asm.md
│   └── fine-tuning.md
├── deploy/
│   ├── docker-compose.yml
│   ├── docker-compose.gpu.yml
│   ├── helm/
│   └── homebrew/
├── tests/
│   ├── unit/
│   ├── integration/
│   └── e2e/
├── .github/
│   └── workflows/
│       ├── ci.yml
│       └── release.yml
├── Makefile
├── go.mod
├── go.sum
├── config.example.yaml
└── README.md
```

---

## Campaign Flow

```
1.  User: target + objective + scope
2.  Orchestrator: plan campaign, set milestones
3.  Recon Agent: run tools natively (subfinder, httpx, nuclei, naabu, katana, dnsx, gau)
                 → analyze output → return AttackSurface
4.  Classifier Agent: map CVEs, score CVSS, filter false positives
                      → return ClassifiedFindingSet
5.  Orchestrator: review findings, select attack paths
6.  Exploit Agent: build ranked AttackPlan with chain-of-thought reasoning
7.  Orchestrator: execute steps → feed results back → Exploit Agent adapts
8.  Loop until objective reached or all paths exhausted
9.  Report Agent: generate professional report (PDF/HTML/Markdown/JSON)
10. [If bug bounty mode]: format for program, dedup, submit or export
11. [If ASM mode]: schedule next scan, diff against previous, alert on new findings
```

---

## Sprint Plan

---

### Sprint 0 — Project Foundation & Developer Experience
**Duration:** 1 week
**Goal:** Clean professional Go project that any engineer can clone and run in under 10 minutes. Every structural and tooling decision locked in before a line of product code is written.

**Why this sprint matters:** We're replacing a single Python file with a production Go platform. Getting the structure, tooling, and conventions right now prevents accumulating technical debt that compounds across every subsequent sprint.

#### 0.1 Repository Cleanup
- Move `PentestAI.py` → `legacy/PentestAI.py` with a comment at the top explaining it is the original prototype
- Move `Pentest_LLM.gguf` reference → `legacy/README.md` documenting the original model approach
- Move `requirement.txt` → `legacy/requirements.txt`
- Create root `.gitignore` covering: Go binaries, `.env`, `config.yaml`, `*.gguf`, `node_modules`, `dist`, `__pycache__`, `.DS_Store`
- Create root `LICENSE` (Apache 2.0) with correct copyright header

#### 0.2 Go Project Initialization
- Initialize Go module: `go mod init github.com/Armur-Ai/auto-pentest-gpt-ai`
- Create full directory structure as defined in Repository Structure above — all directories with `.gitkeep` files
- Write root `go.mod` with Go 1.22 minimum version
- Add initial dependencies to `go.mod`:
  - `github.com/spf13/cobra` — CLI framework
  - `github.com/gofiber/fiber/v2` — HTTP server
  - `github.com/gorilla/websocket` — WebSocket
  - `github.com/charmbracelet/bubbletea` — terminal UI
  - `github.com/charmbracelet/lipgloss` — terminal styling
  - `github.com/anthropics/anthropic-sdk-go` — Claude API
  - `github.com/jackc/pgx/v5` — PostgreSQL driver
  - `github.com/redis/go-redis/v9` — Redis client
  - `github.com/spf13/viper` — config management
  - `go.uber.org/zap` — structured logging
  - `github.com/stretchr/testify` — test assertions

#### 0.3 Code Quality Tooling
- Create `.golangci.yml` with linters enabled: `errcheck`, `gosimple`, `govet`, `ineffassign`, `staticcheck`, `unused`, `gofmt`, `goimports`, `misspell`, `gocritic`
- Create `Makefile` with targets:
  - `make build` — compile binary to `./bin/autopentest`
  - `make dev` — start full local stack via docker compose + run binary with hot reload via `air`
  - `make test` — run unit tests with race detector (`go test -race ./...`)
  - `make test-integration` — run integration tests (requires running services)
  - `make lint` — run golangci-lint
  - `make fmt` — run gofmt + goimports
  - `make generate` — run sqlc generate + any other code generation
  - `make docs` — generate API docs from code
  - `make clean` — remove build artifacts
- Create `.air.toml` for hot reload during development (Air tool)
- Set up pre-commit hooks: `golangci-lint`, `gofmt` check, `go mod tidy` check, `detect-secrets`

#### 0.4 Configuration System (`internal/config/config.go`)
- Define `Config` struct with all configuration fields, grouped by section:
  ```go
  type Config struct {
      Server      ServerConfig
      Database    DatabaseConfig
      Redis       RedisConfig
      Orchestrator OrchestratorConfig  // provider + model + api key
      Agents      AgentsConfig         // per-agent model endpoints
      Tools       ToolsConfig          // tool timeouts, flags, wordlists
      Scope       ScopeConfig          // default scope settings
      ASM         ASMConfig            // continuous ASM settings
      BugBounty   BugBountyConfig      // HackerOne/Bugcrowd API keys
  }
  ```
- Implement `Load(path string) (*Config, error)` using Viper: reads from `config.yaml` file, overridable via env vars prefixed `AUTOPENTEST_`
- Implement `Validate(c *Config) error`: checks all required fields are set, URLs are valid, model names are non-empty
- Write `config.example.yaml`: every field documented with inline comments explaining purpose, valid values, and default

#### 0.5 Structured Logging (`internal/logger/logger.go`)
- Initialize `go.uber.org/zap` in production mode (JSON output) or development mode (human-readable), switchable via config
- Implement `WithCampaignID(ctx, id)`, `WithAgentName(ctx, name)`, `WithTechnique(ctx, technique)` context propagation helpers
- Every log line in the application must carry: `campaign_id` (if in a campaign), `agent` (if in an agent), `level`, `timestamp`, `message`

#### 0.6 Error Types (`internal/errors/errors.go`)
- Define sentinel errors: `ErrScopeViolation`, `ErrAuthRequired`, `ErrAgentFailed`, `ErrToolNotFound`, `ErrModelUnavailable`, `ErrCampaignAborted`, `ErrRateLimitExceeded`
- Implement `WrapToolError(tool, err)`, `WrapAgentError(agent, err)` for structured error context
- All errors implement `error` interface and carry structured fields for logging

#### 0.7 Local Development Environment
- Write `deploy/docker-compose.dev.yml`: PostgreSQL 16, Redis 7, Ollama (with model pull on startup), the Go API server (compiled binary, mounted from `./bin/`), the React dev server (Vite)
- Write `deploy/docker-compose.test.yml`: isolated services for integration testing, ephemeral volumes
- Write `scripts/setup.sh`: installs Go tooling (air, sqlc, golangci-lint), runs `docker compose up -d`, waits for services healthy, runs DB migrations, seeds test data
- Write `scripts/seed.go`: creates 2 test campaigns with mock data, 1 test environment, 2 test API keys

#### 0.8 Scope Enforcement (Build Before Anything Else)
- Implement `internal/scope/validator.go`:
  - `ScopeDefinition` struct: `AllowedCIDRs []string`, `AllowedDomains []string`, `AllowedPorts []int`
  - `func Validate(target string, scope ScopeDefinition) error`: parses target as IP or domain, checks against each CIDR/domain in scope, returns `ErrScopeViolation` with target and scope details if not allowed
  - `func ValidateCommand(cmd string, scope ScopeDefinition) error`: extracts all IPs and domains from a command string using regex, validates each — rejects the command if any target is out of scope
  - **This function is called by every tool wrapper and executor before running. No exceptions.**
- Write `tests/unit/scope_test.go`: table-driven tests covering in-scope IP, out-of-scope IP, in-scope domain, out-of-scope domain, CIDR boundary cases

#### 0.9 CI Pipeline (`.github/workflows/ci.yml`)
- Trigger: every PR and push to `main`
- Jobs (run in parallel where independent):
  - `lint`: run golangci-lint
  - `test`: run `go test -race ./...`, upload coverage to Codecov
  - `build`: compile binary for Linux amd64, verify it runs `--version`
  - `docker`: build Docker image, verify it starts

**Acceptance Criteria:**
- [ ] `git clone && make dev` produces a running local stack with zero manual steps
- [ ] `make test` runs and passes (even with empty test suites)
- [ ] `make lint` passes with zero warnings
- [ ] `config.example.yaml` documents every config field
- [ ] Calling `scope.Validate("192.168.99.1", scope)` against a scope of `10.0.0.0/24` returns `ErrScopeViolation`
- [ ] CI pipeline runs green on a new PR

**Dependencies:** None

---

### Sprint 1 — LLM Provider Abstraction
**Duration:** 1 week
**Goal:** A single, clean Go interface for all LLM providers — Claude, Ollama, LM Studio. Every agent talks to this interface. Swapping providers requires only a config change.

**Why this sprint matters:** Every agent in the platform sends prompts and receives responses. If the provider abstraction is wrong, changing it later means touching every agent. One week of investment here saves weeks of refactoring later.

#### 1.1 Provider Interface (`internal/llm/provider.go`)
- Define `Provider` interface:
  ```go
  type Provider interface {
      Complete(ctx context.Context, req CompletionRequest) (*CompletionResponse, error)
      Stream(ctx context.Context, req CompletionRequest) (<-chan StreamChunk, error)
      HealthCheck(ctx context.Context) error
      ModelName() string
      ContextWindow() int
      SupportsToolUse() bool
  }
  ```
- Define `CompletionRequest`: `Messages []Message`, `Tools []Tool`, `MaxTokens int`, `Temperature float64`, `SystemPrompt string`
- Define `Message`: `Role string` (system/user/assistant/tool), `Content string`, `ToolCallID string` (for tool results)
- Define `Tool`: `Name string`, `Description string`, `Parameters json.RawMessage` (JSON Schema)
- Define `ToolCall`: `ID string`, `Name string`, `Arguments string` (raw JSON)
- Define `CompletionResponse`: `Content string`, `ToolCalls []ToolCall`, `Usage Usage`, `StopReason string`
- Define `StreamChunk`: `Delta string`, `ToolCallDelta *ToolCallDelta`, `Done bool`
- Define `Usage`: `InputTokens int`, `OutputTokens int`

#### 1.2 Claude Provider (`internal/llm/claude.go`)
- Implement `ClaudeProvider` using `anthropic-sdk-go`
- `Complete`: call `client.Messages.New()` with mapped request fields; map response back to `CompletionResponse`
- `Stream`: call `client.Messages.NewStreaming()`; iterate events, emit `StreamChunk` per delta; close channel on `message_stop`
- Tool use: map `Tool` structs to Anthropic `ToolParam`; parse `ToolUseBlock` responses into `ToolCall` structs
- Retry logic: exponential backoff on 429 (rate limit) and 529 (overloaded), max 3 retries, jitter added
- Usage tracking: after every `Complete` call, write `Usage` record to DB with `campaign_id`, `agent_name`, `model`, `input_tokens`, `output_tokens`, `timestamp`
- Write `tests/unit/llm/claude_test.go`: mock HTTP server returning canned responses; test `Complete`, `Stream`, tool call parsing, retry on 429

#### 1.3 Ollama Provider (`internal/llm/ollama.go`)
- Implement `OllamaProvider` using `net/http` against Ollama's REST API
- `Complete`: `POST /api/chat` with `model`, `messages`, `stream: false`; parse response JSON into `CompletionResponse`
- `Stream`: `POST /api/chat` with `stream: true`; read newline-delimited JSON stream; emit `StreamChunk` per line
- Tool use: Ollama supports native tool calling for some models; implement JSON-mode fallback for models that don't — parse structured JSON from completion content
- `HealthCheck`: `GET /api/tags`; verify model name appears in response; return descriptive error if Ollama not running or model not pulled
- `PullModel(ctx, name)`: `POST /api/pull`; stream progress back to caller
- Write `tests/unit/llm/ollama_test.go`: mock Ollama server; test all methods

#### 1.4 LM Studio Provider (`internal/llm/lmstudio.go`)
- Implement `LMStudioProvider` using OpenAI-compatible API that LM Studio exposes
- `POST /v1/chat/completions` — identical schema to OpenAI; use `sashabaranov/go-openai` library with `BaseURL` set to LM Studio endpoint
- `HealthCheck`: `GET /v1/models`; verify server responds and at least one model is loaded
- Write `tests/unit/llm/lmstudio_test.go`

#### 1.5 Provider Factory (`internal/llm/factory.go`)
- `func NewProvider(cfg config.OrchestratorConfig) (Provider, error)`: reads `Provider` field (`claude|ollama|lmstudio`), instantiates the correct implementation
- `func ValidateProvider(ctx context.Context, p Provider) error`: calls `HealthCheck`, verifies `ContextWindow() >= 32000` (minimum for our use), logs model name and context window on success

#### 1.6 Token Budget Manager (`internal/llm/budget.go`)
- Implement `BudgetManager`: tracks token usage per campaign; warns when a single conversation approaches 80% of context window
- Implement `Summarize(ctx, messages []Message, provider Provider) ([]Message, error)`: when context exceeds 70% of window, sends the oldest 50% of messages to the LLM with instruction to summarize, replaces them with the summary — preserves recency while managing context
- This is critical for long campaigns where the orchestrator accumulates a large message history

**Acceptance Criteria:**
- [ ] All three providers implement `Provider` interface and pass `go vet` + type checking
- [ ] Switching `provider: ollama` to `provider: claude` in config requires zero code changes in any agent
- [ ] Claude provider correctly parses a tool call response and returns populated `ToolCall` structs
- [ ] Ollama `HealthCheck` returns a descriptive error when Ollama is not running, not a generic connection refused
- [ ] Token usage is logged to DB after every Claude `Complete` call
- [ ] `BudgetManager.Summarize` reduces a 20-message history to 11 messages (1 summary + 10 recent)

**Dependencies:** Sprint 0

---

### Sprint 2 — Core Data Models & Database
**Duration:** 1 week
**Goal:** Define every data structure the platform uses — campaigns, findings, attack surfaces, reports — and the database schema that persists them. Every subsequent sprint uses these models.

**Why this sprint matters:** Data model decisions made now propagate to every agent, every API endpoint, every report template. Getting them right before building the agents prevents painful migrations later.

#### 2.1 Campaign Models (`internal/pipeline/context.go`)
- Define `Campaign`: `ID uuid`, `Name string`, `Target string`, `Objective string`, `Status CampaignStatus`, `ScopeDefinition`, `AuthToken string`, `CreatedAt time.Time`, `StartedAt *time.Time`, `CompletedAt *time.Time`
- Define `CampaignStatus` enum: `Planned | Initializing | Recon | Classifying | Planning | Executing | Adapting | Reporting | Complete | Failed | Aborted`
- Define `CampaignEvent`: append-only audit log — `ID`, `CampaignID`, `Timestamp`, `EventType`, `AgentName`, `Detail string` (human-readable), `Data json.RawMessage` (structured)
- Define `CampaignMode` enum: `Manual | BugBounty | ContinuousASM`

#### 2.2 Attack Surface Models
- Define `AttackSurface`: `CampaignID`, `Target`, `Subdomains []SubdomainRecord`, `Hosts []HostRecord`, `Endpoints []EndpointRecord`, `Technologies map[string]string`, `CreatedAt`
- Define `HostRecord`: `IP string`, `Hostnames []string`, `OpenPorts []int`, `Services map[int]ServiceRecord`, `OS string`, `Tags []string`
- Define `ServiceRecord`: `Port int`, `Protocol string`, `Name string`, `Version string`, `Banner string`, `HTTPDetails *HTTPDetails`
- Define `HTTPDetails`: `URL string`, `StatusCode int`, `Title string`, `Server string`, `Technologies []string`, `Headers map[string]string`, `ResponseBodyHash string`
- Define `SubdomainRecord`: `Domain string`, `IP string`, `CNAME string`, `HTTPDetails *HTTPDetails`, `Source string`
- Define `EndpointRecord`: `URL string`, `Method string`, `Parameters []string`, `StatusCode int`, `Interesting bool`, `Notes string`

#### 2.3 Finding Models
- Define `RawFinding`: `ID uuid`, `CampaignID`, `Source string` (which tool), `Type string`, `Target string`, `Detail string`, `RawOutput string`, `DiscoveredAt time.Time`
- Define `ClassifiedFinding`: `ID uuid`, `RawFindingID`, `Title string`, `Description string`, `CVEIDs []string`, `CVSSScore float64`, `CVSSVector string`, `Severity Severity`, `AttackCategory string`, `Confidence Confidence`, `FalsePositiveProbability float64`, `ChainCandidates []uuid`, `Evidence []Evidence`
- Define `Severity` enum: `Critical | High | Medium | Low | Informational`
- Define `Confidence` enum: `High | Medium | Low | Unverified`
- Define `Evidence`: `Type string` (command_output/screenshot/log), `Content string`, `Timestamp time.Time`, `Description string`

#### 2.4 Attack Plan Models
- Define `AttackPlan`: `ID uuid`, `CampaignID`, `Paths []AttackPath`, `RecommendedPathID uuid`, `Reasoning string`, `CreatedAt time.Time`
- Define `AttackPath`: `ID uuid`, `Name string`, `Description string`, `Steps []AttackStep`, `TargetFindingIDs []uuid`, `EstimatedSuccessProbability float64`, `RequiredPrivileges string`, `ExpectedImpact string`
- Define `AttackStep`: `ID uuid`, `Name string`, `TechniqueID string` (MITRE ATT&CK), `Command string`, `ExpectedOutputPattern string`, `OnSuccessStepID *uuid`, `OnFailureStepID *uuid`, `CleanupCommand string`
- Define `ExecutionResult`: `StepID uuid`, `CommandExecuted string`, `Output string`, `Success bool`, `Evidence []Evidence`, `ExecutedAt time.Time`, `DurationMs int`

#### 2.5 Database Schema & Migrations (`internal/db/migrations/`)
- Write migration `000001_initial.sql`: creates all tables matching above models — `campaigns`, `campaign_events`, `attack_surfaces`, `raw_findings`, `classified_findings`, `attack_plans`, `attack_paths`, `attack_steps`, `execution_results`
- Write migration `000002_pgvector.sql`: enables `pgvector` extension, adds `embedding vector(1536)` column to `classified_findings` for semantic similarity search
- Write migration `000003_cleanup_registry.sql`: creates `cleanup_actions` table (`id`, `campaign_id`, `command`, `target`, `registered_at`, `executed_at`, `status`)
- Verify all migrations run forward and backward cleanly

#### 2.6 Database Queries (sqlc)
- Write `internal/db/queries/campaigns.sql`: `CreateCampaign`, `GetCampaign`, `UpdateCampaignStatus`, `ListCampaigns`, `AppendCampaignEvent`, `GetCampaignEvents`
- Write `internal/db/queries/findings.sql`: `InsertRawFinding`, `InsertClassifiedFinding`, `GetFindingsByCampaign`, `GetFindingByID`, `UpdateFindingClassification`
- Write `internal/db/queries/plans.sql`: `InsertAttackPlan`, `GetAttackPlan`, `InsertExecutionResult`, `GetExecutionResults`
- Run `sqlc generate` to produce type-safe Go query functions in `internal/db/queries/`
- Write `internal/db/postgres.go`: `Connect(cfg DatabaseConfig) (*pgxpool.Pool, error)` — connection pool with max connections, health check on startup

#### 2.7 Cleanup Registry (`internal/pipeline/cleanup.go`)
- Implement `CleanupRegistry`:
  - `Register(ctx, campaignID, command, target string) error` — inserts into `cleanup_actions` before any command runs
  - `RunCleanup(ctx, campaignID string) CleanupReport` — executes all registered cleanup commands for a campaign in reverse order; marks each as `executed` or `failed`; returns report of what succeeded/failed
  - `PendingCleanup(ctx, campaignID string) ([]CleanupAction, error)` — returns unexecuted cleanup actions (for recovery after crash)
- `CleanupRegistry` is injected into every agent executor — they call `Register` before every command

**Acceptance Criteria:**
- [ ] All migrations run cleanly on a fresh PostgreSQL instance
- [ ] sqlc generates valid, compilable Go code for all queries
- [ ] `CleanupRegistry.RunCleanup` executes registered actions in reverse order and marks each complete in DB
- [ ] `AttackSurface` serializes to/from JSON correctly with nested structs
- [ ] `pgvector` extension is available and `embedding` column accepts 1536-dimensional vectors

**Dependencies:** Sprint 0

---

### Sprint 3 — Recon Agent & Native Go Tool Integration
**Duration:** 2 weeks
**Goal:** Build the Recon Agent — native Go wrappers for 7 security tools, plus the Qwen-powered analysis layer that turns raw output into a structured `AttackSurface` model.

**Why this sprint matters:** The quality of everything downstream (classification, exploitation, reporting) is bounded by the quality of recon. This sprint defines the data that every other agent reasons about.

#### 3.1 Tool Wrapper Interface (`internal/tools/base.go`)
- Define `Tool` interface:
  ```go
  type Tool interface {
      Name() string
      Run(ctx context.Context, target string, opts Options) (*ToolResult, error)
      IsAvailable() bool
  }
  ```
- Define `ToolResult`: `ToolName string`, `Target string`, `RawOutput string`, `ParsedFindings []map[string]any`, `Duration time.Duration`, `Error error`
- Define `Options`: `map[string]any` with typed accessors `GetString(key)`, `GetInt(key)`, `GetBool(key)`
- **Every `Run` implementation calls `scope.ValidateCommand(constructedCommand, scope)` before executing. Returns `ErrScopeViolation` without running if check fails.**

#### 3.2 subfinder (`internal/tools/subfinder.go`)
- Import `github.com/projectdiscovery/subfinder/v2/pkg/runner` as a library (no subprocess)
- Configure runner: passive sources only by default (no active DNS brute force unless `aggressive: true` in options), respect scope domain
- Parse results: each subdomain → `SubdomainRecord` with source attribution
- Options: `recursive bool`, `timeout int`, `rateLimit int`

#### 3.3 httpx (`internal/tools/httpx.go`)
- Import `github.com/projectdiscovery/httpx/runner` as a library
- Default probes: status code, title, content length, server header, technology detection, redirect chain, TLS info
- Parse JSON output → `HTTPDetails` per URL
- Options: `followRedirects bool`, `timeout int`, `threads int`, `matchStatusCodes []int`

#### 3.4 nuclei (`internal/tools/nuclei.go`)
- Import `github.com/projectdiscovery/nuclei/v3/pkg/...` as a library
- Default template categories for recon phase: `technologies`, `exposures`, `misconfiguration` — non-destructive only
- Parse JSON results → `RawFinding` per match with template ID, severity, matched-at
- Options: `templates []string`, `severity []string`, `timeout int`, `rateLimit int`

#### 3.5 naabu (`internal/tools/naabu.go`)
- Import `github.com/projectdiscovery/naabu/v2/pkg/runner` as a library
- Default: scan top-1000 ports with SYN scan; stealth option slows rate and randomizes order
- Parse results: open port list → populate `HostRecord.OpenPorts`
- Options: `ports string` (e.g. `"80,443,8080"` or `"top-100"`), `timeout int`, `rate int`

#### 3.6 katana (`internal/tools/katana.go`)
- Import `github.com/projectdiscovery/katana/pkg/...` as a library
- Web crawler: discovers endpoints, forms, JS-referenced URLs
- Parse results: unique URLs → `EndpointRecord` list
- Options: `depth int`, `javaScriptCrawl bool`, `timeout int`, `headless bool`

#### 3.7 dnsx (`internal/tools/dnsx.go`)
- Import `github.com/projectdiscovery/dnsx/libs/dnsx` as a library
- Bulk DNS resolution for discovered subdomains → IP addresses
- Reverse DNS lookups for discovered IPs
- Options: `resolvers []string`, `retries int`, `timeout int`

#### 3.8 gau (`internal/tools/gau.go`)
- Import `github.com/lc/gau/v2/pkg/...` as a library
- Fetches known URLs from Wayback Machine, Common Crawl, URLScan, OTX
- Filter interesting extensions: `.php`, `.asp`, `.aspx`, `.jsp`, `.env`, `.git`, `.config`, `.bak`, `.sql`, `.log`, `.key`, `.pem`
- Parse results → `EndpointRecord` list with source attribution

#### 3.9 Tool Execution Coordinator (`internal/tools/coordinator.go`)
- Implement `Coordinator`: manages parallel tool execution
  - `RunAll(ctx, target, scope, opts) (*ToolRunSummary, error)`: runs all tools concurrently with `errgroup`; each tool gets its own timeout from config; failures are logged but don't abort other tools
  - `RunSelected(ctx, tools []string, target, scope, opts)`: run subset of tools
  - Tool ordering: subfinder + dnsx first (discover subdomains/IPs), then naabu + httpx in parallel, then katana + gau + nuclei in parallel
  - Streams `ToolResult` events to a channel as each tool completes (don't wait for all to finish)

#### 3.10 Recon Agent (`internal/agent/recon/agent.go`)
- Implement `ReconAgent`:
  - `PlanRecon(target, scope) ReconPlan`: determines which tools to run based on target type
    - Domain target: subfinder → dnsx → naabu + httpx → katana + gau + nuclei
    - IP target: naabu → httpx → nuclei
    - URL target: httpx → katana → gau → nuclei
  - `Execute(ctx, plan ReconPlan) (*AttackSurface, error)`:
    1. Run `Coordinator.RunAll` for planned tools
    2. Stream tool results to campaign event log as they arrive
    3. Collect all `ToolResult` objects
    4. Call `Analyze` with collected results
  - `Analyze(ctx, results []ToolResult) (*AttackSurface, error)`:
    1. Serialize all tool results into structured JSON context string
    2. Send to Qwen 2.5 7B model via Ollama provider with analysis prompt
    3. Parse response into `AttackSurface` struct
    4. Validate: every field matches schema, no empty required fields
    5. Persist `AttackSurface` to DB
    6. Return to orchestrator

#### 3.11 Output Parser (`internal/agent/recon/parser.go`)
- Implement `ParseAttackSurface(rawJSON string) (*AttackSurface, error)`: strict JSON parsing with field validation
- Implement `MergeToolResults(results []ToolResult) MergedData`: deduplicates hosts/subdomains found by multiple tools into single enriched records
- Retry logic: if Qwen response doesn't parse as valid `AttackSurface`, retry with simplified prompt up to 2 times; on third failure return partial results rather than error

#### 3.12 Tests
- `tests/unit/tools/subfinder_test.go`: mock subfinder runner, verify output parsing
- `tests/unit/tools/scope_enforcement_test.go`: verify every tool wrapper calls scope validation, returns `ErrScopeViolation` for out-of-scope targets
- `tests/unit/recon/parser_test.go`: table-driven tests with valid and malformed Qwen outputs, verify parser handles all cases
- `tests/integration/recon_test.go` (marked `integration`): run recon against `scanme.nmap.org` (a legitimate public test target), verify `AttackSurface` is populated

**Acceptance Criteria:**
- [ ] All 7 tools run natively as Go library calls — no `exec.Command` for any tool
- [ ] Scope validation blocks any tool from targeting an out-of-scope IP at the wrapper level
- [ ] `Coordinator.RunAll` streams results as each tool completes, not after all finish
- [ ] Recon agent successfully analyzes output and returns a valid `AttackSurface` with at least hosts, ports, and technologies populated
- [ ] Full recon of a simple target completes in under 5 minutes

**Dependencies:** Sprints 0, 1, 2

---

### Sprint 4 — Classifier Agent
**Duration:** 1 week
**Goal:** Build the Classifier Agent — takes raw findings from the attack surface and enriches each one with CVE mappings, CVSS scores, false positive filtering, and severity ranking.

**Why this sprint matters:** Raw findings are noise. The Exploit Agent's reasoning quality is directly bounded by the quality of classified, scored, ranked findings it receives. Garbage in, garbage out.

#### 4.1 NVD CVE Client (`internal/agent/classifier/cve.go`)
- Implement `NVDClient`:
  - `SearchByCPE(ctx, cpeName string) ([]CVE, error)`: query NVD API v2.0 `GET /rest/json/cves/2.0?cpeName=...`
  - `SearchByKeyword(ctx, product, version string) ([]CVE, error)`: query with `keywordSearch={product version}`
  - `GetCVE(ctx, cveID string) (*CVE, error)`: fetch specific CVE by ID
  - Rate limiting: NVD API allows 5 req/30s without API key, 50 req/30s with key — implement token bucket rate limiter
  - Caching: store results in Redis with 24-hour TTL; key = `nvd:{cpe_or_keyword}`; avoid redundant API calls
- Define `CVE`: `ID`, `Description`, `CVSSv3Score float64`, `CVSSv3Vector string`, `CVSSv3Severity string`, `PublishedDate time.Time`, `References []string`, `AffectedVersions []string`

#### 4.2 CVSS Scorer (`internal/agent/classifier/scorer.go`)
- Implement `ParseCVSSVector(vector string) (*CVSSComponents, error)`: parse CVSS v3.1 vector string (e.g. `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) into component struct
- Implement `ComputeBaseScore(components CVSSComponents) float64`: implement CVSS v3.1 base score formula exactly per FIRST specification
- Implement `AdjustForContext(base float64, ctx ScoringContext) float64`:
  - `ctx.InternetFacing = true`: multiply by 1.15 (higher exposure)
  - `ctx.AuthenticationRequired = true`: multiply by 0.8 (harder to exploit)
  - `ctx.ExploitAvailable = true`: multiply by 1.2 (weaponized exploit exists)
  - Cap at 10.0
- Implement `ScoreToSeverity(score float64) Severity`: 9.0-10.0 = Critical, 7.0-8.9 = High, 4.0-6.9 = Medium, 0.1-3.9 = Low, 0.0 = Informational

#### 4.3 False Positive Filter (`internal/agent/classifier/fp_filter.go`)
- Implement `FPFilter.Score(finding RawFinding) float64`: returns false positive probability 0.0-1.0
- Rules (each adds to FP probability):
  - Generic server banner without version number: +0.6
  - Port open finding without service identification: +0.4
  - Endpoint found but returns 4xx on all probes: +0.5
  - CVE mapped but version range doesn't match detected version: +0.7
  - Finding appears in >80% of scans (common baseline noise): +0.5
  - Finding on non-standard port with no service match: +0.3
- Implement `ShouldFilter(finding RawFinding) bool`: returns true if FP probability > 0.75

#### 4.4 Classifier Agent (`internal/agent/classifier/agent.go`)
- Implement `ClassifierAgent`:
  - `Classify(ctx, surface AttackSurface) (*ClassifiedFindingSet, error)`:
    1. For each `RawFinding` in surface:
       a. Run CVE lookup (parallel, rate-limited)
       b. Compute CVSS score
       c. Compute FP probability
       d. Skip findings with FP probability > 0.75
    2. Batch remaining findings into groups of 20
    3. For each batch: send to Mistral 7B via Ollama with classification prompt asking for: attack category, confidence level, chain candidates, contextual notes
    4. Parse Mistral output → `ClassifiedFinding` structs
    5. Sort results by CVSS score descending
    6. Persist `ClassifiedFindingSet` to DB
    7. Return to orchestrator
- Define `ClassifiedFindingSet`: `CampaignID`, `Findings []ClassifiedFinding`, `Summary ClassificationSummary`, `CreatedAt`
- Define `ClassificationSummary`: `TotalFindings int`, `BySeverity map[Severity]int`, `TopCategories []string`, `FilteredAsFP int`

#### 4.5 Tests
- `tests/unit/classifier/cve_test.go`: mock NVD HTTP responses, verify caching, rate limiting
- `tests/unit/classifier/scorer_test.go`: verify CVSS score computation against known test vectors from FIRST specification
- `tests/unit/classifier/fp_filter_test.go`: table-driven tests for each FP rule
- `tests/integration/classifier_test.go`: classify a set of 10 known real findings, verify severity assignments

**Acceptance Criteria:**
- [ ] CVSS score computation matches FIRST reference calculator for 5 known test vectors
- [ ] NVD cache hit rate is 100% on second call for same CVE
- [ ] FP filter correctly identifies and removes 3 known false positive patterns
- [ ] Classifier processes 50 findings in under 60 seconds
- [ ] `ClassifiedFindingSet` is sorted by CVSS score descending

**Dependencies:** Sprints 2, 3

---

### Sprint 5 — Exploit Agent & Execution Engine
**Duration:** 2 weeks
**Goal:** Build the Exploit Agent — DeepSeek R1-powered attack chain construction — and the execution engine that safely runs exploitation commands.

**Why this sprint matters:** This is the most technically challenging agent. Attack path construction requires genuine multi-step reasoning. DeepSeek R1's chain-of-thought architecture is chosen precisely for this. The execution engine must be both capable and safe.

#### 5.1 Attack Path Builder (`internal/agent/exploit/pathbuilder.go`)
- Implement `PathBuilder.BuildChains(findings []ClassifiedFinding) []AttackPath`:
  - Graph-based chain construction: findings are nodes, "A enables B" relationships are edges
  - Pre-defined relationship rules:
    - `SQLInjection` → `DataExtraction`, `AuthBypass`, `FileRead`
    - `PathTraversal` → `FileRead`, `SourceCodeDisclosure`, `CredentialAccess`
    - `OpenRedirect` → `PhishingAmplification`, `OAuthBypass`
    - `ExposedGitRepo` → `SourceCodeDisclosure`, `CredentialExtraction`, `SecretDiscovery`
    - `WeakCredentials` → `AuthenticationBypass`, `PrivilegeEscalation`
    - `OutdatedSoftware` → `KnownExploitAvailable`
    - `MisconfiguredCORS` → `CrossOriginDataTheft`
    - `XXE` → `SSRF`, `FileRead`, `InternalNetworkScan`
    - `SSRF` → `InternalNetworkScan`, `CloudMetadataAccess`, `PortScan`
  - Build all valid chains, return as `[]AttackPath` sorted by estimated success probability
  - This supplements (not replaces) DeepSeek's reasoning — the LLM adds novel chains the rules don't cover

#### 5.2 Exploit Agent (`internal/agent/exploit/agent.go`)
- Implement `ExploitAgent`:
  - `BuildPlan(ctx, findings ClassifiedFindingSet, objective string) (*AttackPlan, error)`:
    1. Call `PathBuilder.BuildChains` to get rule-based chains
    2. Serialize findings + objective + rule-based chains into context
    3. Send to DeepSeek R1 8B via Ollama with prompt instructing chain-of-thought reasoning:
       - "Think through each finding. Which are most exploitable? How can they be chained? What path leads most efficiently to the objective? Output your thinking in `<think>` tags, then output the final plan as JSON."
    4. Parse `<think>` section as reasoning trace (stored in `AttackPlan.Reasoning`)
    5. Parse JSON plan section as `AttackPlan` struct
    6. Merge LLM-generated paths with rule-based paths, deduplicate
    7. Rank all paths by: success probability × severity × chain length score
    8. Persist `AttackPlan` to DB
    9. Return to orchestrator
  - `AdaptPlan(ctx, plan AttackPlan, result ExecutionResult) (*AttackPlan, error)`:
    1. Serialize current plan + latest execution result into context
    2. Send to DeepSeek R1: "Given this step result, should we continue on the current path, pivot to an alternative, or adjust the approach? Think through it then output the updated plan."
    3. Parse and return updated `AttackPlan`

#### 5.3 Command Execution Engine (`internal/agent/exploit/executor.go`)
- Implement `Executor`:
  - `Execute(ctx, step AttackStep, scope ScopeDefinition) (*ExecutionResult, error)`:
    1. `scope.ValidateCommand(step.Command, scope)` — hard stop if fails
    2. `cleanup.Register(campaignID, step.CleanupCommand, target)` — must complete before execution
    3. `exec.CommandContext(ctx, ...)` with timeout from step or default (120s)
    4. Capture stdout + stderr
    5. Match output against `step.ExpectedOutputPattern` (regex)
    6. Build and return `ExecutionResult`
  - `DryRun(step AttackStep) string`: returns the command string with all substitutions applied, without executing — used by `--dry-run` flag

#### 5.4 Docker Executor (`internal/agent/exploit/docker_executor.go`)
- For commands that require a specific environment (Kali Linux tools not available locally):
  - Implement `DockerExecutor`: uses `docker/docker client-go` to create ephemeral containers
  - `RunInContainer(ctx, image, command string) (*ExecutionResult, error)`:
    1. Pull image if not present
    2. Create container with: no network access to host, read-only filesystem except `/tmp`, memory limit 512MB, CPU limit 0.5 core
    3. Run command, stream output
    4. Remove container after completion (always, even on error)
  - Default image: `kalilinux/kali-rolling` with pre-installed tools
  - Scope validation still applies — container networking is restricted to target scope

#### 5.5 Tests
- `tests/unit/exploit/pathbuilder_test.go`: verify rule-based chains are correctly constructed for known finding combinations
- `tests/unit/exploit/executor_test.go`: mock command execution, verify scope validation is called, verify cleanup is registered, verify dry run returns command without executing
- `tests/unit/exploit/docker_test.go`: mock Docker API, verify container lifecycle (create → run → remove)

**Acceptance Criteria:**
- [ ] Exploit agent constructs a valid `AttackPlan` with at least 2 attack paths from a test `ClassifiedFindingSet`
- [ ] `<think>` reasoning trace is captured and stored in `AttackPlan.Reasoning`
- [ ] Executor calls `scope.ValidateCommand` before running any command
- [ ] Executor calls `cleanup.Register` before running any command
- [ ] `DryRun` returns command string without executing (verified by checking no child processes spawned)
- [ ] Docker executor removes container after execution even when command fails

**Dependencies:** Sprints 2, 3, 4

---

### Sprint 6 — Orchestrator Agent
**Duration:** 2 weeks
**Goal:** Build the Orchestrator Agent — the ReAct loop that coordinates all four specialist agents, plans campaigns, makes adaptive decisions, and manages campaign state.

**Why this sprint matters:** This is the glue that turns four independent agents into a coherent, adaptive campaign. The orchestrator is the only component that sees the full picture — every decision flows through it.

#### 6.1 ReAct Agent Loop (`internal/agent/orchestrator/agent.go`)
- Implement `OrchestratorAgent` as a ReAct (Reason + Act + Observe) loop:
  ```
  loop:
    1. Build message: system prompt + campaign context + memory + last observation
    2. Send to LLM provider (Claude or local)
    3. Receive: either a text response (reasoning) or a tool call
    4. If tool call: dispatch to appropriate specialist agent or built-in tool
    5. Append tool result to messages as tool response
    6. Append to campaign memory
    7. Emit event to WebSocket hub (for live streaming to UI/CLI)
    8. Check: is campaign objective reached? Is campaign aborted?
    9. Loop
  ```
- Implement campaign memory as a rolling `[]Message` slice: append each exchange; when token budget reaches 70%, call `BudgetManager.Summarize`
- Implement loop termination conditions: objective reached, all attack paths exhausted, maximum iterations exceeded (configurable, default 50), campaign aborted

#### 6.2 Orchestrator Tools (`internal/agent/orchestrator/tools.go`)
- Define each specialist agent operation as a `Tool` the orchestrator can call:
  - `run_recon`: args `{target, depth}` → dispatches `ReconAgent.Execute`, returns `AttackSurface` summary
  - `classify_findings`: args `{campaign_id}` → dispatches `ClassifierAgent.Classify`, returns `ClassifiedFindingSet` summary
  - `build_attack_plan`: args `{objective}` → dispatches `ExploitAgent.BuildPlan`, returns `AttackPlan` summary
  - `execute_step`: args `{step_id, plan_id}` → dispatches `Executor.Execute`, returns `ExecutionResult`
  - `adapt_plan`: args `{plan_id}` → dispatches `ExploitAgent.AdaptPlan` with last result, returns updated plan summary
  - `generate_report`: args `{}` → dispatches `ReportAgent.Generate`, returns report path
  - `query_surface`: args `{query}` → semantic search over `classified_findings` using pgvector similarity; returns matching findings
  - `pause`: args `{reason}` → transitions campaign to `Paused`, sends notification, waits for resume signal
  - `complete`: args `{summary}` → marks campaign complete, triggers report generation

#### 6.3 Agent Memory System (`internal/memory/`)
- Implement persistent cross-engagement memory that makes the tool smarter with every scan:
  - `MemoryStore`: stores learned patterns in PostgreSQL + pgvector for semantic retrieval
  - After every campaign completes, extract and persist:
    - **Tech Stack Patterns**: "Rails apps on this hosting provider tend to have X misconfiguration"
    - **Successful Attack Chains**: which exploit chains worked against which tech stacks
    - **False Positive Patterns**: findings that were consistently noise for specific configurations
    - **Timing Patterns**: which tools/techniques were fastest for specific target types
  - `RecallRelevant(ctx, target, techStack) []MemoryEntry`: before starting a new campaign, query memory for relevant past insights using semantic similarity
  - Inject recalled memories into orchestrator system prompt: "Based on previous engagements with similar targets, prioritize X and skip Y"
  - Privacy: memory is per-installation, never leaves the machine. `autopentest memory clear` wipes everything
  - `autopentest memory show`: displays learned patterns and stats
  - `autopentest memory export/import`: share anonymized patterns between installations (opt-in)
- **This is a core moat**: every scan makes the next scan better for that user. Switching to a competitor means losing accumulated intelligence.

#### 6.4 Campaign Planner (`internal/agent/orchestrator/planner.go`)
- Implement `Planner.DecomposeObjective(objective, target string) []Milestone`:
  - Milestones are ordered checkpoints the orchestrator tracks progress against
  - `"find all vulnerabilities"` → `[recon_complete, findings_classified, exploitation_attempted, report_generated]`
  - `"find RCE"` → `[recon_complete, rce_candidates_identified, rce_exploited_or_exhausted, report_generated]`
  - `"bug bounty scan"` → `[scope_loaded, recon_complete, findings_classified, duplicates_checked, report_formatted]`
- Implement `Planner.AssessMilestone(milestone Milestone, state CampaignState) bool`: checks whether current state satisfies milestone completion criteria

#### 6.5 Campaign State Machine (`internal/pipeline/campaign.go`)
- Implement `StateMachine` with explicit state transitions:
  - Each transition: validates it's allowed from current state, logs to `CampaignEvent`, updates DB
  - Transitions: `Start()`, `BeginRecon()`, `BeginClassifying()`, `BeginPlanning()`, `BeginExecuting()`, `BeginAdapting()`, `BeginReporting()`, `Complete()`, `Fail(reason)`, `Abort()`
  - `Abort()`: transitions to `Aborted`, triggers `CleanupRegistry.RunCleanup`, emits abort event to all subscribers
- Implement `EmergencyStop(campaignID string)`: callable from API and CLI; calls `Abort()` within 5 seconds

#### 6.6 Event Streaming (`internal/api/ws/hub.go`)
- Implement `EventHub`: manages WebSocket connections per campaign
  - `Subscribe(campaignID, conn)`: register a WebSocket connection
  - `Publish(campaignID, event CampaignEvent)`: broadcast event to all subscribers for that campaign
  - `Unsubscribe(campaignID, conn)`: clean up on disconnect
- Events streamed in real-time: orchestrator reasoning text (token by token), tool dispatch, tool result, state transitions, new findings
- Campaign event types: `thought` (orchestrator thinking), `tool_call`, `tool_result`, `finding_discovered`, `state_change`, `step_executed`, `error`

#### 6.7 Campaign API (`internal/api/handlers/campaigns.go`)
- `POST /api/v1/campaigns`: validate request body → create `Campaign` in DB → return campaign ID
- `POST /api/v1/campaigns/:id/start`: verify authorization token → transition to `Initializing` → start orchestrator goroutine → return 202
- `POST /api/v1/campaigns/:id/stop`: call `EmergencyStop` → return 200
- `GET /api/v1/campaigns/:id`: return campaign with current status, milestone progress, finding counts
- `GET /api/v1/campaigns/:id/events`: WebSocket upgrade → subscribe to `EventHub` → stream events
- `GET /api/v1/campaigns/:id/findings`: return `ClassifiedFindingSet` (requires campaign in `Executing` or later state)
- `GET /api/v1/campaigns/:id/report`: return generated report file (requires `Complete` state)

#### 6.8 Tests
- `tests/unit/orchestrator/agent_test.go`: mock all four specialist agents and LLM provider; verify ReAct loop correctly dispatches tool calls, appends to memory, terminates on objective-reached signal
- `tests/unit/orchestrator/planner_test.go`: verify milestone decomposition for 3 different objective strings
- `tests/unit/pipeline/state_machine_test.go`: verify all valid/invalid transitions; verify `Abort` calls cleanup
- `tests/integration/orchestrator_test.go`: full orchestrator run against mock specialist agents; verify campaign progresses through all states

**Acceptance Criteria:**
- [ ] Orchestrator ReAct loop correctly dispatches `run_recon` tool call and processes the returned `AttackSurface`
- [ ] Campaign progresses through all states from `Planned` to `Complete` in integration test
- [ ] Emergency stop transitions to `Aborted` and triggers cleanup within 5 seconds
- [ ] WebSocket stream delivers orchestrator `thought` events in real-time (latency <500ms per token)
- [ ] Token budget manager correctly summarizes memory when approaching 70% of context window
- [ ] Agent memory persists patterns after campaign completion and recalls them for similar targets
- [ ] `autopentest memory show` displays learned patterns with stats
- [ ] `autopentest memory clear` wipes all stored patterns

**Dependencies:** Sprints 1, 2, 3, 4, 5

---

### Sprint 7 — Report Agent
**Duration:** 1 week
**Goal:** Build the Report Agent — Llama 3.1 8B-powered professional report generation in PDF, HTML, Markdown, and JSON formats.

**Why this sprint matters:** The report is the deliverable that justifies the entire platform. Professional, evidence-backed, clearly written output is what makes this usable for real engagements and bug bounty submissions.

#### 7.1 Report Data Model (additions to Sprint 2 models)
- Define `PentestReport`: `ID uuid`, `CampaignID`, `Target`, `Objective`, `ExecutiveSummary string`, `ScopeDescription string`, `Methodology string`, `Findings []ReportFinding`, `AttackNarrative string`, `RiskSummary RiskSummary`, `RemediationPlan []RemediationItem`, `Appendices []Appendix`, `GeneratedAt time.Time`
- Define `ReportFinding`: `ID uuid`, `Title string`, `Severity Severity`, `CVSSScore float64`, `CVSSVector string`, `Description string`, `Evidence []Evidence`, `AffectedComponents []string`, `Remediation string`, `References []string`, `ProofOfConcept string`
- Define `RiskSummary`: `OverallRisk string`, `CriticalCount int`, `HighCount int`, `MediumCount int`, `LowCount int`, `InfoCount int`
- Define `RemediationItem`: `Priority int`, `Finding string`, `Action string`, `Effort string`, `Impact string`

#### 7.2 Report Agent (`internal/agent/report/agent.go`)
- Implement `ReportAgent.Generate(ctx, campaignID string) (*PentestReport, error)`:
  1. Fetch from DB: campaign details, all `ClassifiedFinding` records, all `ExecutionResult` records, `AttackPlan`
  2. Build structured context JSON from all campaign data
  3. Call Llama 3.1 8B via Ollama in 4 separate prompts (to stay within context):
     - Prompt 1: "Write an executive summary for a non-technical audience. Focus on business risk, not technical details. 2-3 paragraphs."
     - Prompt 2: "For each finding, write a technical writeup with: what it is, why it matters, how it was found, evidence, how to fix it."
     - Prompt 3: "Write an attack narrative — tell the story of this penetration test as a sequence of events, from initial recon to final finding."
     - Prompt 4: "Write a prioritized remediation plan. Order items by: severity × ease of fix. Be specific and actionable."
  4. Assemble all sections into `PentestReport`
  5. Persist to DB
  6. Return

#### 7.3 Report Renderer (`internal/agent/report/renderer.go`)
- Implement `Renderer.ToMarkdown(report *PentestReport) ([]byte, error)`: renders report to clean GitHub-flavored Markdown using `text/template`
- Implement `Renderer.ToHTML(report *PentestReport) ([]byte, error)`: renders to self-contained HTML with embedded CSS (Tailwind via CDN), syntax-highlighted code blocks, collapsible finding sections
- Implement `Renderer.ToPDF(report *PentestReport) ([]byte, error)`: renders HTML → PDF using `go-wkhtmltopdf` or `chromedp` headless Chrome; cover page with target and date, table of contents, page numbers, footer with classification marking
- Implement `Renderer.ToJSON(report *PentestReport) ([]byte, error)`: `json.MarshalIndent` with clean field names

#### 7.4 Report Templates (`internal/agent/report/templates/`)
- `executive_summary.html.tmpl`: section template with correct heading hierarchy
- `finding.html.tmpl`: finding card with severity badge, CVSS gauge, evidence code block
- `remediation.html.tmpl`: prioritized table with effort/impact matrix
- `cover.html.tmpl`: cover page with target, date, classification marking, Armur AI branding

#### 7.5 Tests
- `tests/unit/report/renderer_test.go`: render a test `PentestReport` to all 4 formats, verify output is valid (Markdown parses, HTML is valid, JSON unmarshals, PDF is non-zero bytes)
- `tests/unit/report/agent_test.go`: mock Llama provider, verify all 4 prompts are sent and responses assembled correctly

**Acceptance Criteria:**
- [ ] PDF report generates in under 60 seconds with cover page, TOC, and all sections
- [ ] Each finding in report contains: title, severity badge, CVSS score, description, evidence block, remediation
- [ ] Executive summary contains no technical jargon (verified by checking absence of CVE IDs and command strings)
- [ ] JSON export is valid and deserializes to `PentestReport` struct without errors
- [ ] HTML report is self-contained (no external CDN dependencies that would break offline viewing)

**Dependencies:** Sprints 2, 5, 6

---

### Sprint 8 — CLI (Command Line Interface)
**Duration:** 1 week
**Goal:** A best-in-class CLI that is simple for beginners and powerful for experts. Beautiful terminal output. Zero configuration required for basic use.

**Why this sprint matters:** The CLI is the primary interface for security professionals. It must feel as polished as tools like `gh`, `fly`, or `docker`. A good CLI drives adoption; a bad one kills it regardless of how good the backend is.

#### 8.1 CLI Structure (`cli/`)
- Implement root command with Cobra: `autopentest [command] [flags]`
- Global flags: `--config string` (config file path), `--api string` (API server URL, default `http://localhost:8080`), `--json` (machine-readable JSON output), `--quiet` (suppress decorative output), `--verbose` (debug logging)
- All commands that modify state require explicit confirmation unless `--yes` flag provided

#### 8.2 Scan Command (`cli/scan.go`)
```
autopentest scan <target> [flags]

Flags:
  --objective string     What to find (default: "find all vulnerabilities")
  --scope string         CIDR or domain scope, comma-separated (required)
  --mode string          manual|bugbounty|asm (default: manual)
  --provider string      claude|ollama|lmstudio (overrides config)
  --dry-run              Show planned commands without executing
  --output string        Output directory for report (default: ./reports)
  --format string        Report format: pdf|html|md|json|all (default: pdf)
  --follow               Stream live output (equivalent to scan + watch)
  --auth-token string    Authorization token (required for production use)
```
- When `--follow` is set: starts campaign AND opens live watch view in same terminal session
- `scan` creates the campaign, starts it, and returns campaign ID immediately (non-blocking) unless `--follow`

#### 8.3 Campaign Commands (`cli/campaign.go`)
```
autopentest campaign list                   # List all campaigns with status
autopentest campaign status <id>            # Detailed status of one campaign
autopentest campaign watch <id>             # Live stream of agent activity
autopentest campaign stop <id>              # Emergency stop
autopentest campaign report <id> [flags]    # Download/display report
autopentest campaign delete <id>            # Delete campaign and artifacts

campaign report flags:
  --format string   pdf|html|md|json (default: pdf)
  --output string   Output path (default: ./<campaign-id>.pdf)
  --open            Open report in browser/app after download
```

#### 8.4 Live Watch TUI (`cli/ui/watch.go`)
- Implement using `bubbletea` — a full terminal UI with live updates:
  - **Header bar**: campaign ID, target, objective, elapsed time, current state
  - **Phase progress**: horizontal steps bar — `Recon → Classify → Plan → Execute → Report` with current step highlighted
  - **Agent thoughts panel** (largest area): scrollable log of orchestrator reasoning text, streamed token by token, newest at bottom; dim gray for reasoning, bright white for decisions, yellow for tool calls
  - **Findings ticker** (right sidebar): live count of findings by severity, updates as findings are discovered
  - **Current action**: last tool dispatched + status (running / complete / failed)
  - **Footer**: keyboard shortcuts — `q` quit watch (keeps campaign running), `s` stop campaign, `r` open report when complete, `↑↓` scroll thoughts
- Connect to WebSocket `GET /api/v1/campaigns/:id/events`; render each event type appropriately

#### 8.5 Doctor Command (`cli/doctor.go`)
```
autopentest doctor
```
- Checks in order, prints status with colored pass/fail indicator for each:
  1. API server reachable at configured URL
  2. PostgreSQL connected and migrations up to date
  3. Redis connected
  4. Ollama running at configured endpoint
  5. Each of the 4 specialist models pulled in Ollama (check by name)
  6. Each native Go tool available: subfinder, httpx, nuclei, naabu, katana, dnsx, gau (checks if Go module is available, not PATH)
  7. Docker daemon running (required for container-mode execution)
  8. Claude API key valid (if provider = claude, makes a minimal test call)
  9. Available disk space > 10GB (for model storage and reports)
  10. RAM > 8GB (for running local models)
- On any failure: print specific instructions to fix it (e.g. "Ollama model not found. Run: autopentest models pull")

#### 8.6 Models Commands (`cli/models.go`)
```
autopentest models pull         # Pull all 4 ArmurAI specialist models
autopentest models list         # Show all models + versions + sizes
autopentest models update       # Update to latest versions of all models
autopentest models remove       # Remove all specialist models
```
- `models pull` shows a progress bar per model using `lipgloss` progress component
- Model checksums verified after download against known-good hashes

#### 8.7 Config Command (`cli/config.go`)
```
autopentest config init                      # Interactive setup wizard
autopentest config set <key> <value>         # Set a config value
autopentest config get <key>                 # Get a config value
autopentest config show                      # Print full config (redacts secrets)
autopentest config validate                  # Validate config file
```
- `config init` wizard: asks for provider choice, API key (if Claude), Ollama endpoint (if local), DB connection string; writes `config.yaml`; runs `doctor` at end to verify

#### 8.8 Explain Command (`cli/explain.go`)
```
autopentest explain <finding-id>           # Explain a finding in plain English
autopentest explain <cve-id>               # Explain a CVE
autopentest explain <finding-id> --remediate  # Include step-by-step fix instructions
autopentest explain <finding-id> --audience developer|manager|executive
```
- Sends finding details to LLM with audience-appropriate prompt
- `--audience developer`: technical explanation with code-level fix examples
- `--audience manager`: business risk framing, compliance implications
- `--audience executive`: one-paragraph impact statement, cost of inaction
- This doubles the user base — defenders and dev teams use the tool too, not just pentesters
- Output is formatted Markdown rendered beautifully in terminal via `glamour`

#### 8.9 Version & Update Commands
```
autopentest version             # Print version, commit hash, build date
autopentest update              # Self-update to latest release via GitHub API
```

#### 8.9 Tests
- `tests/unit/cli/scan_test.go`: verify `scan` command constructs correct campaign request from flags
- `tests/unit/cli/doctor_test.go`: mock all services, verify each check runs and reports correctly
- `tests/unit/cli/config_test.go`: verify `config set` writes correct value, `config validate` catches missing required fields

**Acceptance Criteria:**
- [ ] `autopentest scan example.com --scope example.com --follow` runs a campaign end-to-end with live terminal output
- [ ] `autopentest doctor` identifies and clearly describes each failing check with fix instructions
- [ ] `autopentest models pull` shows per-model progress bars and verifies checksums
- [ ] Watch TUI renders agent thoughts in real-time with correct visual hierarchy
- [ ] `autopentest --json campaign status <id>` outputs valid JSON parseable by `jq`
- [ ] All commands print `--help` with correct usage, flags, and examples

**Dependencies:** Sprints 0, 6, 7

---

### Sprint 9 — Web Dashboard
**Duration:** 2 weeks
**Goal:** A polished React dashboard that makes campaign activity visible and reports readable. The "demo moment" that drives sharing and stars.

**Why this sprint matters:** The web UI is what people screenshot and share. The live orchestrator thought stream is the feature that makes people say "holy shit, it's actually thinking." This drives GitHub stars more than any other single feature.

#### 9.1 Frontend Setup (`web/`)
- Initialize Vite + React 18 + TypeScript
- Install: `shadcn/ui`, `tailwindcss`, `@tanstack/react-query`, `zustand`, `wouter` (lightweight router), `recharts` (charts), `react-force-graph-2d` (attack surface graph)
- Configure Vite to build static assets into `web/dist/`; embed `web/dist/` into Go binary using `//go:embed` directive — single binary serves the dashboard

#### 9.2 Dashboard Page (`web/src/pages/Dashboard.tsx`)
- Active campaigns list: name, target, status badge, elapsed time, finding count (by severity), progress bar showing current phase
- "New Scan" button: opens quick-scan modal (target + scope + objective, 3 fields)
- Recent findings feed: last 10 findings across all campaigns with severity badge and truncated title
- Stats bar: total campaigns, total findings by severity, models status

#### 9.3 New Campaign Wizard (`web/src/pages/NewCampaign.tsx`)
- Step 1 — Target: input for domain/IP, scope CIDR inputs (add/remove rows), objective text input with suggestion chips ("Find all vulns", "Find RCE", "Find auth bypasses", "Bug bounty scan")
- Step 2 — Provider: radio between Claude (shows API key field) and Local LLM (shows Ollama endpoint + model dropdown populated from `GET /api/v1/models`)
- Step 3 — Authorization: operator name field, date range for authorization window, generates signed token client-side, shows token for operator to copy/save
- Step 4 — Review: summary of all settings, estimated time, "Launch Campaign" button

#### 9.4 Live Campaign View (`web/src/pages/CampaignLive.tsx`)
- **Phase bar**: animated steps with current phase highlighted and spinner
- **Orchestrator Thoughts** (center, largest panel): scrolling stream of agent reasoning text, arrives token by token via WebSocket; styled as a terminal — dark background, monospace font, reasoning in gray, decisions in white, tool calls in yellow, findings in green
- **Attack Surface Map** (right panel): force-directed graph using `react-force-graph-2d`; nodes = discovered hosts/subdomains (sized by port count), edges = trust relationships; updates live as recon completes; hover shows host details
- **Findings Feed** (bottom left): findings appear as cards as they're discovered, color-coded by severity; clicking a finding expands it
- **Emergency Stop** button: top right, red, requires clicking twice (confirm dialog on first click)
- Connect to WebSocket `GET /api/v1/campaigns/:id/events` using browser native WebSocket

#### 9.5 Report Viewer (`web/src/pages/ReportViewer.tsx`)
- Rendered HTML report displayed in-browser in an iframe
- Left sidebar: findings index with severity badges, click to jump to finding section
- Top bar: export buttons (PDF download, HTML download, JSON download, Markdown download)
- Share button: copies a permalink to this report view

#### 9.6 Settings Page (`web/src/pages/Settings.tsx`)
- Provider configuration: switch between Claude/Ollama/LM Studio, test connection button
- Model management: table of 4 specialist models with version, size, status (pulled/not pulled), pull/update/remove actions
- API Keys: list configured API keys with last-used date, create new key, revoke key

#### 9.7 API Routes for Dashboard
- `GET /api/v1/models`: list available Ollama models
- `GET /api/v1/stats`: overall stats (campaign counts, finding counts, model status)
- `GET /api/v1/reports/:id/html`: serve rendered HTML report

**Acceptance Criteria:**
- [ ] `web/dist` is embedded in Go binary — `./bin/autopentest serve` serves the dashboard with no separate web server
- [ ] Live campaign view shows orchestrator thought stream within 1 second of campaign start
- [ ] Attack surface graph updates in real-time as subdomains are discovered
- [ ] Report viewer renders a full report and all 4 download formats work
- [ ] New campaign wizard creates and starts a campaign without the user touching the CLI

**Dependencies:** Sprints 6, 7, 8

---

### Sprint 10 — Continuous ASM Engine
**Duration:** 2 weeks
**Goal:** Build the continuous attack surface monitoring engine — watches a defined scope, detects new and changed assets, automatically triggers targeted AI tests, and alerts on significant findings.

**Why this sprint matters:** Point-in-time scans miss the constantly changing attack surface. New subdomains, new ports, new services appear every day. Continuous ASM closes the gap between scheduled pentests — this is what commercial tools charge $50k/year for.

#### 10.1 Scope Watcher (`internal/asm/watcher.go`)
- Implement `ScopeWatcher`:
  - Manages a set of watched scopes, each with its own polling schedule (configurable per scope, default 24h)
  - Uses goroutines + time.Ticker per scope for concurrent, independent polling
  - On each tick: run recon tools against the scope, store snapshot in DB
  - Compare snapshot with previous using `DiffEngine`
  - If diff detected: emit `AssetChangeEvent` to a channel consumed by `TriggerEngine`

#### 10.2 Asset Snapshot Store (`internal/asm/snapshot.go`)
- Implement `SnapshotStore`:
  - `Save(ctx, scopeID, snapshot AttackSurface) error`: persist to `asm_snapshots` table
  - `GetLatest(ctx, scopeID string) (*AttackSurface, error)`: return most recent snapshot
  - `GetHistory(ctx, scopeID string, limit int) ([]AttackSurface, error)`: return N most recent snapshots
- Add migration `000004_asm.sql`: creates `asm_scopes`, `asm_snapshots`, `asm_asset_changes` tables

#### 10.3 Diff Engine (`internal/asm/diff.go`)
- Implement `DiffEngine.Diff(prev, curr AttackSurface) *AssetDiff`:
  - `NewSubdomains []string`: in curr but not in prev
  - `RemovedSubdomains []string`: in prev but not in curr
  - `NewPorts map[string][]int`: new open ports per host
  - `ClosedPorts map[string][]int`: closed ports per host
  - `NewServices map[string][]ServiceRecord`: new services detected
  - `NewEndpoints []EndpointRecord`: new web endpoints
  - `ChangedTechnologies map[string][]string`: technology version changes
- Implement `IsSignificant(diff *AssetDiff) bool`: returns true if diff contains new subdomains, new ports on critical services, or new endpoints — used to decide whether to auto-trigger a scan

#### 10.4 Auto-Trigger Engine (`internal/asm/trigger.go`)
- Implement `TriggerEngine`:
  - Consumes `AssetChangeEvent` from watcher
  - For each significant change: automatically create and start a new campaign targeting only the changed assets
  - Campaign objective set to: `"Assess newly discovered asset: <asset>"` with scope limited to the new asset
  - Respects rate limiting: max 3 auto-triggered campaigns per 24h per scope (prevents runaway scanning)
  - All auto-triggered campaigns require a pre-configured authorization token stored in the scope config

#### 10.5 ASM API (`internal/api/handlers/asm.go`)
- `POST /api/v1/asm/scopes`: create watched scope with target, schedule, notification config
- `GET /api/v1/asm/scopes`: list all watched scopes with status
- `DELETE /api/v1/asm/scopes/:id`: stop watching a scope
- `GET /api/v1/asm/scopes/:id/history`: asset change history with diff view
- `POST /api/v1/asm/scopes/:id/scan-now`: trigger immediate scan without waiting for schedule

#### 10.6 Notifications (`internal/asm/notify.go`)
- Implement `Notifier` interface: `Notify(ctx, event AssetChangeEvent) error`
- Implement `SlackNotifier`: posts to configured webhook with finding summary
- Implement `EmailNotifier`: sends SMTP email with diff summary
- Implement `WebhookNotifier`: posts JSON payload to configured URL
- Notification content: new assets discovered, critical/high findings from auto-triggered campaigns, technology changes that match known CVEs

#### 10.7 CLI Commands for ASM
```
autopentest asm add <target> --schedule 24h --scope <cidr>    # Start watching a scope
autopentest asm list                                            # List watched scopes
autopentest asm history <scope-id>                             # Show asset change history
autopentest asm remove <scope-id>                              # Stop watching
autopentest asm scan-now <scope-id>                            # Trigger immediate scan
```

**Acceptance Criteria:**
- [ ] `ScopeWatcher` correctly detects a new subdomain added to a mock target between two scans
- [ ] `DiffEngine` correctly identifies new ports, new subdomains, and technology version changes
- [ ] Auto-trigger creates a campaign targeting only the changed assets, not the full scope
- [ ] Rate limiting prevents more than 3 auto-triggered campaigns per 24h
- [ ] Slack notification is sent within 60 seconds of a significant asset change being detected

**Dependencies:** Sprints 3, 6

---

### Sprint 11 — Bug Bounty Workflow
**Duration:** 2 weeks
**Goal:** Build first-class bug bounty hunter support — read program scopes from HackerOne/Bugcrowd, track what's been tested, detect duplicate findings, and generate program-compliant reports.

**Why this sprint matters:** Bug bounty hunters are one of the most active and vocal communities on GitHub. A tool that genuinely understands their workflow (scope management, dedup, report format) will spread through that community faster than any marketing.

#### 11.1 HackerOne Client (`internal/bugbounty/hackerone.go`)
- Implement `HackerOneClient`:
  - `GetProgram(ctx, handle string) (*BugBountyProgram, error)`: `GET https://api.hackerone.com/v1/hackers/programs/{handle}` — fetch scope, policy, bounty table
  - `GetScope(ctx, handle string) (*ProgramScope, error)`: extract in-scope and out-of-scope assets
  - `GetSubmissions(ctx, handle string) ([]Submission, error)`: fetch previously submitted reports to enable dedup
  - `SubmitReport(ctx, handle string, report SubmissionRequest) (*Submission, error)`: create a new report (optional, requires explicit flag)
- Define `BugBountyProgram`: `Handle`, `Name`, `Policy`, `BountyTable`, `InScope []ScopeAsset`, `OutOfScope []ScopeAsset`
- Define `ScopeAsset`: `AssetType string` (URL/domain/IP/app), `Identifier string`, `EligibleForBounty bool`, `MaxSeverity string`

#### 11.2 Bugcrowd Client (`internal/bugbounty/bugcrowd.go`)
- Implement `BugcrowdClient` with equivalent methods for Bugcrowd API v1
- `GetTargetGroups(ctx, programCode string) ([]TargetGroup, error)`: fetch in-scope/out-of-scope targets
- `GetSubmissions(ctx, programCode string) ([]Submission, error)`: fetch existing submissions for dedup

#### 11.3 Scope Importer (`internal/bugbounty/scope_importer.go`)
- Implement `ImportScope(ctx, program BugBountyProgram) (*ScopeDefinition, error)`:
  - Converts program scope assets to `ScopeDefinition` (CIDRs, domains, ports)
  - Automatically sets out-of-scope exclusions
  - Validates imported scope is not empty before returning
- This `ScopeDefinition` is passed directly to campaign creation — bug bounty users never need to manually define scope

#### 11.4 Duplicate Detector (`internal/bugbounty/dedup.go`)
- Implement `DuplicateDetector`:
  - `IsDuplicate(ctx, finding ClassifiedFinding, program string) (bool, *Submission, error)`:
    1. Fetch existing submissions for the program from HackerOne/Bugcrowd API
    2. Compute semantic similarity between `finding.Description` and each existing submission title/description using pgvector embeddings
    3. If cosine similarity > 0.85: flag as potential duplicate, return matching submission
    4. Also check: same CVE ID on same asset, same URL with same vulnerability class
  - `BatchCheck(ctx, findings []ClassifiedFinding, program string) map[uuid]DuplicateResult`

#### 11.5 Bug Bounty Report Formatter (`internal/bugbounty/formatter.go`)
- Implement `FormatForHackerOne(finding ClassifiedFinding, evidence []Evidence) HackerOneReport`:
  - `Title`: concise, follows H1 conventions (e.g. "Reflected XSS in /search parameter `q`")
  - `VulnerabilityInformation`: technical writeup with steps to reproduce, impact, CVSS
  - `SeverityRating`: mapped from CVSS score to H1's `none|low|medium|high|critical`
  - `ProofOfConcept`: formatted command output / screenshot evidence
  - `RecommendedFix`: remediation guidance
- Implement `FormatForBugcrowd(finding ClassifiedFinding, evidence []Evidence) BugcrowdReport`

#### 11.6 Bug Bounty Mode Campaign Flow
- When `--mode bugbounty` is set on `autopentest scan`:
  1. Prompt for program handle
  2. Fetch scope from HackerOne/Bugcrowd, display it, confirm with user
  3. Import scope as `ScopeDefinition` — use directly for scope enforcement
  4. After classification: run `DuplicateDetector.BatchCheck` on all findings
  5. Mark duplicates in `ClassifiedFindingSet` — orchestrator skips them
  6. After campaign: generate report with HackerOne/Bugcrowd-formatted finding sections
  7. Optionally submit: `--submit` flag enables direct submission via API (with confirmation prompt)

#### 11.7 CLI Commands for Bug Bounty
```
autopentest scan <handle> --mode bugbounty [flags]
  --program string     HackerOne handle or Bugcrowd code
  --submit             Submit confirmed findings via API (requires confirmation)
  --format h1|bc       Report format (hackerone or bugcrowd)

autopentest bb programs                    # List configured programs
autopentest bb scope <handle>              # Show program scope
autopentest bb submissions <handle>        # List previous submissions
```

**Acceptance Criteria:**
- [ ] `HackerOneClient.GetScope` correctly parses in-scope and out-of-scope assets for a real H1 program
- [ ] Scope importer converts H1 scope to `ScopeDefinition` with correct CIDR/domain entries
- [ ] Duplicate detector flags a finding with cosine similarity > 0.85 to an existing submission
- [ ] H1 report format passes H1's report submission validation (no required fields missing)
- [ ] Bug bounty mode auto-imports scope and user never needs to manually define `--scope`

**Dependencies:** Sprints 2, 4, 6, 7

---

### Sprint 12 — Synthetic Training Data Generation
**Duration:** 2 weeks
**Goal:** Generate high-quality synthetic training datasets for all four specialist models using Claude as the data generation engine.

**Why this sprint matters:** The fine-tuned models are the moat. Training data quality determines model quality. A well-curated dataset cannot be copied by forking the repository.

#### 12.1 Data Generator Framework (`training/generate_data.py`)
- Implement `SyntheticDataGenerator` using `anthropic` Python SDK:
  - `generate_batch(prompt_template, variables, n) -> list[dict]`: generates N samples by varying `variables` in the prompt template
  - `validate(sample, schema) -> bool`: validates each generated sample against a Pydantic schema
  - `deduplicate(samples) -> list[dict]`: removes samples with embedding cosine similarity > 0.9
  - `score_quality(sample) -> float`: prompts Claude to score sample 1-5 on accuracy, completeness, format; keeps only ≥4
  - Outputs Alpaca-format JSONL: `{"instruction": "...", "input": "...", "output": "..."}`
  - Outputs ShareGPT-format JSONL: `{"conversations": [{"from": "human", "value": "..."}, {"from": "gpt", "value": "..."}]}`

#### 12.2 Recon Agent Training Data (`training/generate_recon_data.py`)
- **Target:** 50,000 samples
- **Format:** input = raw tool output (nmap XML + subfinder JSON + httpx JSONL), output = structured `AttackSurface` JSON
- **Generation:**
  - Define 200 synthetic host profiles: varies OS, open ports, services, versions, web apps
  - For each profile: generate realistic nmap XML, subfinder subdomain list, httpx output using Claude
  - Prompt Claude to produce the correct `AttackSurface` JSON given those tool outputs
  - Include edge cases: hosts with no open ports, hosts with unusual services, heavily filtered hosts
- **Splits:** 45,000 train / 4,000 validation / 1,000 test

#### 12.3 Classifier Agent Training Data (`training/generate_classifier_data.py`)
- **Target:** 30,000 samples
- **Format:** input = `RawFinding` JSON, output = `ClassifiedFinding` JSON with CVE, CVSS, severity, category
- **Generation:**
  - Source 5,000 real CVE descriptions from NVD (public data) as ground truth
  - Generate 3 synthetic finding descriptions per CVE (varying detail level, scanner output format)
  - Generate 5,000 false positive examples: realistic-looking findings that are actually benign
  - Generate 5,000 multi-CVE findings: one finding maps to multiple CVEs
- **Splits:** 27,000 train / 2,000 validation / 1,000 test

#### 12.4 Exploit Agent Training Data (`training/generate_exploit_data.py`)
- **Target:** 40,000 samples (most data, hardest task)
- **Format:** input = `ClassifiedFindingSet` JSON + objective, output = `AttackPlan` JSON with `<think>` chain-of-thought
- **Generation sources:**
  - Parse 2,000 public CTF writeups (HackTheBox, TryHackMe, VulnHub) into finding → attack chain structures using Claude
  - Parse 500 public HackerOne disclosed reports into finding → exploitation path structures
  - Generate 15,000 novel scenarios: synthetic target profiles with 3-8 findings, Claude constructs attack chains with full reasoning
  - Generate 5,000 negative examples: findings that don't chain, dead-end attack paths
- **Include `<think>` traces:** every sample has explicit chain-of-thought before JSON output — required for DeepSeek R1 fine-tuning
- **Splits:** 36,000 train / 3,000 validation / 1,000 test

#### 12.5 Report Agent Training Data (`training/generate_report_data.py`)
- **Target:** 20,000 samples
- **Format:** input = campaign findings summary, output = report section (executive summary / finding writeup / remediation)
- **Generation sources:**
  - Source structure from public pentest report templates and example reports
  - Generate 5,000 executive summary samples: varying finding types, target industries, severity distributions
  - Generate 10,000 individual finding writeup samples: all OWASP Top 10 categories, all severity levels
  - Generate 5,000 remediation plan samples: varying priorities, technical contexts
- **Splits:** 18,000 train / 1,000 validation / 1,000 test

#### 12.6 Data Quality Pipeline (`training/quality_pipeline.py`)
- Implement automated quality gates:
  - Schema validation: every sample passes its Pydantic schema
  - Claude quality scoring: samples scoring <4/5 are discarded
  - Diversity check: compute token distribution per field; flag if one value dominates >20% of samples
  - Embedding dedup: remove samples with >0.9 cosine similarity to any existing sample
- Implement dataset statistics report: samples per category, average quality score, coverage analysis per vulnerability type
- All datasets versioned with hash in filename: `recon_v1_50k_a3f2b1.jsonl`

**Acceptance Criteria:**
- [ ] Data generator produces valid Alpaca-format JSONL with no schema violations
- [ ] Recon dataset: 50k samples, 100% valid `AttackSurface` JSON outputs
- [ ] Exploit dataset: 40k samples, 100% contain `<think>` reasoning traces before JSON
- [ ] Quality pipeline rejects samples scoring <4/5 and produces statistics report
- [ ] Deduplication removes at least 5% of generated samples (verifies dedup is working)

**Dependencies:** Sprint 0 (Claude API access), Sprint 2 (data model schemas)

---

### Sprint 13 — Model Fine-Tuning & Publishing
**Duration:** 2 weeks
**Goal:** Fine-tune all four specialist models on curated datasets and publish to `ArmurAI` on HuggingFace Hub.

**Why this sprint matters:** This sprint creates the proprietary models that are the platform's moat. A competitor can fork the code. They cannot fork the models without the training data and compute.

#### 13.1 Fine-Tuning Infrastructure (`training/`)
- Use **Unsloth** for all fine-tuning: 2× faster than standard HuggingFace, 70% less VRAM, supports all 4 base models
- Use **QLoRA** (4-bit quantization + LoRA): fine-tune on single A100 (80GB) or 2× RTX 4090 (24GB each)
- All training scripts parameterized via config, reproducible with fixed seeds
- Training runs on RunPod/Lambda Labs GPU instances; `training/Makefile` automates spin-up and teardown
- All checkpoints saved to HuggingFace Hub every 500 steps (resumable if interrupted)

#### 13.2 Recon Model (`training/train_recon.py`)
- Base: `Qwen/Qwen2.5-7B-Instruct`
- Dataset: `data/recon/recon_v1_50k_*.jsonl` (45k train / 4k val)
- LoRA config: `r=64`, `lora_alpha=16`, target modules: all linear layers
- Training: 3 epochs, batch 4, grad accumulation 8, cosine LR schedule, warmup 100 steps
- Eval metric: `AttackSurface` JSON validity rate on 1k test set; target >95%
- Publish: `ArmurAI/recon-agent-qwen2.5-7b` with model card documenting: base model, dataset stats, eval results, usage example

#### 13.3 Classifier Model (`training/train_classifier.py`)
- Base: `mistralai/Mistral-7B-Instruct-v0.3`
- Dataset: `data/classifier/classifier_v1_30k_*.jsonl` (27k train / 2k val)
- LoRA config: `r=64`, `lora_alpha=16`, 2 epochs
- Eval metrics: CVE mapping accuracy, CVSS MAE, FP recall; targets: >85% CVE accuracy, CVSS MAE <0.5, >90% FP recall
- Publish: `ArmurAI/classifier-agent-mistral-7b`

#### 13.4 Exploit Model (`training/train_exploit.py`)
- Base: `deepseek-ai/DeepSeek-R1-Distill-Llama-8B`
- Dataset: `data/exploit/exploit_v1_40k_*.jsonl` (36k train / 3k val)
- LoRA config: `r=128` (higher rank — complex reasoning task), 3 epochs
- Special: do NOT filter out `<think>` tokens; they are part of the training target for R1 models
- Eval metrics: `AttackPlan` JSON validity rate, step sequence coherence score, expert eval on 200 sampled outputs (1-5 scale); target: >85% valid JSON, expert score >4/5
- Publish: `ArmurAI/exploit-agent-deepseek-r1-8b`

#### 13.5 Report Model (`training/train_report.py`)
- Base: `meta-llama/Llama-3.1-8B-Instruct`
- Dataset: `data/report/report_v1_20k_*.jsonl` (18k train / 1k val)
- LoRA config: `r=64`, 2 epochs
- Eval metrics: ROUGE-L vs reference reports, human eval on 100 samples; target: ROUGE-L >0.6, human score >4/5
- Publish: `ArmurAI/report-agent-llama3.1-8b`

#### 13.6 Model Registry & Versioning (`internal/models/registry.go`)
- Implement `ModelRegistry`:
  - `Pull(ctx, modelName, version string) error`: downloads from HuggingFace Hub via Ollama pull; verifies SHA256 checksum
  - `List(ctx) ([]ModelInfo, error)`: lists available models with version, size, pulled status
  - `IsAvailable(ctx, modelName string) bool`: checks if model is pulled and responding to test prompt
  - `Update(ctx, modelName string) error`: pull latest version if newer than installed
- Version pins: `internal/models/versions.go` — constants for each model's current production version; updated on each model release
- `autopentest models pull` calls `ModelRegistry.Pull` for all 4 models

#### 13.7 Model Cards (HuggingFace)
- Write `README.md` for each model on HuggingFace with:
  - What the model does (one paragraph)
  - How it fits into the Auto-Pentest-GPT-AI architecture
  - Base model and training approach
  - Evaluation results with numbers
  - Usage example (how to call it via Ollama)
  - Limitations and responsible use notice

**Acceptance Criteria:**
- [ ] All 4 models published to `ArmurAI` org on HuggingFace Hub
- [ ] Recon model achieves >95% valid JSON on 1k test set
- [ ] Exploit model achieves >85% valid `AttackPlan` JSON on 1k test set
- [ ] `autopentest models pull` downloads all 4 models and verifies checksums
- [ ] All 4 models run via Ollama on a MacBook Pro M2 with 16GB RAM without OOM errors

**Dependencies:** Sprint 12

---

### Sprint 14 — API, Documentation & Developer Experience
**Duration:** 2 weeks
**Goal:** Complete REST API with OpenAPI spec, comprehensive documentation covering every feature, and a developer SDK. This is what turns users into contributors and integrators.

**Why this sprint matters:** Documentation is not optional — it is the product for developers. Every hour spent on clear docs pays back 10x in reduced support burden and increased adoption. This sprint treats docs as a first-class deliverable.

#### 14.1 REST API Completion (`internal/api/`)
- Complete all API routes with consistent error responses:
  - All errors: `{"error": {"code": "SCOPE_VIOLATION", "message": "...", "details": {...}}}`
  - All success lists: `{"data": [...], "meta": {"total": N, "page": 1, "per_page": 20}}`
  - All timestamps in RFC3339 format
- Rate limiting: 100 req/min per API key using Redis token bucket
- Authentication: `X-API-Key` header, keys stored as bcrypt hashes in DB; generate via `autopentest config api-key create`
- CORS: allow configured origins (for dashboard on different port during development)

#### 14.2 OpenAPI Specification
- Annotate all Fiber handlers with `swag` doc comments
- Run `swag init` to generate `docs/swagger.json` and `docs/swagger.yaml`
- Serve Swagger UI at `GET /api/docs` in development mode
- Every endpoint documented with: description, all parameters, all possible response schemas, example request and response bodies
- Publish OpenAPI spec to `docs/api-reference.md` as rendered Markdown for GitHub browsing

#### 14.3 Documentation Site (`docs/`)
- Write `docs/README.md`: documentation index, links to all doc pages
- Write `docs/quickstart.md`:
  - Prerequisites: Go 1.22, Docker, Ollama
  - 5 commands from zero to first completed scan
  - Expected output at each step
  - What to do if each step fails
- Write `docs/architecture.md`:
  - System architecture diagram (Mermaid, rendered as PNG)
  - Description of each component and its responsibilities
  - Data flow walkthrough: trace a single finding from recon tool output through all agents to report
  - Decision log: why Go, why these 4 base models, why custom agent framework
- Write `docs/cli-reference.md`:
  - Every command documented with: description, syntax, all flags with types/defaults/descriptions, examples (at least 3 per command), common error messages and fixes
  - Generated from Cobra's built-in `--help` output plus manual additions
- Write `docs/api-reference.md`:
  - Generated from OpenAPI spec
  - Every endpoint: method + path, description, authentication requirement, request body schema, response schemas, example curl request, example response
- Write `docs/configuration.md`:
  - Every field in `config.yaml` documented: type, default, valid values, description, which component uses it
  - Environment variable override names for every field
  - Example configs for 3 deployment scenarios: local development, team server, CI/CD integration
- Write `docs/providers.md`:
  - Step-by-step setup for Claude (get API key, set in config, verify with `doctor`)
  - Step-by-step setup for Ollama (install, pull models, configure endpoint, verify)
  - Step-by-step setup for LM Studio (download, load model, enable server, configure endpoint)
  - Comparison table: capability, privacy, cost, setup effort
- Write `docs/continuous-asm.md`:
  - What continuous ASM is and why it matters
  - How to add a watched scope
  - How notifications work (Slack/email/webhook setup)
  - How auto-triggered campaigns work and how to configure them
  - How to read the asset change history
- Write `docs/bug-bounty.md`:
  - How to connect HackerOne / Bugcrowd account
  - How bug bounty mode works end-to-end
  - How duplicate detection works
  - How to generate and submit reports
  - Example workflow: morning routine for a bug bounty hunter
- Write `docs/fine-tuning.md`:
  - Overview of the 4 models and their roles
  - How to reproduce fine-tuning (requirements, commands, expected time and cost)
  - How to contribute training data (format, quality criteria, submission process)
  - How to add a new specialist model to the architecture

#### 14.4 Python SDK (`sdk/python/`)
- Create separate Python package `autopentest-sdk` in `sdk/python/`
- `pip install autopentest-sdk` installable package
- Implement `AutoPentestClient`:
  ```python
  client = AutoPentestClient(api_url="http://localhost:8080", api_key="...")
  campaign = client.campaigns.create(target="example.com", objective="find RCE", scope=["example.com"])
  campaign.start()
  for event in campaign.stream():          # streaming generator
      print(event.type, event.data)
  report = campaign.get_report(format="json")
  ```
- Full async variant: `AsyncAutoPentestClient` with `async for event in campaign.astream()`
- Publish to PyPI under `autopentest-sdk`
- Write `sdk/python/README.md` with complete usage examples
- Write `sdk/python/examples/`: 3 example scripts (basic scan, bug bounty scan, continuous ASM integration)

#### 14.5 Contributing Guide
- Write `CONTRIBUTING.md`:
  - How to set up development environment
  - How to add a new recon tool (step-by-step with example)
  - How to add a new CLI command (step-by-step)
  - How to contribute training data (format + quality standards)
  - Code style guide (Go formatting, naming conventions, error handling patterns)
  - PR review checklist
  - How to report security vulnerabilities (responsible disclosure)

**Acceptance Criteria:**
- [ ] Every API endpoint returns consistent error format on failure
- [ ] `docs/quickstart.md` takes a new user from zero to first completed scan in under 15 minutes (verified by user test)
- [ ] OpenAPI spec validates against OpenAPI 3.0 schema with zero errors
- [ ] Python SDK `client.campaigns.create(...).start()` creates and starts a real campaign
- [ ] Every CLI command has at least 3 documented examples in `docs/cli-reference.md`
- [ ] `docs/configuration.md` covers every field in `config.example.yaml`

**Dependencies:** Sprints 8, 9

---

### Sprint 15 — Distribution & Ecosystem
**Duration:** 2 weeks
**Goal:** Make Auto-Pentest-GPT-AI available through every channel a security professional, developer, or team might use. Zero friction from discovery to first scan.

**Why this sprint matters:** The best tool in the world is useless if people can't install it. Distribution is not an afterthought — it is the difference between 200 stars and 20,000.

#### 15.1 Go Release Binary (GitHub Actions)
- Write `.github/workflows/release.yml`: triggers on `git tag v*`
- Build matrix: `GOOS=linux GOARCH=amd64`, `GOOS=linux GOARCH=arm64`, `GOOS=darwin GOARCH=amd64`, `GOOS=darwin GOARCH=arm64`, `GOOS=windows GOARCH=amd64`
- Embed web dashboard (`web/dist/`) in binary using `//go:embed`
- Strip debug info (`-ldflags="-s -w"`) to minimize binary size
- Sign binaries with `cosign` (supply chain security)
- Generate SHA256 checksums file
- Create GitHub Release with: changelog (from `CHANGELOG.md`), all binaries, checksums, release notes template

#### 15.2 Homebrew Tap (`deploy/homebrew/`)
- Create `armur-ai/homebrew-tap` repository
- Write `Formula/autopentest.rb`:
  - Downloads correct binary for OS/arch from GitHub Release
  - Verifies SHA256 checksum
  - Installs binary to `$(brew --prefix)/bin/autopentest`
  - Installs shell completions for bash/zsh/fish
  - Runs `autopentest doctor` as post-install check
- Write GitHub Actions in the tap repo to auto-update formula on new releases
- Test: `brew install armur-ai/tap/autopentest` on macOS arm64 and amd64

#### 15.3 Linux Install Script (`deploy/install.sh`)
```bash
curl -sSL https://install.autopentest.ai/install.sh | sh
```
- Detects OS and architecture
- Downloads correct binary from GitHub Releases
- Verifies SHA256 checksum
- Installs to `/usr/local/bin/autopentest`
- Sets up shell completions
- Runs `autopentest doctor` to verify installation
- Idempotent: safe to run multiple times
- Hosts at `install.autopentest.ai` (Cloudflare Pages, static file serving)

#### 15.4 Docker Images
- Write `deploy/docker/Dockerfile`:
  - Multi-stage build: stage 1 builds Go binary + React assets; stage 2 is minimal Alpine + binary
  - All native Go security tools compiled into the binary (no subprocess for subfinder/httpx/etc.)
  - Tools that require external install (nuclei templates): downloaded on first run
  - Final image: ~150MB
- Write `deploy/docker/Dockerfile.gpu`: extends base with Ollama pre-installed, models downloaded on first run
- Push to Docker Hub: `armurai/autopentest:latest`, `armurai/autopentest:v{version}`, `armurai/autopentest:gpu`
- Push to GitHub Container Registry: `ghcr.io/armur-ai/autopentest`
- Write GitHub Actions to push on every release tag

#### 15.5 Docker Compose (`deploy/docker-compose.yml`)
- Services: `autopentest` (Go backend + dashboard), `postgres`, `redis`, `ollama`
- `ollama` service: starts Ollama, then runs model pull for all 4 specialist models on first startup (using entrypoint script with `ollama pull` commands)
- First-run experience: `docker compose up` → wait ~10 min for models to download → visit `http://localhost:8080` → dashboard is live
- Write `deploy/docker-compose.gpu.yml`: enables GPU passthrough for Ollama (NVIDIA CUDA + AMD ROCm variants)
- Write `deploy/docker-compose.dev.yml`: adds hot-reload, mounts source code, enables debug logging
- Write `deploy/docker-compose.yml` README section explaining every service and env var

#### 15.6 npm Package (`deploy/npm/`)
- Create `@armurai/autopentest` npm package
- `npx @armurai/autopentest scan <target>`: downloads correct platform binary on first run, runs it
- `package.json`: `bin` field pointing to node shim that downloads binary if not present
- Shim downloads from GitHub Releases, verifies checksum, caches at `~/.autopentest/bin/`
- Publish to npm registry
- Usage: `npx @armurai/autopentest scan example.com --scope example.com` with no prior installation

#### 15.7 Shell Completions
- Implement Cobra completion commands: `autopentest completion bash`, `autopentest completion zsh`, `autopentest completion fish`, `autopentest completion powershell`
- Homebrew formula installs completions automatically
- Docker image includes completions in `/etc/bash_completion.d/`
- `docs/quickstart.md` includes one-liner to add completions to shell profile

#### 15.8 Helm Chart (`deploy/helm/autopentest/`)
- Write Helm chart for Kubernetes deployment:
  - `Chart.yaml`: name, version, description, dependencies (postgresql, redis bitnami charts)
  - `values.yaml`: all configurable values with defaults and comments
  - `templates/deployment.yaml`: autopentest deployment with resource limits, liveness/readiness probes
  - `templates/ollama-deployment.yaml`: Ollama deployment with GPU node selector and model init container
  - `templates/service.yaml`, `templates/ingress.yaml`
  - `templates/hpa.yaml`: HorizontalPodAutoscaler for API replicas
  - `templates/secret.yaml`: manages API keys and DB credentials
- Test: `helm install autopentest ./deploy/helm/autopentest` deploys cleanly to a test K8s cluster
- Publish chart to GitHub Pages Helm repository

#### 15.9 GitHub Action (`deploy/github-action/`)
- Create `armur-ai/autopentest-action` — a GitHub Action for CI/CD security scanning:
  ```yaml
  # In any repo's .github/workflows/security.yml:
  - uses: armur-ai/autopentest-action@v1
    with:
      target: ${{ env.STAGING_URL }}
      scope: "staging.example.com"
      provider: claude
      api-key: ${{ secrets.ANTHROPIC_API_KEY }}
      fail-on: high    # Fail the PR if High/Critical findings
      format: sarif     # GitHub Security tab integration
  ```
- Outputs: SARIF file (uploads to GitHub Security tab), Markdown summary (appears in PR comment), JSON findings (for downstream jobs)
- `fail-on` flag: `critical`, `high`, `medium`, `low` — fails the GitHub check if findings at or above that severity are found
- SARIF integration means findings appear directly in GitHub's Security tab and inline on PR diffs
- Runs in Docker container with prebuilt image from `ghcr.io/armur-ai/autopentest`
- This is a massive distribution vector: once one developer adds this to their CI, every PR reviewer sees the tool's output
- Publish to GitHub Marketplace

#### 15.10 `go install` Support
- Ensure `cmd/autopentest/main.go` is the single entrypoint, so users can run:
  ```
  go install github.com/Armur-Ai/autopentest/cmd/autopentest@latest
  ```
- No CGO dependency — pure Go so cross-compilation just works
- This is expected by every Go developer; missing it is a credibility hit
- No public download metrics, but table-stakes for the Go ecosystem

#### 15.11 Snap Store (Linux)
- Create `deploy/snap/snapcraft.yaml`:
  ```yaml
  name: autopentest
  summary: AI-powered autonomous penetration testing
  description: |
    Multi-agent AI system that autonomously performs full-cycle penetration tests.
  grade: stable
  confinement: classic  # needs network + filesystem access
  ```
- Build snap via GitHub Actions on every release
- Publish to Snap Store under `armurai` publisher account
- **Why Snap matters:** public install count visible on snapcraft.io page — trackable metric
- `sudo snap install autopentest --classic` — reaches Ubuntu/Debian/Fedora users
- Snap auto-updates: users stay on latest version without manual intervention

#### 15.12 Windows Package Managers
- **Winget** (`deploy/winget/`):
  - Create manifest YAML for Windows Package Manager Community Repository
  - Submit PR to `microsoft/winget-pkgs` on each release via GitHub Actions
  - `winget install ArmurAI.autopentest` — reaches Windows enterprise users
  - Install stats visible on winget.run
- **Scoop** (`deploy/scoop/`):
  - Create bucket JSON for Scoop
  - Host in `armur-ai/scoop-bucket` repo
  - `scoop bucket add armurai https://github.com/armur-ai/scoop-bucket && scoop install autopentest`
  - Scoop is popular with Windows power users and security researchers

#### 15.13 GitHub Repository Polish
- Write root `README.md` with:
  - One-sentence description + screenshot of live watch TUI
  - Architecture diagram (Mermaid rendered as PNG)
  - Feature list with icons
  - Quick install section: 3 tabs — Homebrew / Docker / Linux
  - Quick start: 3 commands to first scan
  - Agent roster table
  - HuggingFace model links
  - Contributing + community links
- Write `CHANGELOG.md` following Keep a Changelog format
- Configure GitHub repository: description, topics (`penetration-testing`, `security`, `ai`, `golang`, `bug-bounty`, `llm`, `agents`), website URL, social preview image
- Enable GitHub Discussions for community Q&A
- Write issue templates: bug report, feature request, training data contribution

**Acceptance Criteria:**
- [ ] `brew install armur-ai/tap/autopentest` installs and runs on macOS arm64
- [ ] `curl -sSL https://install.autopentest.ai/install.sh | sh` installs on Ubuntu 22.04
- [ ] `npx @armurai/autopentest scan example.com --scope example.com` runs without prior installation
- [ ] `docker compose up` reaches a working dashboard state with no manual steps beyond waiting for model downloads
- [ ] `helm install autopentest ./deploy/helm/autopentest` deploys all services to test K8s cluster
- [ ] GitHub Release includes signed binaries for all 5 platform/arch combinations with checksum file
- [ ] GitHub Action runs in a test repo, produces SARIF output, and findings appear in GitHub Security tab
- [ ] GitHub Action fails the check when `fail-on: high` is set and a High severity finding is detected
- [ ] GitHub Action posts a Markdown summary as a PR comment
- [ ] `go install github.com/Armur-Ai/autopentest/cmd/autopentest@latest` compiles and runs
- [ ] Snap package installs and runs on Ubuntu 22.04
- [ ] `winget install ArmurAI.autopentest` installs on Windows 11
- [ ] Each distribution channel has publicly visible download/install metrics

**Dependencies:** Sprints 8, 9, 13

---

### Sprint 16 — End-to-End Testing & Launch Preparation
**Duration:** 1 week
**Goal:** Comprehensive testing against real vulnerable targets, performance hardening, and everything needed for a polished public launch.

#### 16.1 Test Lab Setup
- Spin up intentionally vulnerable targets in isolated Docker network:
  - `webgoat/goat-and-wolf` (OWASP WebGoat — known web vulns)
  - `vulhub/` containers (known CVE reproductions)
  - Custom target: a deliberately misconfigured web app with: SQLi, XSS, exposed `.git`, default credentials, exposed admin panel
- Write `tests/e2e/full_campaign_test.go`: runs complete campaign against WebGoat, asserts:
  - At least 5 findings discovered
  - At least 1 Critical or High severity finding classified
  - Attack plan constructed with at least 2 paths
  - Report generated with all sections populated
  - Campaign completes in under 20 minutes

#### 16.2 Performance Benchmarks
- Benchmark recon phase: measure time from `ReconAgent.Execute` start to `AttackSurface` returned
  - Target: under 5 minutes for a domain with <20 subdomains
- Benchmark classification: measure time for `ClassifierAgent.Classify` on 50 findings
  - Target: under 60 seconds
- Benchmark report generation: time from `ReportAgent.Generate` call to PDF written
  - Target: under 90 seconds
- Profile memory usage during a full campaign: target peak <2GB RAM
- Identify and fix top 3 bottlenecks found in profiling

#### 16.3 Competitor Benchmarks
- Run autopentest, PentestGPT, CAI, and PentAGI against the same 3 vulnerable targets (WebGoat, DVWA, custom target)
- Measure and publish comparison table:
  | Metric | autopentest | PentestGPT | CAI | PentAGI |
  |--------|-------------|------------|-----|---------|
  | Findings discovered | | | | |
  | True positive rate | | | | |
  | Time to complete | | | | |
  | Report quality (1-5) | | | | |
  | Install friction (steps) | | | | |
  | Privacy (local option) | | | | |
- Publish as `docs/benchmarks.md` with methodology, raw data, and reproduction instructions
- Include in README with a summary table — concrete numbers drive adoption more than feature lists
- Update benchmarks with each major release

#### 16.4 Security Review
- Review all subprocess executions: verify scope validation is called for every one
- Review all DB queries: verify parameterized queries everywhere, no string concatenation
- Review API authentication: verify every endpoint requires API key except health check
- Review file writes: verify no user-controlled input reaches file paths without sanitization
- Fix all findings before launch

#### 16.5 Launch Assets
- Record demo GIF (15 seconds): `autopentest scan --follow` showing live watch TUI — orchestrator thoughts scrolling, findings appearing, completion
- Record demo video (3 minutes): full walkthrough from install to report download, posted to YouTube
- Write HackerNews launch post: "Show HN: Auto-Pentest-GPT-AI — autonomous AI pentesting in Go with 4 fine-tuned specialist models"
- Write Reddit posts for: r/netsec, r/bugbounty, r/golang, r/selfhosted
- Create Twitter/X thread: architecture diagram + demo GIF + key differentiators
- Tag `v1.0.0` release

**Acceptance Criteria:**
- [ ] E2E test finds at least 5 real vulnerabilities in WebGoat and generates a valid PDF report
- [ ] Full campaign completes in under 20 minutes on a MacBook Pro M2
- [ ] Zero security review findings remain unresolved at launch
- [ ] Demo GIF clearly shows live orchestrator thought streaming
- [ ] `v1.0.0` GitHub Release is published with all distribution artifacts

**Dependencies:** Sprints 0–15

---

### Sprint 17 — Plugin System & Community Playbooks
**Duration:** 2 weeks
**Goal:** Build an extension system that lets the community contribute attack playbooks, custom tool integrations, and report templates — creating the nuclei-templates-style moat.

**Why this sprint matters:** Nuclei has 8,000+ community templates. Metasploit has 4,000+ modules. The engine is open source, but the community's accumulated knowledge is the moat. This sprint creates the foundation for that flywheel.

#### 17.1 Playbook Format (`internal/plugins/playbook.go`)
- Define YAML playbook format:
  ```yaml
  # playbooks/aws-cloud-audit.yaml
  name: AWS Cloud Security Audit
  description: Comprehensive assessment of AWS-hosted applications
  author: community
  version: 1.0.0
  tags: [aws, cloud, infrastructure]

  variables:
    target_domain:
      type: string
      required: true
    aws_region:
      type: string
      default: us-east-1

  phases:
    - name: cloud_recon
      tools:
        - name: subfinder
          options: { recursive: true }
        - name: httpx
          options: { followRedirects: true }
      post_analysis: |
        Identify any AWS-specific endpoints (S3 buckets, API Gateway,
        CloudFront distributions, ELB endpoints). Flag any that are
        publicly accessible without authentication.

    - name: aws_specific_checks
      tools:
        - name: nuclei
          options:
            templates: ["cloud/aws/**"]
        - name: custom_script
          command: "python3 scripts/s3_bucket_check.py {{target_domain}}"
      post_analysis: |
        Classify all AWS misconfigurations by severity. Check for:
        S3 bucket policies, IAM role exposure, metadata endpoint access.

    - name: exploitation
      conditions:
        - findings.severity >= "high"
      strategy: |
        Focus on SSRF → metadata endpoint → IAM credential chains.
        Test S3 bucket write access on any writable buckets found.
  ```
- Implement `PlaybookParser`: validates YAML against schema, resolves variables, expands tool references
- Implement `PlaybookExecutor`: feeds playbook phases to orchestrator as structured objectives with tool constraints
- Playbooks can reference other playbooks (composition): `include: common/web-basics.yaml`

#### 17.2 Custom Tool Integration
- Allow defining external tools via YAML in `~/.autopentest/plugins/tools/`:
  ```yaml
  # ~/.autopentest/plugins/tools/trufflehog.yaml
  name: trufflehog
  description: Scan for leaked secrets in git repos
  command: trufflehog git {{target}} --json
  output_format: jsonl
  finding_parser:
    type_field: "DetectorName"
    severity: high
    title_template: "Secret found: {{DetectorName}} in {{SourceMetadata.Data.Git.file}}"
  scope_check: false  # trufflehog scans repos, not network targets
  ```
- Custom tools are available alongside native Go tools; the orchestrator can decide to use them
- Scope validation applies unless `scope_check: false`

#### 17.3 Custom Report Templates
- Allow custom HTML/Markdown report templates in `~/.autopentest/plugins/reports/`
- Templates use Go `text/template` syntax with the `PentestReport` struct as data context
- Bundled templates: `default`, `executive-brief`, `compliance-focused`, `bug-bounty-submission`
- `autopentest report <campaign-id> --template compliance-focused`

#### 17.4 Community Playbook Registry (`internal/plugins/registry.go`)
- Implement `Registry` client:
  - `Search(query string) []PlaybookInfo`: search community playbook index
  - `Install(name, version string) error`: download from GitHub `armur-ai/autopentest-playbooks` repo
  - `Update() error`: update all installed community playbooks
  - `Publish(path string) error`: validate + submit PR to community repo (authenticated via GitHub)
- Community repo: `armur-ai/autopentest-playbooks` — structured like nuclei-templates:
  ```
  playbooks/
  ├── cloud/
  │   ├── aws-full-audit.yaml
  │   ├── gcp-assessment.yaml
  │   └── azure-security.yaml
  ├── web/
  │   ├── owasp-top10.yaml
  │   ├── api-security.yaml
  │   └── wordpress-full.yaml
  ├── network/
  │   ├── internal-pentest.yaml
  │   └── wireless-assessment.yaml
  └── compliance/
      ├── pci-dss.yaml
      ├── hipaa.yaml
      └── soc2.yaml
  ```
- CLI commands:
  ```
  autopentest playbook search <query>       # Search community playbooks
  autopentest playbook install <name>       # Install a playbook
  autopentest playbook list                 # List installed playbooks
  autopentest playbook update               # Update all playbooks
  autopentest playbook run <name> [flags]   # Run a playbook
  autopentest playbook create               # Scaffold a new playbook
  autopentest playbook validate <path>      # Validate a playbook YAML
  autopentest playbook publish <path>       # Submit to community registry
  ```

#### 17.5 Contributor Attribution & Playbook Stats
- Every playbook YAML has an `author` field with GitHub username:
  ```yaml
  author:
    name: "SecurityResearcher42"
    github: "secresearcher42"
  ```
- `autopentest playbook stats <name>`: shows how many times a playbook has been used, findings discovered, average severity
- `autopentest playbook leaderboard`: shows top contributors ranked by playbook usage across the community
- Playbook stats are opt-in: when a playbook completes, anonymized usage data (playbook name + finding count + severity distribution) is submitted to a stats API
- README badge: "Powered by 500+ community playbooks" — auto-updated from registry stats
- Monthly "Top Contributor" recognition in the community repo README and Discord
- This creates social incentive to contribute — contributors gain reputation in the security community

#### 17.6 Playbook Auto-Update & Discovery
- `autopentest playbook update` runs on a configurable schedule (default: weekly)
- New playbook notification: "3 new playbooks available matching your scan history" — based on tech stacks you've scanned before
- `autopentest playbook recommend <target>`: analyzes target and suggests relevant community playbooks
- Playbook dependency resolution: if a playbook requires a custom tool plugin, auto-install it

#### 17.7 Tests
- `tests/unit/plugins/playbook_test.go`: parse valid/invalid playbooks, verify variable resolution, test phase execution order
- `tests/unit/plugins/registry_test.go`: mock registry API, verify install/search/update
- `tests/integration/playbook_test.go`: run `owasp-top10.yaml` playbook against WebGoat, verify findings

**Acceptance Criteria:**
- [ ] YAML playbook parses and executes correctly, producing findings equivalent to manual orchestrator campaign
- [ ] Custom tool defined via YAML is available to the orchestrator and produces parseable findings
- [ ] `autopentest playbook install aws-full-audit` downloads and installs from community registry
- [ ] Playbook composition (`include:`) correctly merges phases from included playbooks
- [ ] `autopentest playbook validate` catches malformed YAML with actionable error messages

**Dependencies:** Sprints 3, 6, 8

---

### Sprint 18 — MCP Server Mode
**Duration:** 1 week
**Goal:** Expose autopentest as an MCP (Model Context Protocol) server so Claude Desktop, Cursor, Windsurf, and any MCP-compatible AI can use pentesting tools directly.

**Why this sprint matters:** MCP is exploding in 2026. Every Claude Desktop and Cursor user is a potential autopentest user if they can add it with a single line in their MCP config. This is the highest-leverage distribution channel available right now — it puts the tool inside the IDE/chat interface people already live in.

#### 18.1 MCP Server (`internal/mcp/server.go`)
- Implement MCP server using the `mcp-go` SDK (or equivalent Go MCP library)
- Server runs as: `autopentest mcp serve` (stdio mode for Claude Desktop) or `autopentest mcp serve --transport sse --port 3001` (SSE mode for web clients)
- Register as MCP server in Claude Desktop config:
  ```json
  {
    "mcpServers": {
      "autopentest": {
        "command": "autopentest",
        "args": ["mcp", "serve"]
      }
    }
  }
  ```

#### 18.2 MCP Tools (`internal/mcp/tools.go`)
- Expose the following as MCP tools (callable by any connected AI):
  - `scan_target`: start a full autonomous scan — args: `target`, `scope`, `objective`
  - `quick_recon`: run recon only, return attack surface — args: `target`
  - `check_vulnerability`: run nuclei with specific templates — args: `target`, `templates[]`
  - `classify_finding`: classify a raw finding with CVE/CVSS — args: `finding_description`, `target`
  - `explain_finding`: explain a vulnerability in plain English — args: `finding_id` or `cve_id`, `audience`
  - `generate_report`: generate report for a campaign — args: `campaign_id`, `format`
  - `port_scan`: run naabu port scan — args: `target`, `ports`
  - `crawl_urls`: run katana/gau URL discovery — args: `target`, `depth`
  - `search_findings`: semantic search across all findings — args: `query`
  - `campaign_status`: get current status of a campaign — args: `campaign_id`
- Every tool enforces scope validation — MCP doesn't bypass safety
- Every tool returns structured results that the AI can reason about

#### 18.3 MCP Resources (`internal/mcp/resources.go`)
- Expose the following as MCP resources (context the AI can read):
  - `campaign://{id}`: full campaign details with current status
  - `findings://{campaign_id}`: all findings for a campaign
  - `report://{campaign_id}`: generated report content
  - `memory://patterns`: learned attack patterns from memory system
  - `playbook://{name}`: playbook content for reference
- Resources are read-only and respect authentication

#### 18.4 MCP Prompts (`internal/mcp/prompts.go`)
- Pre-built prompt templates exposed to connected AI:
  - `security_assessment`: "Perform a comprehensive security assessment of {target}"
  - `explain_for_developers`: "Explain these findings to a development team with remediation code examples"
  - `bug_bounty_triage`: "Triage these findings for bug bounty submission — assess duplicates, impact, and report quality"
  - `compliance_check`: "Assess these findings against {framework} compliance requirements"

#### 18.5 Tests
- `tests/unit/mcp/server_test.go`: verify MCP protocol handshake, tool listing, tool execution
- `tests/integration/mcp_test.go`: start MCP server, connect client, call `quick_recon` tool, verify response

**Acceptance Criteria:**
- [ ] `autopentest mcp serve` starts and responds to MCP `initialize` handshake
- [ ] All MCP tools are listed in `tools/list` response with correct JSON Schema parameters
- [ ] `scan_target` MCP tool starts a real campaign and streams progress
- [ ] `quick_recon` MCP tool returns structured attack surface within 5 minutes
- [ ] Scope validation blocks out-of-scope targets even when called via MCP
- [ ] Claude Desktop can discover and use autopentest tools after adding to MCP config

**Dependencies:** Sprints 3, 6, 8

---

### Sprint 19 — CTF Mode
**Duration:** 1 week
**Goal:** Build an autonomous CTF-solving mode that can tackle HackTheBox and TryHackMe machines — the gateway drug that brings students, beginners, and content creators to the tool.

**Why this sprint matters:** The professional pentester audience is ~100k people. The CTF/learning audience is 10x that. Students share tools on YouTube, Twitter, and Discord. If autopentest can solve HTB boxes, every cybersecurity YouTuber will make a video about it. That's free marketing to millions.

#### 19.1 CTF Solver (`internal/ctf/solver.go`)
- Implement `CTFSolver`:
  - `Solve(ctx, target, platform, machineName string) (*CTFResult, error)`:
    1. Configure orchestrator with CTF-specific objective: "Find all flags (user.txt and root.txt)"
    2. Add CTF-specific orchestrator instructions: focus on privilege escalation chains, check common CTF patterns (SUID binaries, cron jobs, custom services)
    3. Run standard campaign flow but with CTF-tuned prompts
    4. On finding a flag: validate format, record it, continue to next flag
    5. Generate a writeup automatically
  - `CTFResult`: `Flags []Flag`, `AttackNarrative string`, `Writeup string`, `TimeElapsed time.Duration`
  - `Flag`: `Type string` (user/root), `Value string`, `Path string`, `Method string`

#### 19.2 Platform Clients (`internal/ctf/platforms.go`)
- Implement `HTBClient` (HackTheBox API):
  - `ListMachines(ctx) []Machine`: list available machines with difficulty/OS
  - `SpawnMachine(ctx, machineID) (*MachineInstance, error)`: spin up a machine, get target IP
  - `SubmitFlag(ctx, machineID, flag string) (bool, error)`: submit flag for verification
  - `GetMachineInfo(ctx, machineID) (*MachineInfo, error)`: difficulty, OS, tags
- Implement `THMClient` (TryHackMe API):
  - Equivalent methods for TryHackMe rooms
- Both clients handle authentication via API tokens configured in `config.yaml`

#### 19.3 Auto-Writeup Generator (`internal/ctf/writeup.go`)
- Implement `GenerateWriteup(ctx, campaign, flags []Flag) (string, error)`:
  - Uses report agent (or orchestrator) to generate a step-by-step writeup
  - Format follows standard CTF writeup structure:
    1. Machine info (name, difficulty, OS)
    2. Enumeration (what was found)
    3. Initial foothold (how access was gained)
    4. Privilege escalation (path to root)
    5. Flags captured
  - Output as Markdown, optionally as HTML
- `autopentest ctf writeup <campaign-id> --publish`: generates and optionally publishes to a blog/gist

#### 19.4 CLI Commands
```
autopentest ctf solve <target> [flags]
  --platform htb|thm|generic    # Platform (default: generic)
  --machine string               # Machine name (for auto-spawn)
  --follow                       # Stream live output

autopentest ctf list [flags]
  --platform htb|thm             # List available machines
  --difficulty easy|medium|hard  # Filter by difficulty
  --unsolved                     # Only show unsolved machines

autopentest ctf writeup <campaign-id>  # Generate writeup from completed CTF campaign
autopentest ctf submit <campaign-id>   # Submit found flags to platform
```

#### 19.5 Tests
- `tests/integration/ctf_test.go`: run CTF mode against a local Vulnhub-style container, verify at least one flag found

**Acceptance Criteria:**
- [ ] CTF mode finds user.txt flag on a deliberately vulnerable Docker container
- [ ] Auto-generated writeup follows standard CTF structure with all sections populated
- [ ] `autopentest ctf solve --platform htb --machine <name>` auto-spawns the machine, solves, and submits flags
- [ ] CTF-specific orchestrator prompts prioritize privilege escalation patterns

**Dependencies:** Sprints 6, 7, 8

---

### Sprint 20 — Integration Hub
**Duration:** 1 week
**Goal:** Deep integrations with the tools security teams already use — Jira, Slack, SIEM/SOAR platforms, and generic webhooks. Each integration raises switching cost.

**Why this sprint matters:** Every integration is a hook into an existing workflow. Once autopentest is wired into a team's Jira board, their Slack channels, and their SIEM, switching to a competitor means rewiring everything. This is switching cost as moat.

#### 20.1 Jira Integration (`internal/integrations/jira.go`)
- Implement `JiraClient`:
  - `CreateIssue(ctx, finding ClassifiedFinding, project, issueType string) (*JiraIssue, error)`:
    - Maps finding severity to Jira priority (Critical→P1, High→P2, etc.)
    - Title: `[autopentest] {finding.Title}`
    - Description: finding details in Jira wiki markup with evidence, CVSS score, remediation steps
    - Labels: `security`, `autopentest`, severity level
    - Custom fields: CVSS score, CVE IDs (configurable field mapping)
  - `BulkCreateIssues(ctx, findings []ClassifiedFinding, project string) ([]JiraIssue, error)`: batch creation
  - `LinkToExisting(ctx, findingID, issueKey string) error`: link a finding to an existing Jira issue
- Configuration: Jira URL, API token, project key, issue type, custom field mappings
- CLI: `autopentest report <campaign-id> --jira --project SECOPS`

#### 20.2 Slack Integration (`internal/integrations/slack.go`)
- Implement `SlackClient` beyond basic webhook (Sprint 10):
  - **Real-time campaign updates**: post to a channel when campaign starts, when critical findings discovered, when campaign completes
  - **Interactive bot**: `/autopentest scan <target>` slash command starts a campaign from Slack
  - **Finding alerts**: immediate Slack notification on Critical/High findings with severity badge, CVSS, and one-click link to full finding
  - **Daily digest**: summary of all ASM changes and new findings in the last 24h
  - **Thread-per-campaign**: each campaign gets its own thread; all updates go there to avoid noise
- Uses Slack Bot API with Socket Mode for interactive commands
- Configuration: Bot token, signing secret, default channel, alert threshold

#### 20.3 SIEM/SOAR Integration (`internal/integrations/siem.go`)
- Implement generic SIEM event forwarder:
  - Outputs findings in **CEF** (Common Event Format) for ArcSight/QRadar/Splunk
  - Outputs findings in **STIX 2.1** (Structured Threat Information Expression) for SOAR platforms
  - Outputs findings in **SARIF** (Static Analysis Results Interchange Format) for GitHub/GitLab Security
  - Syslog forwarding: UDP/TCP/TLS to any syslog receiver
- Each finding becomes a structured security event with: timestamp, severity, source, target, CVE, CVSS, evidence hash
- Configuration: SIEM type, endpoint, format, TLS cert paths
- CLI: `autopentest report <campaign-id> --siem --format cef --endpoint syslog://splunk.internal:514`

#### 20.4 Generic Webhook (`internal/integrations/webhook.go`)
- Already defined in Sprint 10 notifications, but expand to full webhook system:
  - Configurable events: `campaign.started`, `campaign.completed`, `finding.critical`, `finding.high`, `asm.change`, `report.generated`
  - Webhook payload: standardized JSON with event type, timestamp, campaign context, finding details
  - Retry with exponential backoff (3 retries, 1s/2s/4s)
  - HMAC signature verification header for webhook consumers to validate authenticity
  - Webhook management: `autopentest webhook add/list/remove/test`
- This lets teams integrate with anything: PagerDuty, OpsGenie, Teams, Discord, custom dashboards

#### 20.5 Tests
- `tests/unit/integrations/jira_test.go`: mock Jira API, verify issue creation with correct field mapping
- `tests/unit/integrations/slack_test.go`: mock Slack API, verify message formatting and thread creation
- `tests/unit/integrations/siem_test.go`: verify CEF and STIX output format compliance

**Acceptance Criteria:**
- [ ] Jira integration creates correctly formatted issues with severity→priority mapping
- [ ] Slack bot responds to `/autopentest scan` and posts campaign updates in a thread
- [ ] CEF output validates against ArcSight CEF specification
- [ ] SARIF output validates against SARIF 2.1.0 JSON schema
- [ ] Webhook delivers events with HMAC signature and retries on failure

**Dependencies:** Sprints 4, 6, 10

---

### Sprint 21 — Shared Intelligence Network
**Duration:** 2 weeks
**Goal:** Build an opt-in, anonymized intelligence sharing network where every autopentest installation contributes to and benefits from collective security knowledge. This is the deepest network effect possible — the tool gets measurably better with each new user.

**Why this sprint matters:** This is the difference between a tool and a platform. Every individual scan produces intelligence. Aggregated across thousands of users, this creates a collective knowledge base no competitor can replicate without an equivalent user base. This is how you build a true data network effect.

#### 21.1 Telemetry & Pattern Extraction (`internal/intelligence/extractor.go`)
- After every campaign completes, extract anonymized patterns:
  - **Tech Stack Patterns**: "Target runs Rails 7.x on AWS ECS" → generalized to "Rails 7.x on AWS"
  - **Finding Patterns**: "SQL injection in search parameter" → generalized to "SQLi in search endpoints, Rails 7.x"
  - **False Positive Patterns**: "Nuclei template X fires on Cloudflare but it's always FP" → pattern for community FP database
  - **Attack Chain Success**: "SSRF → metadata endpoint → IAM creds worked on AWS" → chain pattern with success rate
  - **Tool Effectiveness**: "subfinder found 95% of subdomains for .com targets, only 40% for .io targets"
- All patterns are stripped of: target IP/domain, specific URLs, credentials, organization names, finding details
- User sees exactly what will be shared before it's sent: `autopentest intelligence preview`
- Patterns are hashed and deduplicated locally before sending

#### 21.2 Intelligence API (`internal/intelligence/api.go`)
- Hosted at `api.autopentest.ai` (lightweight Go service, separate repo)
- `POST /v1/patterns`: submit anonymized patterns from a completed campaign
- `GET /v1/patterns?tech=rails&cloud=aws`: query patterns relevant to a target's tech stack
- `GET /v1/fp-database`: download collective false positive database
- `GET /v1/chain-success?finding=ssrf`: get community-reported success rates for attack chains starting from a finding type
- `GET /v1/stats`: aggregate stats (total scans, total patterns, top technologies)
- Rate limited, API key per installation (generated on first run)
- All data is anonymized server-side as a second pass; no raw target data is ever stored

#### 21.3 Intelligence Consumer (`internal/intelligence/consumer.go`)
- Before each campaign, query the intelligence API for relevant patterns:
  - "For Rails apps on AWS, community reports these are the most common findings: ..."
  - "Community false positive rate for nuclei template X on Cloudflare: 97% — consider skipping"
  - "SSRF → cloud metadata chain has 73% success rate on AWS targets"
- Inject these insights into the orchestrator's system prompt as prior intelligence
- Track whether community intelligence improved scan quality (did it predict correctly?)
- Feed accuracy data back to the intelligence API to improve pattern quality over time

#### 21.4 Opt-In & Privacy Controls
- Intelligence sharing is **OFF by default** — user must explicitly enable:
  ```
  autopentest config set intelligence.enabled true
  autopentest config set intelligence.share_patterns true   # contribute patterns
  autopentest config set intelligence.consume_patterns true  # use community patterns
  ```
- `autopentest intelligence preview`: shows exactly what would be shared from the last campaign
- `autopentest intelligence opt-out`: permanently delete all submitted patterns from the API
- `autopentest intelligence stats`: shows how community intelligence improved your scans
- Privacy policy clearly documented: what is collected, how it's anonymized, how to delete
- Enterprise users can run a private intelligence server within their org (self-hosted API)

#### 21.5 Community Dashboard
- Public web page at `intelligence.autopentest.ai`:
  - Total community scans (live counter)
  - Top vulnerability categories found across all users
  - Technology-specific risk heatmaps: "WordPress sites have 3.2x more critical findings than Next.js sites"
  - Attack chain success rates by tech stack
  - Contribution leaderboard (by installation ID, anonymous unless user opts to reveal)
- This dashboard is marketing gold — shareable stats that demonstrate the tool's value
- Data exported as JSON API for researchers

#### 21.6 Tests
- `tests/unit/intelligence/extractor_test.go`: verify patterns are properly anonymized — no IPs, domains, or org-identifying info
- `tests/unit/intelligence/consumer_test.go`: verify community patterns are injected into orchestrator prompt correctly
- `tests/integration/intelligence_test.go`: full flow — extract patterns, submit to mock API, query back, verify injection

**Acceptance Criteria:**
- [ ] Pattern extractor strips ALL identifying information (IP, domain, URL, org name) — verified by regex scan of output
- [ ] `autopentest intelligence preview` shows exactly what would be shared with no surprises
- [ ] Community false positive database reduces FP rate by at least 20% on test targets
- [ ] Intelligence is OFF by default and requires explicit opt-in
- [ ] Self-hosted intelligence server works for enterprise users

**Dependencies:** Sprints 4, 6, 10

---

### Sprint 22 — VS Code / Cursor Extension
**Duration:** 1 week
**Goal:** Build a VS Code / Cursor extension that brings autopentest into the IDE — the largest distribution channel in developer tooling with publicly visible install counts.

**Why this sprint matters:** VS Code has 15M+ monthly active users. Cursor has millions more. The VS Code Marketplace shows public install counts — this is a highly visible metric. An extension that shows security findings inline in your code is the kind of thing developers screenshot and share. Combined with MCP server mode (Sprint 18), this creates a "security copilot" experience that no competitor offers.

#### 22.1 Extension Core (`deploy/vscode/`)
- TypeScript extension for VS Code and Cursor
- Activates when workspace contains a `config.yaml` or `autopentest.yaml` file, or when user runs a command
- Communicates with running autopentest API server via HTTP/WebSocket
- Also works via MCP protocol when running in Cursor with MCP enabled

#### 22.2 Extension Features
- **Quick Scan** (`Ctrl+Shift+P` → "AutoPentest: Scan Target"):
  - Input box for target URL/domain
  - Scope auto-detected from project config
  - Progress shown in VS Code notification area
  - Findings appear in the Problems panel (like ESLint errors)
- **Findings Panel** (custom sidebar view):
  - Tree view of findings grouped by severity
  - Each finding shows: title, severity badge, CVSS score, affected URL
  - Click to expand: full description, evidence, remediation
  - "Explain" button: calls `explain` endpoint, shows plain-English explanation in a panel
  - "Create Jira" button: one-click issue creation (if Jira integration configured)
- **Inline Annotations**:
  - If findings reference specific endpoints/paths that match files in the workspace, show inline decorations
  - Hover shows finding details with remediation guidance
  - CodeLens: "Fix this vulnerability" links to remediation docs
- **Campaign Status Bar**:
  - Status bar item showing active campaign status
  - Click to open the findings panel
  - Animated during active scans
- **Report Preview**:
  - Open generated reports (HTML/Markdown) in VS Code preview panel
  - Navigate findings from report directly to code

#### 22.3 Extension Distribution
- Publish to VS Code Marketplace: `armurai.autopentest`
  - **Install count is publicly visible** — key growth metric
  - Categories: "Linters", "Testing", "Other"
  - Tags: "security", "penetration-testing", "vulnerability", "scanner"
- Publish to Open VSX Registry (for Cursor, Codium, Theia)
- Extension auto-updates via marketplace
- Extension size: <5MB (just the UI, backend is the autopentest server)

#### 22.4 Tests
- `deploy/vscode/src/test/`: extension integration tests using VS Code Extension Testing API
- Verify: command registration, findings panel rendering, status bar updates

**Acceptance Criteria:**
- [ ] Extension installs from VS Code Marketplace and activates in a workspace
- [ ] Quick Scan command starts a campaign and findings appear in Problems panel
- [ ] Findings panel shows tree view grouped by severity with correct badges
- [ ] Install count is publicly visible on VS Code Marketplace page
- [ ] Extension works in both VS Code and Cursor

**Dependencies:** Sprints 6, 8, 14

---

### Sprint 23 — Download Metrics Dashboard & Growth Engine
**Duration:** 1 week
**Goal:** Build a public-facing metrics dashboard that aggregates download/install counts from every distribution channel, and automate the growth loops that drive adoption.

**Why this sprint matters:** "50k weekly downloads" is the single most powerful social proof signal for an open source project. But downloads are scattered across npm, Docker Hub, GitHub Releases, Snap Store, VS Code Marketplace, and PyPI. Aggregating them into a single visible number creates a flywheel: high download count → more trust → more downloads. This also gives you real-time product-market fit signal.

#### 23.1 Metrics Aggregator (`deploy/metrics/`)
- Lightweight Go service (or serverless function) that polls download counts from all channels:
  - **npm**: `https://api.npmjs.org/downloads/point/last-week/@armurai/autopentest`
  - **Docker Hub**: `https://hub.docker.com/v2/repositories/armurai/autopentest/`
  - **GitHub Releases**: GitHub API — sum of all asset download counts across releases
  - **PyPI**: `https://pypistats.org/api/packages/autopentest-sdk/recent`
  - **Snap Store**: snapcraft.io metrics API
  - **VS Code Marketplace**: marketplace API install count
  - **Homebrew**: formulae.brew.sh analytics (30-day install count)
  - **GitHub Action**: marketplace install count
  - **Winget**: winget.run stats
- Stores daily snapshots in a simple JSON file or SQLite database
- Exposes API: `GET /api/metrics` → aggregated counts + per-channel breakdown

#### 23.2 Public Dashboard (`metrics.autopentest.ai`)
- Single-page site showing:
  - **Total downloads** (big number, all channels combined)
  - **Weekly downloads** (trend graph, last 12 weeks)
  - **Per-channel breakdown** (bar chart: npm, Docker, GitHub, Snap, VS Code, PyPI, Homebrew)
  - **Growth rate** (week-over-week percentage)
  - **GitHub stars** graph (via GitHub API)
  - **Community stats**: playbook count, intelligence network participants, contributor count
- Hosted on Cloudflare Pages or Vercel (free tier)
- Updates daily via cron job or GitHub Actions scheduled workflow

#### 23.3 README Badges
- Dynamic badges in README.md that show real-time stats:
  ```markdown
  ![Downloads](https://img.shields.io/endpoint?url=https://metrics.autopentest.ai/api/badge/total)
  ![Weekly](https://img.shields.io/endpoint?url=https://metrics.autopentest.ai/api/badge/weekly)
  ![Docker Pulls](https://img.shields.io/docker/pulls/armurai/autopentest)
  ![npm](https://img.shields.io/npm/dw/@armurai/autopentest)
  ![VS Code](https://img.shields.io/visual-studio-marketplace/i/armurai.autopentest)
  ![GitHub Stars](https://img.shields.io/github/stars/Armur-Ai/autopentest)
  ```
- Custom badge endpoint at `metrics.autopentest.ai/api/badge/{metric}` returns shields.io-compatible JSON
- Badges update daily — always showing fresh numbers

#### 23.4 Growth Automation
- **GitHub Stars reminder**: after a successful scan, CLI prints: "If autopentest saved you time, consider starring us on GitHub: https://github.com/Armur-Ai/autopentest" (once per installation, dismissable)
- **Changelog notifications**: `autopentest` checks for new versions on startup (weekly, not every run); if update available, prints one-line notice with what's new
- **Social sharing**: `autopentest share <campaign-id>` generates a shareable summary image (findings count, severity distribution, tech stack) with autopentest branding — designed for Twitter/LinkedIn
- **Referral tracking**: install script and npm shim accept `?ref=` parameter so you can track which blog posts/talks/videos drive installs
- **Weekly digest email** (opt-in): for users who register, weekly email with: your scan stats, new community playbooks, new features, community highlights

#### 23.5 SEO & Discovery
- Ensure the following pages exist and are indexed:
  - `autopentest.ai` — landing page with install instructions, demo GIF, feature list
  - `docs.autopentest.ai` — documentation site (GitHub Pages or Docusaurus)
  - `metrics.autopentest.ai` — public download dashboard
  - `intelligence.autopentest.ai` — community intelligence dashboard
- All pages have proper OpenGraph tags for social sharing
- Submit to: awesome-go, awesome-security, awesome-hacking, awesome-pentest lists on GitHub
- Write guest posts for: The New Stack, Help Net Security, InfoSec Write-ups, DEV Community

**Acceptance Criteria:**
- [ ] Metrics API returns aggregated download count from at least 5 channels
- [ ] Public dashboard shows total downloads, weekly trend, and per-channel breakdown
- [ ] README badges show real-time download counts that update daily
- [ ] `autopentest share` generates a shareable image with scan summary
- [ ] Landing page at autopentest.ai loads with install instructions and demo GIF

**Dependencies:** Sprints 14, 15

---

## Moat Strategy

### The Network Effects Flywheel

The core insight: **the moat is not the product, it's the ecosystem around it**. The product is open source and forkable. The community, the shared intelligence, the playbooks, and the integrations are not.

```
                    ┌──────────────────┐
                    │   New User       │
                    │   Installs tool  │
                    └────────┬─────────┘
                             │
                    ┌────────▼─────────┐
                    │   Runs scans     │
                    └────────┬─────────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
    ┌─────────▼──────┐ ┌────▼──────┐ ┌────▼───────────┐
    │ Contributes    │ │ Shares    │ │ Integrates     │
    │ playbooks      │ │ anonymized│ │ into workflow   │
    │ + templates    │ │ patterns  │ │ (Jira/Slack/CI)│
    └─────────┬──────┘ └────┬──────┘ └────┬───────────┘
              │              │              │
    ┌─────────▼──────────────▼──────────────▼───────────┐
    │          Platform gets better for EVERYONE          │
    │  More playbooks · Smarter AI · More integrations   │
    └─────────────────────────┬─────────────────────────┘
                              │
                    ┌─────────▼─────────┐
                    │  Attracts more    │
                    │  users            │
                    └───────────────────┘
```

### Four Layers of Defensibility

**Layer 1 — Community Playbooks (Direct Network Effect)**

Like nuclei-templates but for full multi-step AI-powered attack chains. Every contributed playbook makes the platform more valuable for every user. A competitor can fork the engine but cannot fork the community.

- Separate repo: `armur-ai/autopentest-playbooks` — the nuclei-templates of AI pentesting
- Contributor attribution + leaderboard (social incentive)
- Playbook stats: usage count, findings discovered, community rating
- Auto-update mechanism pulls new playbooks weekly
- Target: 100 at launch, 500+ at month 6, 2000+ at year 1
- Categories: cloud (AWS/GCP/Azure), web (OWASP/CMS/API), network, compliance (PCI/HIPAA/SOC2), industry-specific

**Layer 2 — Shared Intelligence Network (Data Network Effect)**

The deepest moat. Every scan teaches the system something. Aggregated across thousands of users (opt-in, anonymized), this creates collective intelligence no competitor can replicate without an equivalent user base:

- Collective false positive database: "Nuclei template X on Cloudflare = 97% FP"
- Tech-stack risk profiles: "WordPress sites have 3.2x more critical findings than Next.js"
- Attack chain success rates: "SSRF → metadata on AWS = 73% success rate"
- Tool effectiveness data: "subfinder covers 95% of .com but only 40% of .io"
- The intelligence API feeds directly into agent prompts, making the AI measurably smarter

```
More users → More scans → Better intelligence → Better results → More users
                                    ↓
                          Anonymized patterns (opt-in)
                                    ↓
                          Fine-tuned models v2, v3, v4...
                                    ↓
                          Better out-of-box performance → More users
```

**Layer 3 — Integration Hub (Switching Cost)**

Every integration is a hook into an existing workflow. Each one raises the cost of switching to a competitor:

- **Developer workflow**: VS Code extension, Cursor MCP, GitHub Action (CI/CD)
- **Security operations**: Jira, Slack bot, SIEM (CEF/STIX/SARIF), PagerDuty webhook
- **Bug bounty**: HackerOne scope import + submission, Bugcrowd integration
- **Infrastructure**: Docker, Kubernetes Helm chart, Terraform provider (future)
- Once wired in, ripping out autopentest means rewiring every connected system

**Layer 4 — Distribution Surface (Visibility Moat)**

Being available everywhere creates an awareness advantage. Public download metrics on every channel create social proof that compounds:

- **npm**: weekly download count on npmjs.com (the most visible metric in open source)
- **Docker Hub**: pull count on Docker Hub page
- **VS Code Marketplace**: install count (reaches non-security developers)
- **Snap Store**: install count on snapcraft.io
- **PyPI**: download stats on pypistats.org
- **GitHub**: stars, forks, contributor count
- **Aggregated dashboard**: `metrics.autopentest.ai` shows total downloads across all channels
- High download numbers → more trust → more downloads (self-reinforcing)

### Why Fine-Tuned Models Are Layer 2, Not Layer 1

Fine-tuned models on synthetic data are a starting point, not a moat. The moat comes when those models are trained on real-world data from the shared intelligence network — data that no competitor has access to without an equivalent user base. The roadmap:

1. **v1.0**: Ship with prompted models (Claude API / Ollama). Works immediately, no cold-start.
2. **v1.x**: Collect real-world patterns via agent memory + shared intelligence network (with user consent).
3. **v2.0**: Fine-tune models on anonymized real-world patterns. Now the models are genuinely better than anything a competitor can build by just calling Claude.
4. **v3.0+**: Data flywheel is spinning — each release improves models, which improves results, which attracts more users, which produces more data.

---

## Success Metrics

| Metric | Target |
|---|---|
| GitHub stars (month 1) | 2,000+ |
| GitHub stars (month 6) | 10,000+ |
| Full campaign time (simple target) | <20 minutes |
| Recon phase time (<20 subdomains) | <5 minutes |
| Finding accuracy (real vs false positive) | >80% real findings |
| Report quality score | >4/5 by security professionals |
| Recon model JSON validity | >95% |
| Exploit model plan validity | >85% |
| `docker compose up` to working dashboard | <15 min (model download included) |
| Community playbooks (month 3) | 100+ |
| Community playbooks (month 6) | 500+ |
| Community playbooks (year 1) | 2,000+ |
| MCP tool calls per week (month 3) | 10,000+ |
| GitHub Action installs (month 6) | 500+ repos |
| CTF machines solved autonomously | >50% of Easy HTB |
| **Distribution Metrics** | |
| npm weekly downloads (month 3) | 5,000+ |
| npm weekly downloads (month 6) | 20,000+ |
| Docker Hub pulls (month 6) | 100,000+ |
| VS Code extension installs (month 6) | 10,000+ |
| Total downloads all channels (month 6) | 500,000+ |
| **Network Effect Metrics** | |
| Shared intelligence network participants | 1,000+ (month 6) |
| Community FP database entries | 5,000+ (month 6) |
| Playbook contributors | 100+ (month 6) |
| Integration plugin count | 30+ (month 6) |

---

## What Makes This Defensible

**Four-Layer Moat** (see Moat Strategy section above for full detail):

1. **Community Playbooks (Network Effect)** — nuclei-templates equivalent for AI attack chains; 2,000+ target year 1; can't be replicated by forking the engine
2. **Shared Intelligence Network (Data Network Effect)** — collective FP database, tech-stack risk profiles, attack chain success rates; the tool gets measurably better with each new user
3. **Integration Hub (Switching Cost)** — Jira + Slack + SIEM + GitHub Action + MCP + VS Code + CI/CD; ripping out autopentest means rewiring every connected system
4. **Distribution Surface (Visibility Moat)** — npm + Docker + Snap + VS Code Marketplace + PyPI + Homebrew + Winget; public download metrics on every channel create compounding social proof

**Technical Differentiators:**

5. **Go-native single binary** — `brew install` in one command; no Python runtime, no pip hell
6. **Native Go security tool integration** — subfinder/httpx/nuclei/naabu as libraries, not subprocesses
7. **MCP Server** — usable from Claude Desktop, Cursor, and any MCP-compatible AI; the only pentesting MCP server
8. **VS Code/Cursor Extension** — security findings inline in your IDE; the largest distribution channel in developer tooling
9. **Continuous ASM** — the only open-source tool that autonomously watches your attack surface and triggers AI tests on changes
10. **Bug bounty workflow** — reads H1/Bugcrowd scope, deduplicates, formats reports correctly; nobody else does this
11. **CTF Mode** — autonomous CTF solving drives 10x larger student/beginner audience
12. **Full privacy option** — 100% local with Ollama, nothing leaves your machine
13. **GitHub Action** — security scanning in CI/CD with SARIF integration; findings appear in GitHub Security tab
14. **Multi-agent architecture** — specialist models per task, coordinated by ReAct orchestrator
15. **Public metrics dashboard** — aggregated download counts across all channels; social proof that compounds
