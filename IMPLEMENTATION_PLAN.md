# Pentest Swarm AI — Implementation Plan

> **Status**: Draft v1 — planning horizon ~6 months
> **Last updated**: 2026-04-18
> **Owner**: @AkhilSharma90

This document is the source of truth for the roadmap from v0.1 (current) to v1.0. Every task is scoped small enough to land in a single PR. Check boxes as you ship.

If you're a contributor looking for where to help: look for `P0` (blocking) and `good-first-issue` tags inside each phase.

---

## Table of Contents

1. [North Star & Positioning](#north-star--positioning)
2. [Wave 1 — Credibility Debt (4–6 weeks)](#wave-1--credibility-debt-46-weeks)
3. [Wave 2 — Integrations & Workflows (6–8 weeks)](#wave-2--integrations--workflows-68-weeks)
4. [Wave 3 — Research Frontier (ongoing)](#wave-3--research-frontier-ongoing)
5. [Distribution & Community Growth](#distribution--community-growth)
6. [README Rewrite](#readme-rewrite)
7. [Architectural Decisions](#architectural-decisions)
8. [Benchmarks Target](#benchmarks-target)
9. [Research References](#research-references)

---

## North Star & Positioning

**Goal**: Pentest Swarm AI is the first open-source pentesting tool that is a *real swarm* — decentralized agents coordinating through shared environment state (stigmergy), producing emergent attack paths no single planner specified.

**Non-goals (v1)**: replacing human pentesters; autonomous zero-day discovery (XBOW/Big Sleep territory); web-only scope.

**Moat vs. competitors**:
- vs. **PentestGPT**: we execute, not just suggest
- vs. **HackingBuddyGPT**: we have a full agent swarm, not a single agent
- vs. **PentAGI**: we are stigmergic, not orchestrated
- vs. **HexStrike**: we are not a thin MCP wrapper; we have agent reasoning
- vs. **Shannon**: we're open-core-friendly and swarm-native

---

## Wave 1 — Credibility Debt (4–6 weeks)

> Make the README true. Make the swarm real. Fix the footguns.

### Phase 1.1 — True Swarm Architecture (the big one)

Replace the sequential 5-phase runner (`internal/engine/runner.go:56-298`) with a stigmergic Blackboard pattern. This is the feature that makes the product name honest.

**Core design:**
- **Blackboard**: a Postgres-backed shared knowledge store (findings, hypotheses, open tasks, blocked tasks). Uses existing pgvector for semantic recall.
- **Agents**: long-running workers that subscribe to the blackboard. Each has a *trigger rule* (SQL/vector predicate) that wakes it when relevant state appears.
- **Stigmergy**: every agent write includes a *pheromone weight* — how "interesting" the finding is. Weights decay over time. Other agents' trigger rules read weighted state, biasing exploration.
- **Scheduler**: no central planner. A thin coordinator rate-limits concurrent agents, enforces scope, and kills on signal. Selection is emergent from trigger rules + pheromones.

**Tasks:**

- [x] **1.1.1** Define `Blackboard` Go interface in `internal/swarm/blackboard/board.go`
  - [x] `Write(ctx, Finding) error` — append-only, returns finding ID
  - [x] `Query(ctx, Predicate) iter.Seq[Finding]` — SQL + vector hybrid
  - [x] `Subscribe(ctx, Predicate) <-chan Finding` — blocking stream
  - [x] `Pheromone(findingID) float64` — weight with time decay
  - [x] Unit tests for write/query/subscribe with fake clock
- [x] **1.1.2** Postgres schema migration `migrations/000004_blackboard.sql`
  - [x] `swarm_findings` table: id, campaign_id, agent_name, finding_type, target, data (jsonb), embedding (vector), pheromone_base, half_life_sec, created_at, superseded_by
  - [x] Index on (campaign_id, type); pgvector column present; HNSW index to land with first real embeddings
  - [x] `swarm_pheromone()` SQL function (exponential, half-life configurable per-type)
  - [ ] Backfill script for existing DB *(deferred — no legacy swarm data to migrate)*
- [x] **1.1.3** Agent `Trigger` abstraction via `blackboard.Predicate`
  - [x] `Predicate` as a composable struct (type match, pheromone threshold, SinceID cursor)
  - [x] Trigger evaluation is idempotent — each agent commits a cursor after Handle
- [x] **1.1.4** Refactor each existing agent to the swarm model *(adapter-wrapper approach, preserves legacy path)*
  - [x] `internal/swarm/agents/recon.go` — triggers on `TARGET_REGISTERED`, publishes `SUBDOMAIN`, `PORT_OPEN`, `HTTP_ENDPOINT`, `TECHNOLOGY`
  - [x] `internal/swarm/agents/classifier.go` — triggers on raw findings > 0.2 pheromone, publishes `CVE_MATCH` / `MISCONFIGURATION`
  - [x] `internal/swarm/agents/exploit.go` — triggers on `CVE_MATCH` with pheromone > 0.5, publishes `EXPLOIT_CHAIN` / `EXPLOIT_RESULT`
  - [x] `internal/swarm/agents/report.go` — triggers on `CAMPAIGN_COMPLETE`
- [x] **1.1.5** New scheduler in `internal/swarm/scheduler.go`
  - [x] Blackboard-driven dispatch replaces the phase loop (available behind `--swarm`)
  - [x] Per-agent concurrency caps
  - [x] Graceful shutdown on SIGINT via runCtx cancellation
  - [x] Campaign-level budget (agent-hours + tokens) enforced by the budget watcher
- [x] **1.1.6** Pheromone tuning
  - [x] Per-finding-type decay half-lives in `config/pheromones.yaml` (embedded default + override via `Load`)
  - [x] CLI flag `--exploration-bias {low,med,high}` — scales pheromone base at write time
- [ ] **1.1.7** Delete `internal/engine/runner.go` sequential pipeline (keep a `legacy` subcommand behind `--legacy` flag for 1 release)
- [x] **1.1.8** Integration test: `tests/integration/swarm_e2e_test.go` — seed → 3 agents → asserts dispatch counts + final board shape
- [x] **1.1.9** Observability
  - [x] `swarm.Tracer` interface + NoopTracer; scheduler wraps every `Agent.Handle` in a span (OTel bridge is a few-line adapter — no SDK dep needed)
  - [x] Grafana dashboard JSON in `deploy/metrics/grafana-swarm-dashboard.json` (findings-per-type, active agents, budget, error rate)
  - [x] `blackboard.LoggingBoard` emits structured JSON for every write / cursor commit / budget mutation via zap

### Phase 1.2 — Dashboard Wire-up

Current state: `web/` dashboard renders, `SeverityChart` hardcodes zeros, runner never persists to DB or streams to WS.

- [ ] **1.2.1** Wire scheduler → DB persistence in `internal/db/findings.go` *(runner emits structured finding events now; DB persist on the server path is next)*
- [x] **1.2.2** Wire scheduler → WebSocket `EventHub` for live updates *(server.startCampaign publishes every event via hub.Publish)*
- [x] **1.2.3** Replace mock zeros in `SeverityChart` with a live query against `/api/v1/stats`
- [ ] **1.2.4** Add "live swarm" view: animated pheromone graph, active agents, findings stream
- [ ] **1.2.5** Playwright test: run `pentestswarm scan --dry-run` against mock target, assert chart values non-zero in <10s
- [ ] **1.2.6** Add campaign diff view (run N vs run N-1) — foundation for ASM mode

### Phase 1.3 — Safety Fixes

- [x] **1.3.1** Wire cleanup registry (was `nil` in `internal/engine/runner.go:211`)
  - [x] Every exploit that creates artifacts (files, users, sessions) registers a cleanup
  - [x] Cleanup runs on normal exit, SIGINT, and scheduler crash (detached context survives ctx cancel)
  - [x] Unit tests: `internal/agent/exploit/shellparse_test.go` + integration via runner defer
- [x] **1.3.2** Fix silent LLM fallback in classifier
  - [x] Surface errors to event stream via `classifier.WithErrorSink` + `recon.WithErrorSink`
  - [x] Add `--strict` CLI flag — abort on any LLM failure
  - [x] Default mode: heuristic fallback + WARN event
- [x] **1.3.3** Fix recon empty-AttackSurface on JSON parse failure
  - [x] Retry prompt with narrower schema (already present)
  - [x] On second failure, emit error event to stream (strict mode promotes to fatal)
- [x] **1.3.4** Harden command executor
  - [x] Replace naive field splitting with quote-aware `parseCommand`
  - [x] Reject pipes, redirects, backticks, `$(...)`, newlines unless inside quotes
  - [ ] Sandbox: all exploit commands run in a Docker container by default *(deferred to Wave 2)*
- [x] **1.3.5** Scope enforcement audit
  - [x] All 8 tool adapters now route through `scope.ValidateAndLog(tool, target, def)` instead of the bare `Validate()` so every check is logged
  - [x] Violations emit `WARN subsystem=scope` with tool + target + allowed scope, then return the error — never log-and-continue
  - [x] 9 unit tests cover CIDR boundaries, subdomain matching, wildcards, excluded ranges, and ValidateCommand's non-target allow-list

### Phase 1.4 — LLM Layer Upgrades

- [x] **1.4.1** Model name is config-driven (`OrchestratorConfig.Model`; per-agent via `AgentsConfig` + `NewAgentProvider`)
  - [x] Default to `claude-sonnet-4-6`
  - [x] Support `claude-opus-4-7`, `claude-haiku-4-5-20251001` (any Anthropic model ID)
  - [x] Per-agent model override (cheap agents on Haiku, reasoning on Opus) via `agents.*.model`
- [x] **1.4.2** Prompt caching on Claude
  - [x] Cache system prompt (tool definitions not yet cached — follow-up)
  - [ ] Cache per-campaign shared context (scope, objective, recon summary) *(follow-up)*
  - [x] Emit cache-hit metrics via `Usage.CacheHitRate()`
- [x] **1.4.3** Structured tool-use for the classifier
  - [x] `emit_classified_findings` tool with JSON-Schema enum for severity + confidence
  - [x] Tool-call path used for providers with `SupportsToolUse()` (Claude); legacy JSON-in-prompt retained as fallback for Ollama / LM Studio
- [x] **1.4.4** Token budget per campaign + per agent — hard cap with soft warn
  - Per-campaign budget already enforced by scheduler (agent-hours + tokens)
  - Per-agent layer added: `swarm_agent_budgets` table, `AgentBudget` / `ChargeAgent` / `SetAgentBudget` on the Board; scheduler emits `agent_budget_warn` at soft threshold and skips dispatch after hard cap
  - 3 unit tests cover defaults, warn transition, threshold-raise clears warned flag
- [x] **1.4.5** Eval harness at `tests/llm_eval/`
  - YAML fixture DSL (`severity`, `cvss_min`/`cvss_max`, `*_any_of` allow-lists, `contains_in_description`)
  - 3 classifier fixtures shipped: critical SQLi, medium XSS, low info-disclosure
  - MockProvider replays fixture responses through the real classifier code path so the eval tests the *code*, not the LLM
  - Ready for a `-live` flag extension to run the same rubrics against a real Claude provider

### Phase 1.5 — README Honesty Pass

(see full [README Rewrite](#readme-rewrite) section below)

---

## Wave 2 — Integrations & Workflows (6–8 weeks)

> The real pentester's toolbox, wired into the swarm, with named pipelines.

### Phase 2.1 — Core Tool Integrations

- [x] **2.1.1** `nmap` adapter `internal/tools/nmap.go`
  - [x] XML output parser → findings (`PORT_OPEN`, service/version, OS match)
  - [x] Scope guard in `Run()`; timing flag configurable
  - [x] Requires `nmap` binary; gated via `IsAvailable()` so missing binary = skip
- [x] **2.1.2** `sqlmap` adapter via `sqlmapapi` REST
  - [x] Full task/new → option/set → scan/start → poll status → data → task/delete lifecycle
  - [x] Credentials redacted via key-name regex + inline `key=value` redaction before results surface
  - [x] Defence-in-depth: scope.ValidateAndLog on every call; deferred task delete runs even on timeout
  - [x] 3 unit tests use httptest-backed fake sqlmapapi so CI needs no sqlmap binary
  - [ ] Wiring: trigger on classifier `POTENTIAL_SQLI` findings (follow-up — needs a swarm agent adapter)
- [x] **2.1.3** `ffuf` adapter `internal/tools/ffuf.go` — FUZZ URL + wordlist, JSON parse via temp file, scope-guarded
  - [ ] Wordlist registry (SecLists auto-download on first run, cached) *(follow-up)*
- [x] **2.1.4** `gobuster` adapter — dir + dns modes, text-line parse
- [x] **2.1.5** `trufflehog` adapter — NDJSON stream, `Raw` / `RawV2` secret bodies redacted at ingest
- [x] **2.1.6** `gitleaks` adapter — uses `--redact`, additionally scrubs `Secret` field defence-in-depth; exit-1-on-leaks handled
- [x] **2.1.7** `semgrep` adapter — p/owasp-top-ten default rule pack, JSON parse, exit-1-on-findings handled
- [x] **2.1.8** `amass` adapter — passive by default, active via opt-in flag, NDJSON parse

### Phase 2.2 — Heavyweight Integrations

- [x] **2.2.1** **Burp Suite MCP** bridge (official PortSwigger MCP)
  - [x] JSON-RPC 2.0 HTTP client at `internal/integrations/burp/client.go` with bearer auth
  - [x] Burp tool constants + helpers: `StartActiveScan`, `GetIssues`, `ListTools`, `Ping`
  - [x] Swarm agent `agents.BurpAgent` triggers on `HTTP_ENDPOINT` findings above 0.5 pheromone, publishes Burp issues as `CVE_MATCH`
  - [x] 5 unit tests use httptest-backed JSON-RPC server, so CI runs with no Burp install
- [x] **2.2.2** **Metasploit** via msfrpcd
  - [x] HTTP/JSON client at `internal/integrations/metasploit/client.go` (msgpack was too opaque; msfrpcd supports JSON fine)
  - [x] `auth.login` token cached, transparent refresh on 401
  - [x] `module.execute`, `session.list`, `session.stop`, `job.stop` primitives
  - [x] 5 unit tests use httptest-backed fake msfrpcd; covers token refresh, session lifecycle
  - [ ] Swarm agent that registers every session with the cleanup registry (follow-up, needs an exploit-agent extension)
- [x] **2.2.3** **OWASP ZAP** REST API
  - [x] Client at `internal/integrations/zap/client.go` with API-key query param
  - [x] Spider + active-scan primitives, status polling, alerts endpoint
  - [x] 5 unit tests (spider + active lifecycle, alert parsing, API-key enforcement, URL encoding regression)
- [x] **2.2.4** **Nuclei template author agent**
  - [x] `NucleiAuthorAgent` triggers on high-pheromone novel findings (no CVE match), uses structured tool-use (`emit_nuclei_template`) so output is always parseable
  - [x] Drafts land at `./drafts/nuclei/<id>-<hash>.yaml` for human review
  - [x] Optional `-validate` pass via the nuclei binary when present; rejects ill-formed drafts before publishing
  - [x] `NUCLEI_TEMPLATE_DRAFT` finding type added to blackboard + tuning (12h half-life for reviewer workday)

### Phase 2.3 — Swarm Playbooks (Named Pipelines)

Ship as YAML files in `playbooks/` — like Nuclei templates but for full swarm behaviors.

- [x] **2.3.1** `playbooks/bug-bounty.yaml`
- [x] **2.3.2** `playbooks/external-asm.yaml`
- [x] **2.3.3** `playbooks/ci-cd-security.yaml`
- [x] **2.3.4** `playbooks/internal-network.yaml`
- [x] **2.3.5** `playbooks/ctf-solver.yaml`
- [x] **2.3.6** Playbook schema + validator (`internal/plugins/validate.go`)
  - Name + version-semver check, duplicate-phase detection, variable-type whitelist, tool-known check, `{{ var }}` reference to undeclared variables fails, `required + default` combo warns
  - CLI `pentestswarm playbook validate <path>` now reports full error/warning lists with exit code on errors
  - 9 unit tests cover each rule
- [x] **2.3.7** `pentestswarm playbook run <name>` CLI wiring *(already in `cli/playbook.go`)*
- [ ] **2.3.8** "Playbook marketplace" page on site (v1: just a listing; v2: submit PRs)

### Phase 2.4 — CI/CD & Ecosystem

- [x] **2.4.1** GitHub Action (composite action in `deploy/github-action/action.yml`)
  - [ ] Publish to GitHub Marketplace *(external — tag + GH submit)*
  - [ ] SARIF output integrates with Code Scanning *(wired in action, emitter still pending)*
  - [x] Fail-PR-on-critical flag (`fail-on` input)
- [ ] **2.4.2** Jira adapter — create issues from findings, severity-mapped
- [ ] **2.4.3** Slack adapter — thread-per-campaign, daily digest, ack/escalate buttons
- [ ] **2.4.4** SIEM export — CEF, STIX 2.1, SARIF
- [ ] **2.4.5** Webhook delivery — HMAC-signed, retry with exponential backoff, dead-letter queue

---

## Wave 3 — Research Frontier (ongoing)

> Pick 2–3, don't chase all. Each item has a research lineage — see references.

### Phase 3.1 — RAG / Experience Memory

- [ ] **3.1.1** CVE corpus ingestion
  - [ ] Nightly NVD dump → pgvector with CVSS + CWE metadata
  - [ ] Indexed by vuln type and affected-product
- [ ] **3.1.2** Nuclei template corpus — embed all templates, retrievable by finding signature
- [ ] **3.1.3** ExploitDB corpus
- [ ] **3.1.4** Experience Memory (pattern from AutoAttacker)
  - [ ] Redacted trace of each campaign stored at finish
  - [ ] Retrieval on new campaign: "similar attack surfaces → what worked"
  - [ ] Opt-in telemetry (never on by default) → shared intelligence network
- [ ] **3.1.5** Agent-specific graph memory (arXiv:2511.07800 approach)
  - [ ] Exploit agent learns chain success/failure edges
  - [ ] Encoded as trainable graph, beats flat vector for multi-step reasoning

### Phase 3.2 — Fine-tuned Pentest-Swarm Model

Reproduce Pentest-R1 (arXiv:2508.07382) on Qwen3 or Llama 3.3 base.

- [ ] **3.2.1** Training data pipeline (`training/`)
  - [ ] Phase A: offline walkthroughs (HackTricks, HTB writeups, PortSwigger Academy solutions)
  - [ ] Phase B: online RL traces from CTF solving
- [ ] **3.2.2** Fine-tune Qwen3-32B-Instruct with LoRA
- [ ] **3.2.3** GGUF quantized release (`Pentest_LLM.gguf` already exists — v2 supersedes)
- [ ] **3.2.4** HuggingFace Hub publishing
- [ ] **3.2.5** Ollama modelfile for one-command local install
- [ ] **3.2.6** Distillation target: 7B model that runs on 16GB VRAM laptops

### Phase 3.3 — Benchmarks (the credibility lever)

Publish numbers in README. Update on every release. This is how XBOW built its brand.

- [ ] **3.3.1** Cybench runner (`tests/bench/cybench/`)
  - [ ] Integrate the 40-CTF benchmark
  - [ ] CI job: run against small subset on every PR
- [ ] **3.3.2** AutoPenBench runner
- [ ] **3.3.3** CVE-Bench runner
- [ ] **3.3.4** HackTheBox subset — retired boxes only (legal, reproducible)
- [ ] **3.3.5** Results dashboard at `benchmarks.pentestswarm.ai` — live updated
- [ ] **3.3.6** README table: us vs. PentestGPT / PentAGI / HexStrike / Pentest-R1

### Phase 3.4 — Agent Robustness (the underserved moat)

Memory poisoning and inter-agent-comm attacks are real. Be the first tool to market as *hardened*.

- [ ] **3.4.1** Blackboard write provenance
  - [ ] Every finding signed by originating agent with Ed25519
  - [ ] Tamper detection on read
- [ ] **3.4.2** MINJA-style injection tests in test suite
- [ ] **3.4.3** MemoryGraft detection heuristics
- [ ] **3.4.4** Rate-limit agent → agent communication
- [ ] **3.4.5** Blog post: "How we hardened our swarm against memory-injection attacks" — flagship marketing piece

### Phase 3.5 — Symbolic Execution Hybrid (stretch)

- [ ] **3.5.1** `angr` wrapper for binary targets
- [ ] **3.5.2** LLM-guided symex — LLM proposes paths, angr validates
- [ ] **3.5.3** Benchmark on canonical CTF binaries

---

## Distribution & Community Growth

> Trivy, Nuclei, and Gitleaks all did these four things.

- [ ] **D.1** Docker one-liner as primary quickstart
  - [ ] Publish `ghcr.io/armur-ai/pentest-swarm:latest`
  - [ ] Multi-arch (amd64 + arm64)
  - [ ] Verify: `docker run --rm ghcr.io/armur-ai/pentest-swarm scan <target>` works
- [ ] **D.2** Homebrew tap
  - [ ] Already referenced in README; create `homebrew-tap` repo
  - [ ] GoReleaser config generates tap on release
- [ ] **D.3** GoReleaser for signed binaries (linux/darwin/windows × amd64/arm64)
- [ ] **D.4** GitHub Action on Marketplace (see Phase 2.4.1)
- [ ] **D.5** Kali + BlackArch packaging requests (after v0.5 when API is stable)
- [ ] **D.6** `pentestswarm.ai` landing site
  - [ ] Value prop + demo GIF
  - [ ] Benchmark numbers
  - [ ] Playbook marketplace listing
  - [ ] Discord invite
- [ ] **D.7** Discord community (dedicated channels: #bugbounty, #ctf, #asm, #playbooks)
- [ ] **D.8** Monthly release cadence with release notes framed as "what's new for the swarm"
- [ ] **D.9** Conference talks
  - [ ] Submit to Black Hat Arsenal 2026
  - [ ] Submit to DEF CON Demo Labs
  - [ ] BSides circuit for regional credibility
- [ ] **D.10** Weekly content: one tutorial / blog / video per week during Wave 1+2

---

## README Rewrite

The current README overclaims in specific places. Fix after Wave 1.1 is merged (not before — we need to be able to keep the new claims true).

- [x] **R.1** Hero block (title + tool demo GIF + architecture GIF + badges)
- [x] **R.2** New section: *"What makes this a swarm?"* — stigmergy / emergence / decentralization
- [x] **R.3** Swarm diagram rewritten around the blackboard
- [x] **R.4** Competitor table (us vs. PentestGPT / HackingBuddyGPT / PentAGI / Shannon / HexStrike / Pentest-R1)
- [ ] **R.5** Benchmark numbers inline (after Phase 3.3 ships)
- [x] **R.6** "5-agent architecture" claim replaced with accurate description
- [x] **R.7** "ReAct loop" replaced with stigmergic-swarm framing
- [x] **R.8** Tool claim updated to 8 (ProjectDiscovery stack + nmap)
- [x] **R.9** Feature-status table with stable / beta / alpha / planned labels
- [x] **R.10** Credits & research section with inspiration links

---

## Architectural Decisions

### AD-1: Build the swarm natively in Go, not on Google ADK / CrewAI / AutoGen

**Options considered:**

| Framework | Language | Pattern | Fits? |
|---|---|---|---|
| **Google ADK** | Python (Java/Go partial) | Orchestrator + agents | No |
| **CrewAI** | Python | Role-based orchestration | No |
| **AutoGen** | Python | Conversational multi-agent | No |
| **LangGraph** | Python/JS | State-machine graph | Partial |
| **Eino** (ByteDance) | Go | Orchestration-oriented | Partial |
| **Custom Go + Blackboard** | Go | Stigmergy-native | ✅ |

**Decision**: build native. Reasons:

1. **Language alignment.** The codebase is Go. Bridging to Python ADK via gRPC or subprocess adds latency, complexity, and breaks the "single binary" distribution promise that's central to the Go-native pitch.
2. **Swarm intelligence ≠ multi-agent orchestration.** All the frameworks above assume a central planner dispatches to specialist agents. Stigmergy is the *opposite* — no central planner, coordination via shared environment. Bolting stigmergy onto an orchestrator framework is more work than writing it from scratch.
3. **Blackboard is ~800 LoC.** We already have Postgres + pgvector + an event bus + agent abstractions. What's missing is the *trigger semantics* and *pheromone decay* — both are small, self-contained.
4. **We can always adopt ADK later** for specific features (e.g., ADK's evaluation framework) without buying its whole programming model.

**Trade-off accepted**: we don't get the community plugins / integrations those frameworks ship with. Counter: our integrations are shell-level (tools, not agents), so framework plugins aren't a fit anyway.

### AD-2: Postgres as the Blackboard store

Alternatives: Redis Streams, NATS JetStream, in-memory only.

**Decision**: Postgres + pgvector. We already run it. Transactional writes matter for exploit-cleanup correctness. Query flexibility (SQL + vector) matters for trigger rules. Redis Streams would be faster but give up the query expressiveness.

### AD-3: Pheromone decay is per-finding-type

Different finding classes have different half-lives. A `PORT_OPEN` is valid for hours; a `SESSION_TOKEN` is valid for minutes. Config-driven.

### AD-4: Agents are goroutines, not containers

For v1. Containerization per agent is Phase 1.3.4 (executor sandbox), not per-agent-process. Easier to debug, smaller footprint, fine until we need strong isolation between untrusted agent code.

---

## Benchmarks Target

Aim for v1.0:

| Benchmark | Current (est.) | v1.0 Target | Leader |
|---|---|---|---|
| Cybench (full) | Unknown | ≥ 35% | Pentest-R1 at ~40%+ with Claude Sonnet |
| AutoPenBench | Unknown | ≥ 30% | xOffense 79% (Qwen3-32B tuned) |
| CVE-Bench (one-day) | Unknown | ≥ 60% | GPT-4 87% with advisory |
| HackTheBox retired (easy) | Unknown | ≥ 50% | — |

Publish results per-release in `docs/benchmarks.md`.

---

## Research References

Living list — add as you read.

**Swarm intelligence foundations:**
- [LLM-Powered Swarms (arXiv:2506.14496)](https://arxiv.org/pdf/2506.14496)
- [Multi-agent systems powered by LLMs: swarm intelligence (Frontiers AI 2025)](https://www.frontiersin.org/journals/artificial-intelligence/articles/10.3389/frai.2025.1593017/full)
- [Ledger-State Stigmergy (arXiv:2604.03997)](https://arxiv.org/abs/2604.03997)

**State of the art in AI pentesting:**
- [Pentest-R1 (arXiv:2508.07382)](https://arxiv.org/abs/2508.07382) — 2-stage RL
- [Cybench (arXiv:2408.08926)](https://arxiv.org/abs/2408.08926)
- [CAIBench meta-benchmark (arXiv:2510.24317)](https://arxiv.org/html/2510.24317v1)
- [Benchmarking LLM-driven Offensive Security (arXiv:2504.10112)](https://arxiv.org/html/2504.10112)
- [Cloak, Honey, Trap — USENIX Security 2025](https://www.usenix.org/conference/usenixsecurity25/presentation/ayzenshteyn)

**Memory / reasoning techniques:**
- [From Experience to Strategy — trainable graph memory (arXiv:2511.07800)](https://arxiv.org/html/2511.07800v1)
- [SAILOR symbolic + LLM (arXiv:2604.06506)](https://arxiv.org/abs/2604.06506)

**Agent security (for Phase 3.4):**
- [MemoryGraft (arXiv:2512.16962)](https://arxiv.org/abs/2512.16962)
- [MINJA memory injection (arXiv:2503.03704)](https://arxiv.org/html/2503.03704v2)
- [Dark Side of LLMs — agent takeover (arXiv:2507.06850)](https://arxiv.org/html/2507.06850v3)

**MCP ecosystem:**
- [PortSwigger Burp MCP](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [PentestMCP (arXiv:2510.03610)](https://arxiv.org/html/2510.03610v1)
- [Top MCP Servers for Cybersecurity 2026 (Levo)](https://www.levo.ai/resources/blogs/top-mcp-servers-for-cybersecurity-2026)

---

## Revision Log

- **2026-04-18**: v1 draft. Wave 1 / 2 / 3 structure, Blackboard architecture, ADK decision.
