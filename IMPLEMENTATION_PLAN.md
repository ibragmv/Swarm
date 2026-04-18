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

- [ ] **1.1.1** Define `Blackboard` Go interface in `internal/swarm/blackboard/board.go`
  - [ ] `Write(ctx, Finding) error` — append-only, returns finding ID
  - [ ] `Query(ctx, Predicate) iter.Seq[Finding]` — SQL + vector hybrid
  - [ ] `Subscribe(ctx, Predicate) <-chan Finding` — blocking stream
  - [ ] `Pheromone(findingID) float64` — weight with time decay
  - [ ] Unit tests for write/query/subscribe with fake clock
- [ ] **1.1.2** Postgres schema migration `migrations/005_blackboard.sql`
  - [ ] `findings` table: id, campaign_id, agent_id, type, data (jsonb), embedding (vector), pheromone_base, created_at, superseded_by
  - [ ] Index on (campaign_id, type), pgvector HNSW on embedding
  - [ ] `pheromone_decay()` SQL function (exponential, half-life configurable per-type)
  - [ ] Backfill script for existing DB
- [ ] **1.1.3** Agent `Trigger` abstraction in `internal/swarm/trigger/trigger.go`
  - [ ] `Predicate` as a composable struct (type match, vector similarity, pheromone threshold)
  - [ ] Trigger evaluation is idempotent — each agent tracks last-seen finding ID
- [ ] **1.1.4** Refactor each existing agent to the swarm model
  - [ ] `internal/agent/recon/agent.go` — trigger on `TARGET_REGISTERED`, writes `SUBDOMAIN`, `HTTP_ENDPOINT`, `PORT_OPEN`
  - [ ] `internal/agent/classifier/agent.go` — trigger on raw findings, writes `CVE_MATCH`, `CVSS_SCORE`
  - [ ] `internal/agent/exploit/agent.go` — trigger on `CVE_MATCH` with pheromone >0.5, writes `EXPLOIT_CHAIN`, `EXPLOIT_RESULT`
  - [ ] `internal/agent/report/agent.go` — trigger on campaign-complete signal
- [ ] **1.1.5** New scheduler in `internal/swarm/scheduler/scheduler.go`
  - [ ] Replaces `runner.go` phase loop
  - [ ] Per-agent concurrency caps (config)
  - [ ] Graceful shutdown on SIGINT within 5s (preserves existing guarantee)
  - [ ] Campaign-level budget: max agent-hours, max LLM tokens
- [ ] **1.1.6** Pheromone tuning
  - [ ] Per-finding-type decay half-lives in `config/pheromones.yaml`
  - [ ] CLI flag `--exploration-bias {low,med,high}` — scales new-vs-known weight
- [ ] **1.1.7** Delete `internal/engine/runner.go` sequential pipeline (keep a `legacy` subcommand behind `--legacy` flag for 1 release)
- [ ] **1.1.8** Integration test: deterministic seed, verify 3 agents interact through blackboard, final state matches golden file
- [ ] **1.1.9** Observability
  - [ ] OpenTelemetry spans per agent iteration
  - [ ] Export pheromone heatmap as Grafana dashboard
  - [ ] Log every blackboard write with structured JSON

### Phase 1.2 — Dashboard Wire-up

Current state: `web/` dashboard renders, `SeverityChart` hardcodes zeros, runner never persists to DB or streams to WS.

- [ ] **1.2.1** Wire scheduler → DB persistence in `internal/db/findings.go`
- [ ] **1.2.2** Wire scheduler → WebSocket `EventHub` for live updates
- [ ] **1.2.3** Replace mock data in `web/src/components/charts/SeverityChart.tsx` with real query
- [ ] **1.2.4** Add "live swarm" view: animated pheromone graph, active agents, findings stream
- [ ] **1.2.5** Playwright test: run `pentestswarm scan --dry-run` against mock target, assert chart values non-zero in <10s
- [ ] **1.2.6** Add campaign diff view (run N vs run N-1) — foundation for ASM mode

### Phase 1.3 — Safety Fixes

- [ ] **1.3.1** Wire cleanup registry in `internal/engine/runner.go:211` (currently `nil`)
  - [ ] Every exploit that creates artifacts (files, users, sessions) registers a cleanup
  - [ ] Cleanup runs on normal exit, SIGINT, and scheduler crash (panic recovery)
  - [ ] Unit test: simulated exploit, simulated crash, verify cleanup fired
- [ ] **1.3.2** Fix silent LLM fallback in `internal/agent/classifier/agent.go:69`
  - [ ] Surface errors to event stream
  - [ ] Add `--strict` CLI flag — abort on any LLM failure
  - [ ] Default mode: retry 3× with backoff, then fall back, but emit a WARN event
- [ ] **1.3.3** Fix recon empty-AttackSurface on JSON parse failure (`internal/agent/recon/agent.go:133-136`)
  - [ ] Retry prompt with narrower schema
  - [ ] On second failure, emit error-finding to blackboard (don't silently return empty)
- [ ] **1.3.4** Harden command executor (`internal/agent/exploit/executor.go:79-84`)
  - [ ] Replace naive field splitting with `shellwords.Parse`
  - [ ] Explicitly reject commands containing pipes, redirects, backticks unless allowlisted
  - [ ] Sandbox: all exploit commands run in a Docker container by default (config to opt out)
- [ ] **1.3.5** Scope enforcement audit
  - [ ] Every tool adapter re-validates scope before network call (defense-in-depth)
  - [ ] Log-and-abort on scope violation, not log-and-continue

### Phase 1.4 — LLM Layer Upgrades

- [ ] **1.4.1** Move hardcoded `claude-sonnet-4-6` (`internal/llm/claude.go:41`) to config
  - [ ] Default to `claude-sonnet-4-6`
  - [ ] Support `claude-opus-4-7`, `claude-haiku-4-5-20251001`
  - [ ] Per-agent model override (cheap agents on Haiku, reasoning on Opus)
- [ ] **1.4.2** Add prompt caching to Claude provider
  - [ ] Cache system prompt + tool definitions
  - [ ] Cache per-campaign shared context (scope, objective, recon summary)
  - [ ] Emit cache-hit metrics
- [ ] **1.4.3** Structured tool-use (replace JSON-in-prompt)
  - [ ] Define agent actions as Anthropic tools
  - [ ] Removes the JSON-parse-fail path entirely
- [ ] **1.4.4** Token budget per campaign + per agent — hard cap with soft warn
- [ ] **1.4.5** Add eval harness `tests/llm_eval/` — run fixed prompts, assert outputs match rubrics (per agent)

### Phase 1.5 — README Honesty Pass

(see full [README Rewrite](#readme-rewrite) section below)

---

## Wave 2 — Integrations & Workflows (6–8 weeks)

> The real pentester's toolbox, wired into the swarm, with named pipelines.

### Phase 2.1 — Core Tool Integrations

- [ ] **2.1.1** `nmap` adapter `internal/tools/nmap/nmap.go`
  - [ ] XML output parser → blackboard findings (`PORT_OPEN`, `SERVICE_VERSION`, `OS_FINGERPRINT`)
  - [ ] Rate limit + scope guard
  - [ ] Requires `nmap` binary; `doctor` check added
- [ ] **2.1.2** `sqlmap` adapter via `sqlmapapi` REST
  - [ ] Triggered by classifier `POTENTIAL_SQLI` findings
  - [ ] Uses the API daemon mode; one daemon per campaign
  - [ ] Writes `SQLI_CONFIRMED`, `DB_SCHEMA`, `DB_CREDS` (redacted) to blackboard
- [ ] **2.1.3** `ffuf` adapter `internal/tools/ffuf/ffuf.go`
  - [ ] Content discovery, param fuzzing
  - [ ] Wordlist registry (SecLists auto-download on first run, cached)
- [ ] **2.1.4** `gobuster` adapter (alternative content discovery for HTTP + DNS)
- [ ] **2.1.5** `trufflehog` adapter — repo + artifact secret scanning
- [ ] **2.1.6** `gitleaks` adapter — Git history secrets
- [ ] **2.1.7** `semgrep` adapter — SAST for in-scope repos
- [ ] **2.1.8** `amass` adapter — deeper OSINT/ASM than subfinder

### Phase 2.2 — Heavyweight Integrations

- [ ] **2.2.1** **Burp Suite MCP** bridge (official PortSwigger MCP)
  - [ ] Discover Burp via MCP client
  - [ ] Expose Burp scan results as blackboard findings
  - [ ] Allow swarm to request Burp active scan on a specific endpoint
  - [ ] This is a flagship differentiator — no competitor has a clean Burp integration
- [ ] **2.2.2** **Metasploit** via MSGRPC
  - [ ] Module search + execution
  - [ ] Session management (kept out of LLM context; referenced by handle)
  - [ ] All sessions registered in cleanup registry
- [ ] **2.2.3** **OWASP ZAP** REST API
  - [ ] Spider + active scan triggers
  - [ ] Consume ZAP alerts as findings
- [ ] **2.2.4** **Nuclei template author agent**
  - [ ] LLM generates candidate nuclei templates from novel findings
  - [ ] Auto-test against a known-safe corpus before writing to community templates

### Phase 2.3 — Swarm Playbooks (Named Pipelines)

Ship as YAML files in `playbooks/` — like Nuclei templates but for full swarm behaviors.

- [ ] **2.3.1** `playbooks/bug-bounty.yaml`
  - [ ] subfinder → httpx → katana → nuclei → Burp MCP active scan → sqlmap on flagged params → report
  - [ ] Deduplicates against HackerOne/Bugcrowd previous submissions (scope API)
- [ ] **2.3.2** `playbooks/external-asm.yaml`
  - [ ] amass + subfinder → dnsx → naabu → httpx → gowitness screenshots → nuclei
  - [ ] Diffs against last run, alerts on new assets
  - [ ] Designed for cron / scheduled re-runs
- [ ] **2.3.3** `playbooks/ci-cd-security.yaml`
  - [ ] Triggered by GitHub Action
  - [ ] semgrep + gitleaks + trufflehog + dep audit
  - [ ] Outputs SARIF to GHAS
- [ ] **2.3.4** `playbooks/internal-network.yaml`
  - [ ] nmap → service enum → Metasploit post-ex (read-only by default)
  - [ ] Cleanup always runs
  - [ ] Gated behind explicit written-scope file at `./scope/<date>.yaml`
- [ ] **2.3.5** `playbooks/ctf-solver.yaml`
  - [ ] HackTheBox/TryHackMe flow: enum → foothold → privesc → flag
  - [ ] Benchmark against Cybench
- [ ] **2.3.6** Playbook schema + validator (`internal/playbook/schema.go`)
- [ ] **2.3.7** `pentestswarm playbook run <name>` CLI wiring
- [ ] **2.3.8** "Playbook marketplace" page on site (v1: just a listing; v2: submit PRs)

### Phase 2.4 — CI/CD & Ecosystem

- [ ] **2.4.1** GitHub Action (already scaffolded in `deploy/github-action/`)
  - [ ] Publish to GitHub Marketplace
  - [ ] SARIF output integrates with Code Scanning
  - [ ] Fail-PR-on-critical flag
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

- [ ] **R.1** Hero block
  - [ ] Tagline unchanged
  - [ ] Demo GIF (already done — `docs/demo.gif`)
  - [ ] Badges: build status, stars, license, Discord, benchmark score
- [ ] **R.2** New section: *"What is swarm intelligence?"*
  - [ ] Stigmergy definition with an example
  - [ ] Diagram: Blackboard + agents + pheromones
  - [ ] Contrast with orchestrated multi-agent systems (explicit table)
- [ ] **R.3** New section: *"Why swarms for pentesting?"*
  - [ ] Parallelism on recon
  - [ ] Resilience (dead-end recovery via pheromone decay)
  - [ ] Emergent exploit chains
  - [ ] Scale-free across target sizes
- [ ] **R.4** Competitor table
  - [ ] Columns: architecture, executes or suggests, memory, tools, MCP, benchmarks
  - [ ] Rows: us, PentestGPT, HackingBuddyGPT, PentAGI, Shannon, HexStrike, Pentest-R1
- [ ] **R.5** Benchmark numbers inline (after Phase 3.3 ships)
- [ ] **R.6** Update "5-agent architecture" claim — either ship 5 real agents or say "4 agents + scheduler"
- [ ] **R.7** Update "ReAct loop" claim — describe as *stigmergic* once Phase 1.1 is merged
- [ ] **R.8** Drop the "7-tool" claim when `nmap`/`sqlmap`/`ffuf` land — say "15+ integrated tools"
- [ ] **R.9** Alpha/beta/stable labels per feature — honest status beats aspirational
- [ ] **R.10** Credits & research section with the arXiv reading list

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
