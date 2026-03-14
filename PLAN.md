# Auto-Pentest-GPT-AI
### Autonomous AI-Powered Penetration Testing Platform

> A multi-agent AI system that autonomously performs full-cycle penetration tests — from recon through exploitation through professional reporting — powered by four specialized fine-tuned open source models coordinated by an orchestrator agent.

---

## Vision

Most security tools collect data or execute commands. None of them *think*. Auto-Pentest-GPT-AI is the first platform built around a multi-agent AI architecture where each agent is a specialist — fine-tuned on a best-in-class open source model for its specific task — coordinated by an orchestrator that plans the campaign and synthesizes the results.

The result: a penetration test that runs autonomously from target input to final report, with the reasoning quality of an experienced pentester.

---

## The Problem

Penetration testing today is:
- **Expensive** — skilled pentesters are scarce and charge $200-400/hour
- **Infrequent** — most organizations test once a year, missing changes in attack surface
- **Manual** — tools generate data; humans do all the thinking
- **Inconsistent** — quality varies massively by individual tester skill

Existing automated tools (Metasploit, Burp, Nuclei) are powerful but narrow. They don't reason. They don't chain findings. They don't adapt. They don't explain. They produce data dumps, not intelligence.

---

## The Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      USER INTERFACE                              │
│              (CLI + Web UI + REST API)                           │
└─────────────────────────────┬───────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                    ORCHESTRATOR AGENT                            │
│                                                                  │
│  Model: Claude API  OR  Large Local LLM (user's choice)         │
│  e.g. claude-opus-4-6 | llama3.1:70b | qwen2.5:72b via Ollama  │
│                                                                  │
│  Responsibilities:                                               │
│  • Plans the full campaign given target + objective              │
│  • Dispatches tasks to specialist agents                         │
│  • Synthesizes outputs into a coherent attack narrative          │
│  • Makes high-level decisions: pursue path A or B, stop or       │
│    continue, escalate or pivot                                   │
│  • Handles novel situations outside specialist training          │
└──────┬──────────────┬──────────────┬──────────────┬─────────────┘
       │              │              │              │
       ▼              ▼              ▼              ▼
┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────┐
│   RECON    │ │ CLASSIFIER │ │  EXPLOIT   │ │  REPORT    │
│   AGENT    │ │   AGENT    │ │   AGENT    │ │   AGENT    │
│            │ │            │ │            │ │            │
│ Qwen 2.5   │ │ Mistral 7B │ │ DeepSeek   │ │ Llama 3.1  │
│ 7B         │ │ (fine-     │ │ R1 8B      │ │ 8B         │
│ (fine-     │ │ tuned)     │ │ (fine-     │ │ (fine-     │
│ tuned)     │ │            │ │ tuned)     │ │ tuned)     │
└────────────┘ └────────────┘ └────────────┘ └────────────┘
```

---

## Agent Responsibilities

### Agent 1 — Orchestrator
**Model:** Claude API (`claude-opus-4-6`) or large local LLM (Llama 3.1 70B, Qwen 2.5 72B via Ollama/LM Studio) — **user's choice**

The brain of the system. Doesn't execute techniques directly — it plans, coordinates, and synthesizes. Receives structured outputs from all specialist agents and makes campaign-level decisions. This is where frontier reasoning capability matters most, which is why it runs on the most capable available model.

### Agent 2 — Recon Agent
**Base model:** Qwen 2.5 7B (fine-tuned)
**Why Qwen:** Best-in-class structured data understanding at 7B scale, 128k context window for large recon dumps, exceptional at parsing heterogeneous tool output formats.

Takes raw output from recon tools (nmap, subfinder, httpx, whatweb, ffuf, etc.) and produces a structured, normalized attack surface model. Correlates findings across tools — the same host appearing in multiple tool outputs becomes one enriched record, not three separate findings.

### Agent 3 — Classifier Agent
**Base model:** Mistral 7B (fine-tuned)
**Why Mistral:** Extremely efficient at classification tasks, low latency, strong instruction following.

Sits between Recon and Exploit agents. Takes individual findings from the attack surface model and classifies each one: maps to CVE IDs where applicable, assigns CVSS score, filters false positives, ranks by severity and exploitability, tags with relevant attack categories (OWASP Top 10, ATT&CK). Offloads structured classification from both neighboring agents, making the whole pipeline more accurate.

### Agent 4 — Exploit Agent
**Base model:** DeepSeek R1 8B (fine-tuned)
**Why DeepSeek R1:** R1's chain-of-thought reasoning architecture is remarkable at this scale — it genuinely reasons through multi-step problems rather than just pattern matching. Critical for the hardest task in the pipeline: constructing multi-step attack chains from a classified attack surface.

Takes the classified attack surface from the Classifier Agent and constructs ranked attack paths. Knows CVE-to-exploitation mappings, technique chaining, and when/how to escalate from one finding to the next. Returns ordered attack plan with specific commands to the Orchestrator.

### Agent 5 — Report Agent
**Base model:** Llama 3.1 8B (fine-tuned)
**Why Llama 3.1:** Meta's strongest model at this scale for long-form structured writing, excellent instruction following, consistent professional tone — exactly what report generation requires.

Takes all confirmed findings, evidence, and context accumulated during the campaign and generates a complete professional penetration test report: executive summary, technical findings with CVSS scores, attack narrative, evidence screenshots/output, and prioritized remediation recommendations.

---

## LLM Provider Configuration

Users configure their preferred provider once:

```yaml
# config.yaml
orchestrator:
  provider: claude          # claude | ollama | lmstudio
  model: claude-opus-4-6    # or llama3.1:70b, qwen2.5:72b, etc.
  api_key: sk-ant-...       # required if provider: claude
  endpoint: null            # required if provider: ollama/lmstudio

specialist_agents:
  # These always run locally — privacy by default
  recon:
    model: autopentest-recon-qwen2.5-7b
    endpoint: http://localhost:11434   # Ollama
  classifier:
    model: autopentest-classifier-mistral-7b
    endpoint: http://localhost:11434
  exploit:
    model: autopentest-exploit-deepseek-r1-8b
    endpoint: http://localhost:11434
  report:
    model: autopentest-report-llama3.1-8b
    endpoint: http://localhost:11434
```

The specialist agents always run locally — they handle sensitive target data and raw findings. Only the orchestrator's traffic (high-level planning, no raw target data) goes to Claude API if the user chooses that path.

---

## Repository Structure

```
auto-pentest-gpt-ai/
├── orchestrator/               # Orchestrator agent
│   ├── agent.py                # Main ReAct agent loop
│   ├── planner.py              # Campaign planning logic
│   ├── coordinator.py          # Dispatches tasks to specialist agents
│   ├── providers/              # LLM provider abstractions
│   │   ├── base.py             # Abstract LLMProvider
│   │   ├── claude.py           # Anthropic SDK integration
│   │   ├── ollama.py           # Ollama local integration
│   │   └── lmstudio.py         # LM Studio integration
│   └── tools/                  # Orchestrator tool definitions
├── agents/                     # Specialist agents
│   ├── base.py                 # Abstract SpecialistAgent
│   ├── recon/
│   │   ├── agent.py            # Recon agent logic
│   │   ├── tools/              # Tool execution wrappers
│   │   │   ├── nmap.py
│   │   │   ├── subfinder.py
│   │   │   ├── httpx.py
│   │   │   ├── ffuf.py
│   │   │   ├── whatweb.py
│   │   │   ├── nuclei.py
│   │   │   ├── gau.py
│   │   │   └── amass.py
│   │   └── parser.py           # Normalizes tool outputs
│   ├── classifier/
│   │   ├── agent.py            # Classifier agent logic
│   │   ├── cve_mapper.py       # Finding → CVE mapping
│   │   └── scorer.py           # CVSS scoring
│   ├── exploit/
│   │   ├── agent.py            # Exploit agent logic
│   │   ├── path_builder.py     # Attack path construction
│   │   └── executor.py         # Command execution engine
│   └── report/
│       ├── agent.py            # Report agent logic
│       ├── templates/          # Report format templates
│       └── renderer.py         # PDF/HTML/Markdown output
├── models/                     # Fine-tuned model management
│   ├── registry.py             # Model download/version tracking
│   └── pull.py                 # Pull models from HuggingFace Hub
├── pipeline/                   # Campaign orchestration
│   ├── campaign.py             # Campaign state machine
│   ├── state.py                # State definitions
│   └── context.py              # Shared campaign context
├── scope/                      # Scope enforcement
│   ├── validator.py            # Target validation
│   └── authorization.py        # Authorization token management
├── api/                        # REST API (FastAPI)
│   ├── main.py
│   └── routers/
├── web/                        # React frontend
├── cli/                        # Click CLI
│   └── main.py
├── data/                       # Training data generation (fine-tuning)
│   ├── recon/                  # Recon agent training data
│   ├── classifier/             # Classifier agent training data
│   ├── exploit/                # Exploit agent training data
│   └── report/                 # Report agent training data
├── training/                   # Fine-tuning scripts
│   ├── generate_data.py        # Synthetic data generation via Claude
│   ├── train_recon.py
│   ├── train_classifier.py
│   ├── train_exploit.py
│   └── train_report.py
├── tests/
├── docker/
│   ├── Dockerfile.controller
│   └── docker-compose.yml
├── config.example.yaml
├── requirements.txt
└── setup.py
```

---

## Campaign Flow (End to End)

```
1. User provides: target domain/IP + objective + scope definition

2. ORCHESTRATOR: Plans campaign
   → Determines recon depth based on target type
   → Sets campaign milestones: recon → classify → exploit → report

3. RECON AGENT: Executes recon tools in parallel
   → subfinder (subdomain enumeration)
   → nmap (port + service scanning)
   → httpx (HTTP probing, tech detection)
   → whatweb (technology fingerprinting)
   → gau (historical URL discovery)
   → ffuf (directory/endpoint fuzzing)
   → nuclei (lightweight vuln scanning)
   → Parses all output → builds normalized AttackSurface model
   → Returns structured AttackSurface to Orchestrator

4. ORCHESTRATOR: Reviews attack surface
   → Prioritizes most interesting findings
   → Dispatches to Classifier Agent

5. CLASSIFIER AGENT: Classifies each finding
   → Maps findings to CVE IDs
   → Assigns CVSS scores
   → Filters false positives
   → Ranks by exploitability
   → Returns ClassifiedFindingSet to Orchestrator

6. ORCHESTRATOR: Reviews classified findings
   → Makes strategic decisions: which paths to pursue
   → Dispatches to Exploit Agent with prioritized findings

7. EXPLOIT AGENT: Constructs attack paths
   → Reasons through attack chains
   → Suggests specific techniques + commands per finding
   → Returns RankedAttackPlan to Orchestrator

8. ORCHESTRATOR: Executes attack plan
   → Approves each step
   → Runs commands via exploit executor
   → Feeds results back to Exploit Agent
   → Exploit Agent adapts plan based on results
   → Loop continues until objective reached or all paths exhausted

9. ORCHESTRATOR: Determines campaign complete
   → Compiles all findings, evidence, command outputs
   → Dispatches to Report Agent

10. REPORT AGENT: Generates professional report
    → Executive summary
    → Technical findings with evidence
    → Attack narrative
    → CVSS-scored vulnerability list
    → Remediation recommendations
    → Delivers report in user's chosen format (PDF/HTML/Markdown)
```

---

## Sprint Plan

---

### Sprint 0 — Project Setup & Foundation
**Duration:** 1 week
**Goal:** Clean professional project structure, working local dev environment, every engineer productive in under 10 minutes.

**Why this sprint matters:** The existing repo is a single Python file. We're building a professional platform. Establishing clean structure, tooling, and conventions now prevents accumulating debt across every subsequent sprint.

#### Repository Cleanup & Structure
- Archive `PentestAI.py` → `legacy/PentestAI.py` (preserve history, don't delete)
- Archive `Pentest_LLM.gguf` reference → document in `legacy/README.md`
- Create full directory structure as defined in Repository Structure above
- Initialize all `__init__.py` files, stub modules with docstrings
- Update root `README.md`: new architecture overview, quick start guide, agent descriptions

#### Python Project Setup
- Set up `pyproject.toml`: project metadata, dependencies, tool configs
- Configure `ruff` (linting), `black` (formatting), `mypy` (type checking)
- Configure `pytest` + `pytest-asyncio` for async test support
- Set up `pre-commit` hooks: ruff, black, mypy, `detect-secrets`
- Create `requirements.txt` split into:
  - `requirements/base.txt` — core runtime deps
  - `requirements/dev.txt` — dev + testing deps
  - `requirements/training.txt` — fine-tuning deps (heavy: torch, unsloth, etc.)

#### Local Development Environment
- Write `docker-compose.yml`: Ollama (serves local models), PostgreSQL (campaign history), Redis (task queue), the API server with hot reload
- Write `config.example.yaml`: all configuration options documented with descriptions and defaults
- Write `scripts/setup.sh`: installs Ollama, pulls placeholder models, sets up DB, runs seed data
- Write `Makefile` with targets: `make dev`, `make test`, `make lint`, `make build-agent`

#### Core Config & Logging
- Implement `config.py` using `pydantic-settings`: loads from `config.yaml` + env vars, validates all required fields on startup
- Implement `logging.py` using `structlog`: structured JSON logging, campaign ID propagated in all log lines
- Implement `exceptions.py`: `ScopeViolation`, `AgentError`, `ToolExecutionError`, `ModelUnavailable`, `AuthorizationError`

#### Scope Enforcement (Build First)
- Implement `scope/validator.py`:
  - `ScopeDefinition`: list of allowed IP ranges (CIDR), allowed domains, allowed ports
  - `validate_target(target: str, scope: ScopeDefinition) -> bool`
  - `validate_command(command: str, scope: ScopeDefinition) -> bool` — parses command for embedded IPs/domains, checks each against scope
  - **Every tool execution MUST call `validate_target` before running. Hard failure on violation.**
- Implement `scope/authorization.py`: simple authorization token (signed JSON with campaign ID, scope, expiry, operator name) — required to start any campaign

**Acceptance Criteria:**
- [ ] `make dev` produces running local stack with no manual steps
- [ ] `make test` runs empty test suite and passes
- [ ] Attempting to target an out-of-scope IP raises `ScopeViolation`
- [ ] `config.example.yaml` covers all configuration options

**Dependencies:** None

---

### Sprint 1 — LLM Provider Abstraction Layer
**Duration:** 1 week
**Goal:** Build the unified LLM interface that every agent talks to — Claude, Ollama, or LM Studio, transparently.

**Why this sprint matters:** Every agent in the system sends prompts and receives responses. If the provider abstraction is wrong, changing it later means touching every agent. Get this interface right once.

#### Abstract Provider Interface (`orchestrator/providers/base.py`)
- Define `LLMProvider` abstract base class:
  ```python
  class LLMProvider(ABC):
      @abstractmethod
      async def complete(self, messages: list[Message], tools: list[Tool] | None = None,
                         stream: bool = False) -> CompletionResponse: ...

      @abstractmethod
      async def stream(self, messages: list[Message], tools: list[Tool] | None = None
                       ) -> AsyncIterator[str]: ...

      @abstractmethod
      async def health_check(self) -> bool: ...

      @property
      @abstractmethod
      def supports_tool_use(self) -> bool: ...

      @property
      @abstractmethod
      def context_window(self) -> int: ...
  ```
- Define `Message(role, content)`, `Tool(name, description, parameters)`, `CompletionResponse(content, tool_calls, usage)` Pydantic models
- Define `ToolCall(tool_name, arguments)`, `Usage(input_tokens, output_tokens)` models

#### Claude Provider (`orchestrator/providers/claude.py`)
- Implement `ClaudeProvider(LLMProvider)` using `anthropic` Python SDK
- Support all Claude models: `claude-opus-4-6`, `claude-sonnet-4-6`, `claude-haiku-4-5`
- Implement tool use via Anthropic's tool calling API
- Implement streaming via `stream=True` on `messages.create`
- Implement token budget management: warn when approaching context window
- Implement retry with exponential backoff on rate limit errors (429)
- Track usage per campaign in DB for cost monitoring

#### Ollama Provider (`orchestrator/providers/ollama.py`)
- Implement `OllamaProvider(LLMProvider)` using `httpx` async client against Ollama REST API
- `POST /api/chat` with `model`, `messages`, `stream` params
- Implement tool use via JSON mode + parsing (Ollama doesn't have native tool calling for all models — implement structured output parsing as fallback)
- Health check: `GET /api/tags` to verify Ollama is running and model is pulled
- Implement `pull_model(model_name)` convenience method: `POST /api/pull`

#### LM Studio Provider (`orchestrator/providers/lmstudio.py`)
- Implement `LMStudioProvider(LLMProvider)` using OpenAI-compatible API that LM Studio exposes
- `POST /v1/chat/completions` — identical to OpenAI format
- Use `openai` Python SDK with `base_url` pointed at local LM Studio server
- Health check: `GET /v1/models` to verify server is running and model is loaded

#### Provider Factory (`orchestrator/providers/factory.py`)
- Implement `create_provider(config: OrchestratorConfig) -> LLMProvider`: reads config, instantiates correct provider
- Implement `validate_provider(provider: LLMProvider)`: runs health check, validates model is available, checks context window size meets minimum requirement (32k tokens)

#### Tests (`tests/test_providers.py`)
- Unit tests for each provider using `pytest-httpx` to mock HTTP calls
- Test: correct message format sent to each provider
- Test: tool call response correctly parsed for each provider
- Test: streaming yields tokens correctly
- Test: retry logic fires on 429 response
- Integration test (marked `@pytest.mark.integration`): real call to each provider if credentials/server available

**Acceptance Criteria:**
- [ ] All three providers implement `LLMProvider` interface and pass type checking
- [ ] Switching provider in config requires zero code changes in any agent
- [ ] Claude provider correctly parses tool call responses
- [ ] Ollama provider health check correctly detects when Ollama is not running
- [ ] Token usage is tracked and logged for Claude provider

**Dependencies:** Sprint 0

---

### Sprint 2 — Recon Agent & Tool Integration
**Duration:** 2 weeks
**Goal:** Build the Recon Agent — tool execution wrappers for 8 recon tools + the Qwen-powered analysis layer that turns raw output into a structured attack surface model.

**Why this sprint matters:** Everything downstream depends on the quality of the attack surface model. Bad recon = bad exploitation. This sprint defines the data model every other agent consumes.

#### Attack Surface Data Model (`pipeline/context.py`)
- Define `HostRecord`: IP, hostnames, open_ports, services (port → ServiceRecord), os_detection, last_seen
- Define `ServiceRecord`: port, protocol, service_name, version, banner, http_details (if web service)
- Define `HttpDetails`: url, status_code, title, server_header, technologies (list), response_headers, cookies, redirects
- Define `SubdomainRecord`: domain, ip, cname, http_details, discovery_source
- Define `EndpointRecord`: url, method, parameters, response_code, interesting (bool), notes
- Define `AttackSurface`: target, subdomains (list), hosts (list), endpoints (list), technologies (dict), raw_findings (list), metadata
- All models are Pydantic, serializable to JSON, stored in PostgreSQL as JSONB

#### Tool Wrappers (`agents/recon/tools/`)
Each tool wrapper implements `BaseTool`:
```python
class BaseTool(ABC):
    name: str
    @abstractmethod
    async def run(self, target: str, options: dict) -> ToolResult: ...
    @abstractmethod
    def parse_output(self, raw_output: str) -> list[dict]: ...
```

- **`nmap.py`**: async subprocess wrapper for nmap; default flags `-sV -sC -O --open`; parse XML output (`-oX`) using `python-nmap`; extract: open ports, service names/versions, OS detection, script output; support fast mode (`-T4 -F`) and thorough mode (`-A`)

- **`subfinder.py`**: async subprocess; parse JSON output (`-oJ`); extract: subdomain list with sources; integrate with DNS resolution to get IPs

- **`httpx.py`**: async subprocess; parse JSONL output; extract: status code, title, server, content-type, content-length, technologies, redirect chain, TLS info

- **`whatweb.py`**: async subprocess; parse JSON output (`--log-json`); extract: CMS, frameworks, JS libraries, server software, version numbers

- **`gau.py`**: async subprocess; parse line-delimited URL output; deduplicate; filter by interesting extensions (`.php`, `.asp`, `.aspx`, `.jsp`, `.env`, `.git`, `.config`, `.bak`, `.sql`, `.log`)

- **`ffuf.py`**: async subprocess; parse JSON output (`-o /tmp/ffuf.json -of json`); built-in wordlist selection based on detected technology (PHP wordlist for PHP apps, etc.); extract: discovered paths, response codes, sizes

- **`nuclei.py`**: async subprocess; parse JSONL output; extract: template ID, severity, name, matched-at URL, extracted values; default: run `-t technologies` and `-t exposures` templates only (non-destructive)

- **`amass.py`**: async subprocess for passive mode only (`enum -passive`); parse text output; extract: additional subdomains from passive sources

#### Tool Execution Engine (`agents/recon/tools/executor.py`)
- Implement `ToolExecutor`: manages parallel tool execution with `asyncio.gather`
- Implement timeout enforcement per tool (nmap: 5min, subfinder: 2min, others: 90s)
- Implement retry logic: if tool exits non-zero, retry once with simplified flags
- Implement tool availability check at startup: `which <tool>` for each; warn if missing, suggest install command
- Scope validation: `validate_command(command, scope)` called before every subprocess execution

#### Recon Agent (`agents/recon/agent.py`)
- Implement `ReconAgent`:
  - `plan_recon(target, scope) -> ReconPlan`: determines which tools to run and in what order based on target type (domain → subfinder first; IP → nmap first; web app → httpx + ffuf)
  - `execute_recon(plan: ReconPlan) -> RawReconData`: runs all tools, collects output
  - `analyze(raw: RawReconData) -> AttackSurface`: sends all raw tool output to fine-tuned Qwen 2.5 7B model for analysis and normalization
- Prompt design for Qwen model (pre-fine-tuning — will be improved with fine-tuned model):
  - System: "You are a recon analysis expert. Given raw output from multiple security tools, extract a structured attack surface model. Correlate findings across tools. Identify the most interesting endpoints, exposed services, and technology stack."
  - Input: structured raw tool outputs
  - Output: JSON matching `AttackSurface` schema

#### Output Parser (`agents/recon/parser.py`)
- Implement `AttackSurfaceParser`: validates Qwen output against `AttackSurface` Pydantic model
- Handle partial/malformed JSON output: retry with simplified prompt if parsing fails
- Deduplication: merge duplicate hosts/subdomains found by multiple tools into single enriched records

**Acceptance Criteria:**
- [ ] nmap wrapper correctly parses XML output and returns structured `list[HostRecord]`
- [ ] subfinder + httpx run in parallel against a test domain and results are merged
- [ ] `AttackSurface` model correctly serializes to JSON and persists to DB
- [ ] Recon agent completes full recon of a test domain in <5 minutes
- [ ] Scope validator blocks tool execution against out-of-scope targets

**Dependencies:** Sprint 1

---

### Sprint 3 — Classifier Agent
**Duration:** 1 week
**Goal:** Build the Classifier Agent — takes the attack surface model and enriches every finding with CVE mappings, CVSS scores, false positive filtering, and severity ranking.

**Why this sprint matters:** The Exploit Agent's quality is bounded by the quality of its input. Unclassified raw findings are noise. Classified, scored, ranked findings are a prioritized target list.

#### CVE Mapping (`agents/classifier/cve_mapper.py`)
- Implement `CVEMapper`:
  - Query NVD API v2.0 for CVEs by: `keywordSearch` (technology name + version), CPE name matching
  - Cache results in PostgreSQL: `cve_cache` table with TTL of 24 hours
  - For each service version detected in recon: `get_cves(service_name, version) -> list[CVE]`
  - Each `CVE`: id, description, cvss_v3_score, cvss_v3_vector, published_date, references
- Integrate `vulners` Python library as secondary CVE source for broader coverage

#### CVSS Scorer (`agents/classifier/scorer.py`)
- Implement `CVSSScorer`:
  - Parse CVSS v3.1 vector strings into component scores
  - Compute exploitability score, impact score, base score
  - Adjust base score with contextual modifiers: internet-facing (×1.2), authenticated_required (×0.7), known_exploit_available (×1.3)
  - Output: `SeverityRating` enum: `CRITICAL | HIGH | MEDIUM | LOW | INFORMATIONAL`

#### False Positive Filter (`agents/classifier/fp_filter.py`)
- Implement pattern-based false positive detection:
  - Remove generic "Server: Apache" findings without version numbers
  - Remove findings on non-responsive endpoints (4xx/5xx without meaningful content)
  - Remove duplicate findings (same CVE on same port)
  - Flag findings that require manual verification (e.g. "default credentials" — cannot be auto-verified without attempting login)
- Implement confidence scoring: `HIGH | MEDIUM | LOW | UNVERIFIED` per finding

#### Classifier Agent (`agents/classifier/agent.py`)
- Implement `ClassifierAgent`:
  - `classify(surface: AttackSurface) -> ClassifiedFindingSet`
  - For each finding in attack surface: run CVE mapping + CVSS scoring + FP filter
  - Send to fine-tuned Mistral 7B model for contextual classification:
    - Is this interesting given the overall target profile?
    - Does this finding chain with other findings?
    - What attack category does this fall into? (OWASP Top 10, auth bypass, info disclosure, RCE, etc.)
  - Output: `ClassifiedFindingSet` — sorted by exploitability score, grouped by attack category
- Define `ClassifiedFinding`: finding_id, original_finding, cve_ids, cvss_score, severity, attack_category, confidence, false_positive_probability, chain_candidates (other finding IDs this could chain with), notes

**Acceptance Criteria:**
- [ ] CVE mapper returns correct CVEs for Apache 2.4.49 (known critical CVE)
- [ ] CVSS scorer correctly computes base score from vector string
- [ ] False positive filter removes generic server banner findings
- [ ] Classifier produces sorted `ClassifiedFindingSet` with severity ratings
- [ ] Classification completes in <60 seconds for a 50-finding attack surface

**Dependencies:** Sprint 2

---

### Sprint 4 — Exploit Agent & Execution Engine
**Duration:** 2 weeks
**Goal:** Build the Exploit Agent — the DeepSeek R1-powered system that constructs multi-step attack chains and the execution engine that runs them safely.

**Why this sprint matters:** This is the most technically challenging agent. Attack path construction requires genuine multi-step reasoning — not pattern matching. DeepSeek R1's chain-of-thought architecture is specifically chosen for this.

#### Attack Path Model (`pipeline/context.py` additions)
- Define `AttackPath`: path_id, name, description, steps (ordered list of `AttackStep`), target_finding_ids, estimated_success_probability, required_privileges, expected_impact
- Define `AttackStep`: step_id, technique_name, mitre_technique_id, command, expected_output_pattern, on_success (next step ID), on_failure (fallback step ID or null), cleanup_command
- Define `AttackPlan`: plan_id, campaign_id, paths (ranked list of `AttackPath`), recommended_path_id, reasoning
- Define `ExecutionResult`: step_id, command_executed, output, success, evidence, timestamp

#### Exploit Agent (`agents/exploit/agent.py`)
- Implement `ExploitAgent`:
  - `build_attack_plan(findings: ClassifiedFindingSet, objective: str) -> AttackPlan`
    - Sends classified findings + objective to DeepSeek R1 8B model
    - Model reasons through: which findings are most exploitable, how to chain them, what the kill chain looks like from initial finding to objective
    - Returns structured `AttackPlan` JSON
  - `adapt_plan(plan: AttackPlan, step_result: ExecutionResult) -> AttackPlan`
    - After each step execution, feeds result back to model
    - Model reasons: did this succeed as expected? What does it change about the remaining plan? Should we pivot?
    - Returns updated plan

- Prompt design for DeepSeek R1 (pre-fine-tuning):
  - Leverage R1's `<think>` chain-of-thought: explicitly ask for reasoning before answer
  - "Think through each finding and how it could be exploited. Consider chaining: can finding A be used to gain access that makes finding B exploitable? Construct the most efficient path to the objective."

#### Attack Path Builder (`agents/exploit/path_builder.py`)
- Implement `PathBuilder`: programmatic (non-LLM) attack path construction as a fallback and supplement to LLM reasoning
  - `build_chains(findings: list[ClassifiedFinding]) -> list[AttackPath]`: graph-based chain construction
  - Nodes: findings; Edges: "finding A enables finding B" relationships (e.g. directory traversal → read config file → extract credentials → authenticate to admin panel)
  - Pre-defined relationship rules: `SQLI_enables_data_extraction`, `PATH_TRAVERSAL_enables_file_read`, `OPEN_REDIRECT_enables_phishing`, `EXPOSED_GIT_enables_source_code_review`, etc.
  - LLM supplements this with novel chains the rules don't cover

#### Command Execution Engine (`agents/exploit/executor.py`)
- Implement `CommandExecutor`:
  - `execute(command: str, timeout: int, scope: ScopeDefinition) -> ExecutionResult`
  - **Pre-execution:** `validate_command(command, scope)` — parse command for embedded targets, verify all against scope
  - Execute via `asyncio.create_subprocess_shell` with `timeout`
  - Capture stdout, stderr, return code
  - Pattern match output against `expected_output_pattern` in `AttackStep` to determine success
  - Register cleanup command before executing (cleanup runs even if campaign aborts)
- Implement `DryRunExecutor`: prints commands without executing — `--dry-run` mode for reviewing planned attacks before running

#### Cleanup Registry (`pipeline/campaign.py`)
- Before every command execution: `register_cleanup(campaign_id, cleanup_command, target)`
- `run_cleanup(campaign_id)`: executes all registered cleanup commands in reverse order
- Persist to DB: survives controller restarts

**Acceptance Criteria:**
- [ ] Exploit agent constructs a valid multi-step attack path from a test `ClassifiedFindingSet`
- [ ] Command executor correctly captures output and matches against expected pattern
- [ ] Scope validator blocks execution of commands targeting out-of-scope hosts
- [ ] Dry run mode prints all commands without executing any
- [ ] Cleanup registry correctly reverses test file creation during cleanup

**Dependencies:** Sprints 2, 3

---

### Sprint 5 — Orchestrator Agent
**Duration:** 2 weeks
**Goal:** Build the Orchestrator Agent — the ReAct loop that plans campaigns, coordinates the four specialist agents, and makes high-level decisions.

**Why this sprint matters:** This is the glue. The orchestrator turns four independent agents into a coherent, adaptive campaign. It's the only agent that sees the full picture.

#### ReAct Agent Loop (`orchestrator/agent.py`)
- Implement `OrchestratorAgent` as a ReAct (Reason + Act) loop:
  ```
  loop:
    1. THINK: Given campaign state + memory + last result → what to do next
    2. ACT: Call a tool (run_recon, classify_findings, build_attack_plan,
                         execute_step, generate_report, pause, complete)
    3. OBSERVE: Receive structured result from tool/agent call
    4. REMEMBER: Append to campaign memory
    5. goto 1
  ```
- Implement tool calling: each specialist agent operation is a tool the orchestrator can invoke
- Implement campaign memory: rolling structured log of all decisions, actions, results — passed as context on each loop iteration
- Implement token budget management: summarize old memory when approaching context window limit

#### Orchestrator Tools (`orchestrator/tools/`)
- `run_recon(target, scope, depth)` → dispatches `ReconAgent`, returns `AttackSurface`
- `classify_findings(attack_surface)` → dispatches `ClassifierAgent`, returns `ClassifiedFindingSet`
- `build_attack_plan(findings, objective)` → dispatches `ExploitAgent`, returns `AttackPlan`
- `execute_attack_step(step_id, plan_id)` → dispatches `CommandExecutor`, returns `ExecutionResult`
- `adapt_plan(plan_id, last_result)` → dispatches `ExploitAgent.adapt_plan`, returns updated `AttackPlan`
- `generate_report(campaign_id)` → dispatches `ReportAgent`, returns report path
- `pause_campaign(reason)` → pauses execution, notifies user, waits for resume
- `complete_campaign(summary)` → marks campaign complete, triggers report generation

#### Campaign Planner (`orchestrator/planner.py`)
- Implement `CampaignPlanner`:
  - `decompose_objective(objective: str, target: str) -> list[Milestone]`
  - Milestones: `[recon_complete, surface_classified, attack_plan_ready, objective_reached, report_generated]`
  - Each milestone has success criteria and triggers next phase
- Implement strategic decision making: after each exploit step result, orchestrator decides:
  - Continue on current path?
  - Pivot to a different attack path?
  - Escalate privileges before continuing?
  - Declare objective reached?
  - Admit objective is unreachable and document why?

#### Campaign State Machine (`pipeline/campaign.py`)
- States: `CREATED → SCOPING → RECON → CLASSIFYING → PLANNING → EXECUTING → ADAPTING → REPORTING → COMPLETE | FAILED | ABORTED`
- Each transition logged to `CampaignEvent` append-only table
- Implement `EmergencyStop`: immediately transitions to `ABORTED`, triggers cleanup

#### Campaign API (`api/routers/campaigns.py`)
- `POST /api/v1/campaigns` — create campaign with target, objective, scope, authorization token
- `POST /api/v1/campaigns/{id}/start` — begin execution
- `POST /api/v1/campaigns/{id}/stop` — emergency stop
- `GET /api/v1/campaigns/{id}` — status, current state, progress
- `GET /api/v1/campaigns/{id}/stream` — SSE stream of real-time events (thoughts, actions, results)
- `GET /api/v1/campaigns/{id}/report` — download generated report

**Acceptance Criteria:**
- [ ] Orchestrator successfully runs a full campaign (recon → classify → plan → execute → report) against a test target (HackTheBox/TryHackMe style lab)
- [ ] ReAct loop correctly calls tools in response to observation results
- [ ] Emergency stop triggers cleanup and transitions to ABORTED within 5 seconds
- [ ] SSE stream delivers real-time orchestrator thoughts and actions to client
- [ ] Full campaign completes end-to-end in under 30 minutes on a simple target

**Dependencies:** Sprints 1–4

---

### Sprint 6 — Report Agent
**Duration:** 1 week
**Goal:** Build the Report Agent — Llama 3.1 8B powered professional report generation from campaign findings.

**Why this sprint matters:** The report is the deliverable. A brilliant pentest with a mediocre report is wasted work. Professional, structured output is what makes this usable for real engagements.

#### Report Data Model
- Define `PentestReport`: campaign_id, target, objective, executive_summary, scope_description, methodology, findings (list), attack_narrative, risk_summary, remediation_plan, appendices
- Define `Finding`: id, title, severity, cvss_score, description, evidence (list of `Evidence`), affected_components, remediation, references
- Define `Evidence`: type (screenshot/command_output/log_excerpt), content, timestamp, description

#### Report Agent (`agents/report/agent.py`)
- Implement `ReportAgent`:
  - `generate(campaign_id: str) -> PentestReport`
  - Fetches all campaign data: `CampaignEvent` log, `ExecutionResult` records, `ClassifiedFindingSet`, `AttackPlan`
  - Sends structured campaign data to fine-tuned Llama 3.1 8B in sections:
    - Generate executive summary (non-technical, business risk focused)
    - Generate finding writeup per confirmed vulnerability (technical, evidence-backed)
    - Generate attack narrative (tells the story of the pentest as a sequence of events)
    - Generate remediation plan (prioritized, specific, actionable)
  - Assembles sections into complete `PentestReport`

#### Report Renderer (`agents/report/renderer.py`)
- **Markdown:** clean, structured, GitHub-renderable
- **HTML:** self-contained HTML with embedded CSS, syntax highlighted code blocks, collapsible sections
- **PDF:** uses `weasyprint` to render HTML → PDF; professional layout with cover page, table of contents, page numbers
- **JSON:** machine-readable full report for integration with ticketing systems

#### Report Templates (`agents/report/templates/`)
- `executive_summary.md.j2`: Jinja2 template for executive summary section
- `finding.md.j2`: template for individual finding writeup
- `remediation.md.j2`: template for remediation recommendations
- Templates filled by Llama 3.1 output — model generates the content, template provides structure

**Acceptance Criteria:**
- [ ] Report agent generates a complete report from a test campaign dataset in <3 minutes
- [ ] PDF output is clean, professional, correctly paginated
- [ ] Each finding section contains: title, severity, CVSS score, description, evidence, remediation
- [ ] Executive summary is non-technical and business-risk focused
- [ ] JSON export is valid and contains all findings with structured data

**Dependencies:** Sprints 3, 4, 5

---

### Sprint 7 — CLI & Web UI
**Duration:** 2 weeks
**Goal:** A polished CLI for power users and a web UI for everyone else.

**Why this sprint matters:** The best backend in the world is useless if the interface is painful. Both interfaces need to feel professional and fast.

#### CLI (`cli/main.py`)
- Implement using `click` + `rich` (for beautiful terminal output):
  ```bash
  # Core commands
  autopentest campaign new --target example.com --objective "find RCE" --scope "192.168.1.0/24"
  autopentest campaign start <campaign-id>
  autopentest campaign watch <campaign-id>   # live stream of orchestrator thoughts + actions
  autopentest campaign stop <campaign-id>
  autopentest campaign report <campaign-id> --format pdf --output ./report.pdf

  # Config
  autopentest config init          # interactive setup wizard
  autopentest config set provider claude
  autopentest config set api-key sk-ant-...

  # Models
  autopentest models pull          # pulls all 4 specialist models via Ollama
  autopentest models status        # shows model availability + version

  # Tools check
  autopentest doctor               # checks all required tools are installed
  ```
- Implement `autopentest campaign watch`: streams SSE events from API, renders in terminal with `rich.live` — shows current phase, orchestrator reasoning (in dim text), tool executions, findings as they're discovered
- Implement `autopentest doctor`: checks nmap, subfinder, httpx, ffuf, whatweb, nuclei, amass are installed and in PATH; checks Ollama is running; checks all 4 models are pulled; checks API keys if claude provider configured

#### Web UI (`web/`)
- Initialize React 18 + TypeScript + Vite
- Component library: `shadcn/ui` + Tailwind CSS
- State management: `TanStack Query` for server state, `Zustand` for UI state

**Key pages:**

- **Dashboard (`/`):** active campaigns list with live status, recent findings, quick-start button

- **New Campaign (`/campaigns/new`):**
  - Target input (domain or IP)
  - Objective input (free text, with suggestions: "find RCE", "enumerate all vulnerabilities", "test authentication")
  - Scope definition: IP range CIDR inputs, domain allowlist
  - Provider selection: Claude (requires API key) or Local LLM (requires Ollama endpoint + model)
  - Authorization: operator name + sign authorization token

- **Live Campaign (`/campaigns/:id`):**
  - Phase progress bar: Recon → Classify → Plan → Execute → Report
  - **Orchestrator thoughts panel:** live stream of the orchestrator's reasoning (what it's thinking, what it's deciding) — this is the most engaging UI element
  - **Findings feed:** findings appear in real-time as discovered, color-coded by severity
  - **Tool execution log:** live command output as tools run
  - **Attack surface map:** force-directed graph of discovered hosts/subdomains/relationships, updates in real-time
  - Emergency stop button (prominent, red)

- **Report Viewer (`/campaigns/:id/report`):**
  - Rendered HTML report in-browser
  - Sidebar: finding index, jump to section
  - Export buttons: PDF, HTML, JSON, Markdown

- **Settings (`/settings`):**
  - Provider configuration: Claude API key, or Ollama/LM Studio endpoint
  - Model management: pull/update specialist models
  - Default scope templates

**Acceptance Criteria:**
- [ ] `autopentest doctor` correctly identifies missing tools and missing models
- [ ] `autopentest campaign watch` renders live campaign activity in terminal
- [ ] Web UI new campaign flow creates and starts a campaign end-to-end
- [ ] Orchestrator thoughts stream correctly in the live campaign view
- [ ] Report downloads as valid PDF from the report viewer

**Dependencies:** Sprints 5, 6

---

### Sprint 8 — Synthetic Training Data Generation
**Duration:** 2 weeks
**Goal:** Generate high-quality synthetic training datasets for all four specialist models using Claude as the data generation engine.

**Why this sprint matters:** The fine-tuned models are the moat. The quality of fine-tuning is entirely determined by the quality of training data. This sprint builds the data pipelines that make the moat defensible.

#### Data Generation Framework (`data/generator.py`)
- Implement `SyntheticDataGenerator` using Claude API:
  - Generates instruction-response pairs at scale
  - Validates each generated sample against a schema before saving
  - Deduplicates using embedding similarity (reject samples too similar to existing ones)
  - Saves in Alpaca format (instruction, input, output) and ShareGPT format (conversations)

#### Recon Agent Training Data (`data/recon/`)
- **Dataset goal:** 50,000 instruction-response pairs
- **Format:** input = raw tool output(s), output = structured `AttackSurface` JSON
- **Generation strategy:**
  - Generate realistic nmap XML outputs for 10,000 synthetic host profiles (varying OS, services, versions)
  - Generate matching subfinder outputs (subdomain lists with varying patterns)
  - Generate httpx outputs for each discovered web service
  - Prompt Claude: "Given this raw tool output, extract a structured attack surface model. Identify the most interesting findings. Correlate findings across tools."
  - Validate output parses against `AttackSurface` Pydantic model
- **Data variety:** corporate networks, cloud-heavy environments, legacy infrastructure, web application focused, mixed environments

#### Classifier Agent Training Data (`data/classifier/`)
- **Dataset goal:** 30,000 instruction-response pairs
- **Format:** input = finding description + context, output = `ClassifiedFinding` JSON (CVE IDs, CVSS, severity, attack category, false_positive_probability)
- **Generation strategy:**
  - Source real CVE descriptions from NVD (public data)
  - Generate synthetic finding descriptions for each CVE with varying levels of detail
  - Generate false positive examples: generic findings that look interesting but aren't
  - Prompt Claude: "Classify this security finding. Map to CVE if applicable. Assign CVSS score. Is this a false positive? What attack category?"

#### Exploit Agent Training Data (`data/exploit/`)
- **Dataset goal:** 40,000 instruction-response pairs (most complex — needs the most data)
- **Format:** input = `ClassifiedFindingSet` + objective, output = `AttackPlan` JSON with chain-of-thought reasoning
- **Generation strategy:**
  - Synthesize from public CTF writeups: parse HackTheBox, TryHackMe, VulnHub writeups into finding → attack chain → result structures (use Claude to parse and structure)
  - Synthesize from public pentest reports (HackerOne disclosed reports, Synack public reports)
  - Generate novel scenarios: create synthetic target profiles with 3-8 findings, prompt Claude to construct attack chains with full reasoning
  - **Include `<think>` traces**: for DeepSeek R1 fine-tuning, include chain-of-thought reasoning before each answer
- **Data variety:** web application attacks, network pivoting, privilege escalation chains, cloud misconfigurations, combination attacks

#### Report Agent Training Data (`data/report/`)
- **Dataset goal:** 20,000 instruction-response pairs
- **Format:** input = campaign findings + evidence summary, output = professional report section
- **Generation strategy:**
  - Source public pentest report templates and examples
  - Generate synthetic finding → executive_summary pairs
  - Generate synthetic finding → technical_writeup pairs
  - Generate synthetic campaign_data → full_report pairs
  - Ensure variety in: tone (corporate vs startup), severity level, finding types, remediation approaches

#### Data Quality Pipeline
- Implement automated quality scoring: each generated sample scored 1-5 on accuracy, completeness, format correctness
- Filter: only samples scoring ≥4 go into training set
- Implement diversity metrics: ensure training set covers all target types, severity levels, attack categories
- Output statistics: samples per category, average quality score, coverage analysis

**Acceptance Criteria:**
- [ ] Data generator produces valid Alpaca-format JSONL for all four datasets
- [ ] Recon dataset contains ≥50k samples with valid `AttackSurface` JSON outputs
- [ ] Exploit dataset contains ≥40k samples with chain-of-thought reasoning traces
- [ ] Quality filter correctly rejects malformed or low-quality samples
- [ ] Dataset diversity report shows coverage across all intended categories

**Dependencies:** Sprint 0 (Claude API access)

---

### Sprint 9 — Model Fine-Tuning
**Duration:** 2 weeks
**Goal:** Fine-tune all four specialist models on their respective datasets and publish to HuggingFace Hub.

**Why this sprint matters:** This sprint creates the proprietary models that differentiate the platform from any fork or competitor.

#### Fine-Tuning Infrastructure (`training/`)
- Use **Unsloth** for efficient fine-tuning: 2x faster than standard HuggingFace training, 70% less VRAM, supports Qwen/Mistral/Llama/DeepSeek
- Use **QLoRA** (4-bit quantization + LoRA adapters): fine-tune on consumer hardware (24GB VRAM GPU sufficient)
- Training infrastructure: scripts runnable on single A100 (Modal/RunPod/Lambda Labs) or locally with RTX 4090

#### Recon Model Fine-Tuning (`training/train_recon.py`)
- Base model: `Qwen/Qwen2.5-7B-Instruct`
- Dataset: `data/recon/train.jsonl` (50k samples)
- LoRA config: `r=64`, `lora_alpha=16`, target modules: `q_proj, v_proj, k_proj, o_proj, gate_proj, up_proj, down_proj`
- Training: 3 epochs, batch size 4, gradient accumulation 8, cosine LR schedule
- Evaluation: held-out 5k sample test set; measure `AttackSurface` JSON validity rate, field accuracy
- Target: >95% valid JSON output, >90% field extraction accuracy vs Claude-generated ground truth
- Publish: `ArmurAI/recon-agent-qwen2.5-7b` on HuggingFace Hub

#### Classifier Model Fine-Tuning (`training/train_classifier.py`)
- Base model: `mistralai/Mistral-7B-Instruct-v0.3`
- Dataset: `data/classifier/train.jsonl` (30k samples)
- Same LoRA config, 2 epochs
- Evaluation: CVE mapping accuracy, CVSS score mean absolute error, false positive recall
- Target: >85% CVE mapping accuracy, CVSS MAE <0.5, >90% false positive recall
- Publish: `ArmurAI/classifier-agent-mistral-7b`

#### Exploit Model Fine-Tuning (`training/train_exploit.py`)
- Base model: `deepseek-ai/DeepSeek-R1-Distill-Llama-8B` (R1 reasoning in an 8B model)
- Dataset: `data/exploit/train.jsonl` (40k samples, includes `<think>` traces)
- LoRA config: `r=128` (higher rank for complex reasoning task), 3 epochs
- Evaluation: attack plan validity rate, step sequence coherence, technique-finding alignment
- Target: >85% valid `AttackPlan` JSON, expert evaluation score >4/5 on 200 sampled outputs
- Publish: `ArmurAI/exploit-agent-deepseek-r1-8b`

#### Report Model Fine-Tuning (`training/train_report.py`)
- Base model: `meta-llama/Llama-3.1-8B-Instruct`
- Dataset: `data/report/train.jsonl` (20k samples)
- 2 epochs, focus on instruction following and format consistency
- Evaluation: BLEU/ROUGE vs reference reports, human evaluation on 100 sampled reports
- Target: ROUGE-L >0.6, human evaluation >4/5 on professionalism + completeness
- Publish: `ArmurAI/report-agent-llama3.1-8b`

#### Model Registry (`models/registry.py`)
- Implement `ModelRegistry`: tracks available models, versions, download status
- Implement `models pull`: downloads all 4 fine-tuned models from HuggingFace Hub to local Ollama
- Implement version pinning: `config.yaml` specifies exact model version for reproducibility
- Implement model health check: verify model responds correctly to a test prompt before campaign start

**Acceptance Criteria:**
- [ ] All four models fine-tuned and uploaded to HuggingFace Hub
- [ ] Recon model achieves >95% valid JSON output on test set
- [ ] Exploit model produces coherent multi-step attack plans on 10 manually evaluated scenarios
- [ ] `autopentest models pull` successfully downloads and registers all four models
- [ ] Models run correctly via Ollama on a Mac with 16GB RAM

**Dependencies:** Sprint 8

---

### Sprint 10 — Integration, Testing & Launch Prep
**Duration:** 2 weeks
**Goal:** End-to-end testing, documentation, Docker packaging, and everything needed for a compelling public launch.

**Why this sprint matters:** 200 stars without promotion means there's an audience waiting. The launch needs to be polished enough that those 200 become 2,000 in the first week.

#### Integration Testing
- Set up test lab environment: intentionally vulnerable VMs (Metasploitable 3, DVWA, VulnHub machines) in isolated Docker network
- Write end-to-end test suite: `tests/e2e/` — runs full campaign against test lab, validates:
  - At least 3 findings discovered on Metasploitable 3
  - Attack plan constructed from findings
  - At least 1 successful exploitation step
  - Report generated with correct structure
- Write agent unit tests: mock LLM responses, verify each agent correctly processes inputs and produces valid outputs
- Write scope enforcement tests: verify out-of-scope attacks are blocked at every layer

#### Performance Optimization
- Profile campaign execution: identify bottlenecks in tool execution and agent response times
- Implement parallel recon: run subfinder, nmap, httpx concurrently where safe
- Implement result streaming: recon findings stream to orchestrator as each tool completes (don't wait for all tools to finish)
- Target: full recon + classify + plan in <10 minutes for a medium-complexity target

#### Docker Packaging
- Write `docker/Dockerfile.controller`: multi-stage build, Python app + all CLI tools (nmap, subfinder, httpx, etc.) pre-installed
- Write `docker-compose.yml`: controller + Ollama (with GPU passthrough config) + PostgreSQL + Redis
- Write `docker-compose.cpu.yml`: CPU-only variant (slower but runs on any machine)
- Test on: macOS (Apple Silicon), Ubuntu 22.04, Windows 11 (WSL2)
- Target image size: <2GB controller image (tools add bulk, optimize with multi-stage)

#### Documentation
- Rewrite `README.md`: architecture diagram, quick start (5 commands to first campaign), feature list, model descriptions, FAQ
- Write `docs/quickstart.md`: step-by-step from zero to first campaign in 15 minutes
- Write `docs/architecture.md`: deep dive on agent architecture, data flow, model choices
- Write `docs/fine-tuning.md`: how to reproduce fine-tuning, dataset format, how to contribute training data
- Write `docs/configuration.md`: every config option explained
- Write `docs/providers.md`: how to set up Claude, Ollama, LM Studio
- Write `CONTRIBUTING.md`: how to add new recon tools, how to contribute training data, how to improve agent prompts

#### Launch Assets
- Create architecture diagram (Mermaid + rendered PNG) for README
- Record demo GIF: `autopentest campaign watch` running against a test target — shows orchestrator reasoning in real-time
- Write HackerNews/Reddit launch post draft
- Tag `v1.0.0` release with compiled binaries for macOS/Linux via GitHub Actions + GoReleaser

**Acceptance Criteria:**
- [ ] End-to-end test against Metasploitable 3 finds at least 3 real vulnerabilities and generates a valid report
- [ ] `docker compose up` produces a working platform with no manual configuration steps
- [ ] Full campaign on a simple target completes in <15 minutes
- [ ] README clearly explains the 5-agent architecture and how to run first campaign
- [ ] GitHub Actions CI pipeline runs full test suite on PR

**Dependencies:** Sprints 0–9

---

## Fine-Tuning Data Strategy Summary

| Model | Base | Training Samples | Key Data Sources | Target Metric |
|---|---|---|---|---|
| Recon Agent | Qwen 2.5 7B | 50,000 | Synthetic tool outputs, real scan patterns | >95% valid JSON |
| Classifier | Mistral 7B | 30,000 | NVD CVE data, synthetic findings | >85% CVE accuracy |
| Exploit Agent | DeepSeek R1 8B | 40,000 | CTF writeups, HackerOne reports, synthetic chains | >85% valid plan JSON |
| Report Agent | Llama 3.1 8B | 20,000 | Public pentest reports, synthetic findings | ROUGE-L >0.6 |

---

## Technology Stack

| Component | Technology |
|---|---|
| Orchestrator | Python 3.12 asyncio |
| LLM (Claude) | `anthropic` Python SDK |
| LLM (Local) | Ollama API / LM Studio OpenAI-compatible API |
| Recon Agent LLM | Qwen 2.5 7B (fine-tuned, via Ollama) |
| Classifier Agent LLM | Mistral 7B (fine-tuned, via Ollama) |
| Exploit Agent LLM | DeepSeek R1 8B (fine-tuned, via Ollama) |
| Report Agent LLM | Llama 3.1 8B (fine-tuned, via Ollama) |
| Fine-Tuning | Unsloth + QLoRA |
| API | FastAPI |
| Database | PostgreSQL 16 |
| Task Queue | Redis + asyncio |
| CLI | Click + Rich |
| Web UI | React 18 + TypeScript + shadcn/ui |
| Recon Tools | nmap, subfinder, httpx, ffuf, whatweb, nuclei, gau, amass |
| Deployment | Docker + docker-compose |
| Model Hosting | HuggingFace Hub (`ArmurAI` org) |
| CI/CD | GitHub Actions |

---

## Success Metrics

- **GitHub stars:** 2,000+ in first month post-relaunch (vs 200 organic baseline)
- **End-to-end campaign time:** <15 minutes on a simple target
- **Finding accuracy:** >80% of discovered findings confirmed as real vulnerabilities
- **Report quality:** rated >4/5 by security professionals in user testing
- **Model performance:** all four fine-tuned models outperform their base models on domain-specific benchmarks
- **Community:** contributions of new recon tool integrations, training data, playbooks within 30 days of launch

---

## What Makes This Defensible

1. **Four proprietary fine-tuned models** — the data flywheel improves them with every release
2. **Multi-agent architecture** — each model is narrow and deep, not a general model trying to do everything
3. **The right base model per task** — Qwen for parsing, DeepSeek R1 for reasoning, Llama for writing, Mistral for classification
4. **Full privacy option** — runs 100% locally, no data leaves the machine
5. **Orchestrator flexibility** — Claude for best results, local LLM for air-gapped/private deployments
6. **End-to-end** — recon through reporting in one platform, not a collection of disconnected tools
