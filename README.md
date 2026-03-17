# autopentest

**Autonomous AI-Powered Penetration Testing**

A multi-agent AI system built in Go that autonomously performs full-cycle penetration tests — from reconnaissance through exploitation to professional reporting — powered by specialist AI agents coordinated by an orchestrator.

<!-- badges -->
![GitHub Stars](https://img.shields.io/github/stars/Armur-Ai/autopentest?style=flat-square)
![License](https://img.shields.io/badge/license-Apache%202.0-blue?style=flat-square)
![Go](https://img.shields.io/badge/Go-1.24-00ADD8?style=flat-square&logo=go)

---

## Quick Start

```bash
# Install
brew install armur-ai/tap/autopentest     # macOS
# or
curl -sSL https://install.autopentest.ai | sh  # Linux
# or
docker compose -f deploy/docker-compose.yml up  # Docker

# Configure (just needs a Claude API key)
export AUTOPENTEST_ORCHESTRATOR_API_KEY=sk-ant-your-key-here

# Scan
autopentest scan example.com --scope example.com
```

That's it. All agents use your Claude API key. No Ollama, no model downloads, no GPU needed.

---

## How It Works

```
You: autopentest scan target.com --scope target.com

Orchestrator (Claude) plans the campaign
    |
    +---> Recon Agent runs subfinder, httpx, nuclei, naabu, katana, dnsx, gau
    |         --> builds structured AttackSurface
    |
    +---> Classifier Agent maps CVEs, scores CVSS, filters false positives
    |         --> produces ranked ClassifiedFindingSet
    |
    +---> Exploit Agent constructs multi-step attack chains
    |         --> executes with scope validation + cleanup registration
    |
    +---> Report Agent generates professional PDF/HTML/Markdown report

You: open report.pdf
```

## Architecture

```
                        Go CLI (Cobra)
                            |
                    Go Backend (single binary)
                            |
            +-------+-------+-------+-------+
            |       |       |       |       |
          Recon  Classify Exploit Report  Orchestrator
          Agent   Agent   Agent   Agent    (ReAct loop)
            |
    subfinder · httpx · nuclei · naabu · katana · dnsx · gau
            |
    PostgreSQL + pgvector · Redis · Docker API
```

## Features

**Core**
- 5-agent architecture: Orchestrator + Recon + Classifier + Exploit + Report
- 7 native Go security tool wrappers (no subprocess overhead)
- CVSS v3.1 scoring engine per FIRST specification
- Scope enforcement on every command (hard-coded, no exceptions)
- Campaign state machine with emergency stop

**Modes**
- Manual pentesting with full control
- Bug bounty mode (HackerOne/Bugcrowd scope import, dedup, formatted reports)
- Continuous ASM (watch scope, auto-trigger on new assets)
- CTF mode (autonomous HackTheBox/TryHackMe solving)

**Integrations**
- MCP Server for Claude Desktop and Cursor (`autopentest mcp serve`)
- VS Code / Cursor extension with inline findings
- GitHub Action for CI/CD security scanning (SARIF output)
- Jira, Slack, SIEM (CEF/STIX/SARIF), webhooks with HMAC signing

**Ecosystem**
- Community attack playbooks (YAML, like nuclei-templates)
- Agent memory that gets smarter with every scan
- Shared intelligence network (opt-in, anonymized)
- Plugin system for custom tools and report templates

**Distribution**
- Single Go binary: `brew install`, `docker compose up`, `go install`
- Next.js 15 web dashboard with dark theme (embedded in binary)
- Beautiful terminal TUI with multi-panel agent activity view
- npm, Docker Hub, Snap Store, Winget — public download metrics everywhere

## CLI Commands

```
autopentest scan <target> --scope <scope>    # Start a pentest
autopentest campaign watch <id>               # Live TUI dashboard
autopentest campaign explore <id>             # Browse attack surface
autopentest explain <finding-id>              # Explain in plain English
autopentest doctor                            # Health check
autopentest serve                             # Start API + dashboard
autopentest mcp serve                         # MCP server for Claude/Cursor
autopentest ctf solve <target>                # Autonomous CTF solving
autopentest playbook run <name>               # Run community playbook
```

## LLM Providers

| Provider | Setup | Privacy | Cost |
|----------|-------|---------|------|
| **Claude** (default) | Just set API key | Cloud | Pay per token |
| **Ollama** | Install + pull models | 100% local | Free (your GPU) |
| **LM Studio** | Load model + enable server | 100% local | Free (your GPU) |

All agents inherit the orchestrator's provider. Set one API key, everything works.

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Platform | Go 1.24 (single binary) |
| CLI | Cobra + bubbletea TUI |
| LLM | Claude API, Ollama, LM Studio |
| Security tools | subfinder, httpx, nuclei, naabu, katana, dnsx, gau (native Go) |
| API | Fiber (fasthttp) |
| Database | PostgreSQL 16 + pgvector |
| Cache | Redis 7 |
| Dashboard | Next.js 15 + shadcn/ui + tremor |
| MCP | JSON-RPC over stdio |

## Development

```bash
git clone https://github.com/Armur-Ai/autopentest.git
cd autopentest
./scripts/setup.sh   # Install tools, start services
make build           # Compile binary
make test            # Run tests
make dev             # Start with hot-reload
```

## License

Apache 2.0 — see [LICENSE](LICENSE).

Built by [Armur AI](https://github.com/Armur-Ai).
