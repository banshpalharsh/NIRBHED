<div align="center">

# 🗡️ NIRBHED

**An autonomous, token-frugal offensive-security AI agent — and an MCP server.**

[![Python](https://img.shields.io/badge/python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![MCP](https://img.shields.io/badge/MCP-Claude%20Desktop-8A2BE2)](docs/mcp-setup.md)
[![LLM](https://img.shields.io/badge/LLM-DeepSeek%20%7C%20Claude%20%7C%20OpenAI%20%7C%20Ollama-0b7285)](docs/token-optimization.md)
[![Status](https://img.shields.io/badge/status-alpha-orange)]()

> **nirbheda** (निर्भेद) — Sanskrit for *piercing / penetration*. The tool pierces an attack surface, proves what it finds, and keeps the receipts.

Point it at a target. It runs real security tools, reasons like a pentester, proves what it finds, and writes an evidence-bound report. Drive it with **Claude Desktop (no API key)** or run it **headless with any cheap LLM key** (DeepSeek, Claude, OpenAI, OpenRouter, Ollama…).

`recon → active testing → exploitation → proof → report` — on a hard token/time/cost budget.

</div>

---

## Contents
- [Why Nirbhed exists](#why-nirbhed-exists)
- [Install](#install) · [**Getting Started guide →**](docs/getting-started.md) · [Android/Termux →](docs/android-termux.md)
- [Two ways to run — one engine](#two-ways-to-run--one-engine)
- [Token frugality — how it actually saves money](#token-frugality--how-it-actually-saves-money)
- [What it does (capability map)](#what-it-does-capability-map)
- [CLI](#cli)
- [Install the security tools](#install-the-security-tools)
- [Safety & legal](#safety--legal)
- [Architecture](#architecture)

---

## Why Nirbhed exists

Autonomous-pentest tools are powerful but *expensive to run* — they shovel raw scanner output into an LLM and burn tokens. Nirbhed treats **token frugality as a first-class subsystem** so long, deep runs stay cheap, while refusing to compromise on result quality.

It unifies the ideas behind three excellent projects into one coherent engine:

| Idea | Source inspiration | In Nirbhed |
|------|--------------------|-----------|
| Plug a full toolbelt into an MCP client (no API key — the client is the brain) | HexStrike-AI | `nirbhed mcp` |
| Autonomous "acts like a hacker" loop that validates findings with PoCs | Strix | `nirbhed run` |
| Planner/worker loop, evidence binding ("keeps its receipts"), retest, budgets, scope gates | ARTEX | core engine |

> Nirbhed is an independent, clean-room implementation in Python (MIT). It is *inspired by* those projects, not a fork of them.

---

## Install

Nirbhed isn't on PyPI yet — install it straight from GitHub. **New here? Follow the step-by-step [Getting Started guide](docs/getting-started.md)** (Kali/Linux, API key placement, MCP — zero assumed knowledge).

```bash
# both run modes (recommended)
pipx install "nirbhed[all] @ git+https://github.com/banshpalharsh/NIRBHED.git"

# or just one mode:
pipx install "nirbhed[agent] @ git+https://github.com/banshpalharsh/NIRBHED.git"   # standalone (API key)
pipx install "nirbhed[mcp]   @ git+https://github.com/banshpalharsh/NIRBHED.git"   # MCP server

# no pipx? clone and use pip (add --break-system-packages on Kali/Debian)
git clone https://github.com/banshpalharsh/NIRBHED.git && cd NIRBHED
pip install -e ".[all]"
```

**Android?** Agent mode runs on a phone via Termux — one-command setup and an
A-to-Z guide in [docs/android-termux.md](docs/android-termux.md).

Verify: `nirbhed doctor`.

---

## Two ways to run — one engine

### 1) MCP mode — Claude Desktop, **no API key**

Claude Desktop is the reasoning brain; Nirbhed exposes its entire toolbelt + finding/evidence/report machinery over MCP (stdio). Nothing to pay for beyond your Claude subscription.

> Claude Desktop runs on **Windows/macOS** (there is no official Linux build). On Linux, use any MCP-capable client, or just use agent mode below. Full setup: [docs/mcp-setup.md](docs/mcp-setup.md).

Add to **Claude Desktop → Settings → Developer → Edit Config** (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "nirbhed": {
      "command": "nirbhed",
      "args": ["mcp"],
      "env": { "NIRBHED_SCOPE": "example.com,*.example.com", "NIRBHED_APPROVAL": "balanced" }
    }
  }
}
```

Restart Claude Desktop and ask it to *"recon example.com with nirbhed, then record findings and write a report."* Every installed tool shows up as a callable MCP tool, plus `nirbhed_catalog`, `nirbhed_record_finding`, and `nirbhed_report`.

### 2) Agent mode — headless, **bring a cheap API key**

Any OpenAI-compatible endpoint works. Point `base_url` + `model` at whatever is cheapest for you.

```bash
# put your key somewhere nirbhed looks: ./.env, ~/.config/nirbhed/.env, or ~/.nirbhed.env
mkdir -p ~/.config/nirbhed && cp .env.example ~/.config/nirbhed/.env
# edit that file: NIRBHED_API_KEY / NIRBHED_BASE_URL / NIRBHED_MODEL
# (or just: export NIRBHED_API_KEY=sk-... before running)

nirbhed run https://example.com
```

```env
# DeepSeek (very cheap, default)
NIRBHED_API_KEY=sk-...
NIRBHED_BASE_URL=https://api.deepseek.com
NIRBHED_MODEL=deepseek-chat

# ...or Claude, OpenAI, OpenRouter, Groq, local Ollama — same three vars.
# Optional automatic failover to a second provider:
NIRBHED_FALLBACK_API_KEY=...
NIRBHED_FALLBACK_BASE_URL=https://api.anthropic.com/v1
NIRBHED_FALLBACK_MODEL=claude-haiku-4-5
```

---

## Token frugality — how it actually saves money

This is the part worth reading. Four mechanisms, all on by default:

1. **Two-tier output distillation** (`core/distill.py`) — raw tool output (banners, progress bars, ANSI, log-level lines, thousands of repeated scan lines) is stripped, then ranked: concrete findings (CVEs, severities, open ports, URLs, HTTP statuses, IPs) are kept *ahead of* generic chatter, so a real finding can never be crowded out of the character budget. Hard-capped per observation.
2. **Content-addressed caching** (`core/cache.py`) — identical tool+args ⇒ the distilled result is replayed from disk. **Zero tokens, zero re-execution.** (Evidence is re-bound on replay so report receipts stay valid.)
3. **Near-stateless turns** (`agent/loop.py`) — instead of resending an ever-growing transcript, each turn sends the system prompt + a *compact running state* (asset graph + findings brief + recent actions + last result). Per-turn cost stays roughly flat instead of growing O(n).
4. **Hard budgets** (`core/budget.py`) — token / turn / wall-clock caps stop a run cleanly before it can run away with your spend.

Plus **finding dedup** (`core/findings.py`): the agent never re-sees or re-reports a vuln it already has, and **parallel fan-out** (`registry.run_many`) runs independent recon/scan tools concurrently.

### Measured (run `python scripts/benchmark.py` yourself)
On a synthetic 4,000-line scan and 0.4s tools, on commodity hardware:

| Mechanism | Result |
|-----------|--------|
| Distillation | **99.6%** fewer chars (~58,700 → ~210 est. tokens) — CVE + open-port lines retained |
| Cache replay | **~1700×** faster than re-running (405 ms → 0.2 ms) |
| Parallel fan-out (5 tools) | **~4.9×** faster (2.0 s → 0.4 s) |

Numbers are produced by the live code, not hard-coded — reproduce them with the benchmark script.

---

## What it does (capability map)

- **Live web dashboard**: a localhost URL shows status, phase, budget, the asset graph, and findings in real time — no more flying blind.
- **Human-in-the-loop**: chat to the agent mid-engagement to steer it ("focus on /api, skip bruteforce"), and **Pause / Resume / Stop** at any time.
- **Authenticated testing**: inject cookies, bearer/JWT tokens, basic creds, or custom headers via CLI, env, or the dashboard — applied automatically to `http_request` and exposed to PoCs. Secrets are **never put in the LLM context**.
- **Autonomous loop**: reason → tool(s) → distilled observation → chain. Recon-first, then active, then exploitation, with a stall detector that stops runaway/looping agents.
- **Parallel execution**: independent recon/scan tools run concurrently in one `parallel` action.
- **Proof before report + false-positive guard**: high/critical findings are *refused* unless backed by evidence ids; the agent must prove them with `http_request` / `python_exploit` first.
- **Evidence binding**: every tool run is a timestamped, hashed `Evidence` record; findings cite evidence ids; reports show the receipts.
- **Dual graphs**: a shared asset graph (root → subdomain → service → endpoint) + a coverage ledger of tested vs untested surface.
- **Retest status**: findings carry `reproducible / fixed / cannot_confirm`.
- **Scope + approval gates**: host-glob scope/deny lists; `quiet | balanced | aggressive` noise-governor profiles decide which tool tiers auto-run vs need approval. Exploit/destructive tiers are always gated by default.
- **Reports**: evidence-bound Markdown + JSON, CVSS + OWASP + CWE tagged.
- **Declarative toolbelt**: 60+ wrappers across network, web, auth, binary/RE, cloud/container, forensics, OSINT — defined as *data*, so adding a tool is a YAML block, not code. Covers Nmap, Rustscan, Masscan, NetExec, Subfinder, Amass, httpx, katana, gau, Nuclei, ffuf, feroxbuster, gobuster, SQLMap, Dalfox, WPScan, Nikto, Hydra, John, Hashcat, Trivy, Prowler, Scout Suite, kube-hunter, Radare2, binwalk, ExifTool, and more.

---

## CLI

```bash
nirbhed mcp                      # start MCP server (Claude Desktop; no API key)
nirbhed run <target>             # autonomous agent pentest + live dashboard (needs API key)
nirbhed run <target> --cookie "session=..." --bearer <jwt> -H "X-API-Key: k"   # authenticated
nirbhed view                     # reopen the dashboard for the most recent run
nirbhed exec nmap_quick <host>   # run ONE tool directly — no LLM, zero tokens
nirbhed tools --all              # list the catalog + what's installed
nirbhed doctor                   # config, provider status, tool availability
```

`nirbhed run` opens a dashboard at `http://127.0.0.1:8787` — watch findings live, **chat to steer the agent**, pause/stop, and inject credentials. `nirbhed exec` needs no LLM at all: distillation + caching + scope gating for any wrapped tool.

---

## Install the security tools

Nirbhed *orchestrates* external binaries; install the ones you need (it autodetects what's present — `nirbhed tools --all` shows gaps). On Kali most are a `sudo apt install` or `go install` away; httpx/nuclei/katana/subfinder/ffuf come from ProjectDiscovery.

---

## Safety & legal

Only test systems you are authorized to test. Scope globs and approval gates exist to keep you on-target and are **on by default** — exploit and destructive tools require explicit approval (`--yes`, the `aggressive` profile, or per-call `approve` in MCP). Tool output is always treated as untrusted data, never as instructions.

---

## Architecture

```
            ┌──────────────── front-ends ────────────────┐
            │   MCP server (Claude Desktop, no key)       │
            │   Standalone agent (OpenAI-compatible key)  │
            └───────────────────┬─────────────────────────┘
                                │  one shared engine
   ┌────────────────────────────┼────────────────────────────┐
   │ Registry (declarative catalog + binary autodetect)       │
   │ run(): scope-gate → cache → execute(argv, no shell)      │
   │        → distill → evidence                              │
   ├──────────────────────────────────────────────────────────┤
   │ core:  distill · cache · budget · scope · evidence        │
   │        findings(dedup/CVSS/OWASP) · graph · report        │
   └──────────────────────────────────────────────────────────┘
```

See [`docs/architecture.md`](docs/architecture.md) and [`docs/token-optimization.md`](docs/token-optimization.md).

## License

MIT.
