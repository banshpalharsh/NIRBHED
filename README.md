<div align="center">

# 🗡️ NIRBHED

**An autonomous, token-frugal offensive-security AI agent — and an MCP server.**

> **nirbheda** (निर्भेद) — Sanskrit for *piercing / penetration*. The tool pierces an attack surface, proves what it finds, and keeps the receipts.

Point it at a target. It runs real security tools, reasons like a pentester, proves what it finds, and writes an evidence-bound report. Drive it with **Claude Desktop (no API key)** or run it **headless with any cheap LLM key** (DeepSeek, Claude, OpenAI, OpenRouter, Ollama…).

`recon → active testing → exploitation → proof → report` — on a hard token/time/cost budget.

</div>

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

## Two ways to run — one engine

### 1) MCP mode — Claude Desktop, **no API key**

Claude Desktop is the reasoning brain; Nirbhed exposes its entire toolbelt + finding/evidence/report machinery over MCP (stdio). Nothing to pay for beyond your Claude subscription.

```bash
pipx install "nirbhed[mcp]"     # or: pip install "nirbhed[mcp]"
```

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
pipx install "nirbhed[agent]"
cp .env.example .env     # set NIRBHED_API_KEY / NIRBHED_BASE_URL / NIRBHED_MODEL

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

1. **Output distillation** (`core/distill.py`) — raw tool output (banners, progress bars, ANSI, thousands of repeated scan lines) is stripped to high-signal lines using per-tool salience regexes, then hard-capped. The LLM sees ports/URLs/CVEs/statuses, not noise.
2. **Content-addressed caching** (`core/cache.py`) — identical tool+args ⇒ the distilled result is replayed from disk. **Zero tokens, zero re-execution.**
3. **Near-stateless turns** (`agent/loop.py`) — instead of resending an ever-growing transcript, each turn sends the system prompt + a *compact running state* (asset graph + findings brief + recent actions + last result). Per-turn cost stays roughly flat instead of growing O(n).
4. **Hard budgets** (`core/budget.py`) — token / turn / wall-clock caps stop a run cleanly before it can run away with your spend.

Plus **finding dedup** (`core/findings.py`): the agent never re-sees or re-reports a vuln it already has, so the context window stays small.

---

## What it does (capability map)

- **Autonomous loop**: reason → one tool → distilled observation → chain. Recon-first, then active, then exploitation.
- **Proof before report**: crafts HTTP requests (`http_request`) and runs Python PoCs (`python_exploit`) to validate before recording a finding.
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
nirbhed run <target>             # autonomous agent pentest (needs API key)
nirbhed exec nmap_quick <host>   # run ONE tool directly — no LLM, zero tokens
nirbhed tools --all              # list the catalog + what's installed
nirbhed doctor                   # config, provider status, tool availability
```

`nirbhed exec` is handy on its own: distillation + caching + scope gating for any wrapped tool, with no LLM in the loop at all.

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
