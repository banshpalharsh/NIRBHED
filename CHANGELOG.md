# Changelog

## 0.2.0 — 2026-11-25

### Fixed (correctness)
- **Result cache never wrote.** `Registry.run` looked up the cache but never
  stored results, so every call was a miss and the "zero-token replay" was not
  actually happening. Now writes on completion (skipping timeouts/launch
  failures) and **re-binds a fresh evidence record on replay** so report
  receipts stay valid across sessions.
- **Distiller could drop real findings.** Generic salience terms matched inside
  words (e.g. `match` inside `no-match`), flooding the salient set so CVE/open-port
  lines were pushed past the character cap. Rewrote distillation as **two tiers**
  — concrete findings (CVE, severity, ports, URLs, statuses, IPs) are kept ahead
  of generic chatter — and added log-level noise filtering. Measured reduction on
  a 4,000-line scan improved to 99.6% *with findings retained*.

### Added (capability / performance)
- **Parallel tool execution** — `Registry.run_many()` and a `parallel` agent
  action run independent recon/scan tools concurrently (~4.9× on a 5-tool
  fan-out, measured).
- **False-positive guard** — the agent refuses to record high/critical findings
  without evidence ids; it must prove them first (or downgrade to suspected).
- **Stall detector** — stops runaway/looping agents after repeated invalid or
  empty turns instead of burning the budget.
- **Robust JSON extraction** — balanced-brace parsing + fenced-block + trailing
  comma tolerance, so weaker models' replies parse reliably.
- **Multi-location API key** — `nirbhed` now reads `./.env`,
  `~/.config/nirbhed/.env`, and `~/.nirbhed.env`, so a global pipx install finds
  your key.
- **Benchmark script** — `scripts/benchmark.py` prints live, reproducible numbers.
- **docs/getting-started.md** — full zero-knowledge walkthrough (Kali/Linux).

### Reliability
- MCP server runs each tool off the event loop (`anyio.to_thread`) so a slow scan
  no longer freezes the whole server.
- Token budget charges a floor per turn when a provider reports zero usage, so
  budgets still bind.

### Docs
- Install instructions corrected to **install from GitHub** (not PyPI).
- README benchmarks section with measured numbers.

## 0.1.0
- Initial release: autonomous agent + MCP server, declarative toolbelt,
  distillation/cache/budget/scope, evidence-bound reporting.
