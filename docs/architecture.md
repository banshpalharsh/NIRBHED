# Architecture

Nirbhed is **one engine with two front-ends**. Both front-ends call the same
`Registry.run()` pipeline, so scope gating, caching, distillation and evidence
behave identically whether a human-driven MCP client or the headless agent is in
control.

```
front-ends ─┬─ nirbhed mcp    → MCP server (stdio). Claude Desktop is the brain. No API key.
            └─ nirbhed run    → autonomous Agent. Any OpenAI-compatible LLM. Cheap key.
                                     │
                                     ▼  shared engine
  Registry.run(name, params, allow_gated)
     1. resolve ToolSpec (declarative catalog + built-ins)
     2. binary availability check
     3. ScopeGate: host in-scope? tier allowed under approval profile?
     4. ResultCache: identical call already done? → replay (0 tokens, 0 exec)
     5. execute: argv (NO shell) | built-in http/python runner
     6. distill: strip noise, keep salient lines, hard cap
     7. Evidence.make: timestamped + hashed record, returned with an id
```

## Modules

| Path | Responsibility |
|------|----------------|
| `config.py` | env/flag config; LLM provider + budgets + scope |
| `core/distill.py` | token-frugal output compression |
| `core/cache.py` | content-addressed result cache |
| `core/budget.py` | token/turn/time hard caps |
| `core/scope.py` | scope + deny globs, approval tiers (noise governor) |
| `core/evidence.py` | evidence records ("keeps its receipts") |
| `core/findings.py` | typed findings, dedup, CVSS/OWASP/CWE, retest status |
| `core/graph.py` | asset graph + coverage ledger |
| `core/report.py` | markdown + json reports |
| `tools/base.py` | ToolSpec, safe argv render, subprocess exec |
| `tools/builtins.py` | in-process HTTP client + Python PoC runtime |
| `tools/registry.py` | catalog load, autodetect, the `run()` pipeline |
| `data/tool_specs.yaml` | the declarative toolbelt |
| `llm/provider.py` | OpenAI-compatible client w/ failover |
| `llm/prompts.py` | compact system/turn prompts |
| `agent/loop.py` | near-stateless ReAct planner/worker loop |
| `agent/extract.py` | cheap graph extraction from tool output |
| `mcp/server.py` | MCP stdio server (tools + meta tools) |
| `cli.py` | Typer CLI |

## Why near-stateless turns

A conventional agent appends every observation to a growing transcript, so turn
*n* pays for turns *1..n-1* again. Nirbhed instead reconstructs a **compact state**
each turn — asset graph summary, findings brief, last result, recent action list —
and sends `system + state`. The state is the memory. Per-turn cost stays roughly
flat, which is what makes deep runs affordable on pay-per-token models.
