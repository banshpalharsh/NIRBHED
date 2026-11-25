# Token optimization

The result quality is never traded away; the *noise* is. Five mechanisms:

### 1. Output distillation — `core/distill.py`
Security tools emit huge, repetitive output. Before anything reaches the LLM:
- strip ANSI escapes, banners, spinners, progress bars, verbose log levels
- dedupe consecutive identical lines (scanners repeat heavily)
- keep lines matching **per-tool salience regexes** (open ports, URLs, CVE ids,
  nuclei severities, HTTP statuses, discovery verbs) plus the tail (final totals)
- hard-cap to `NIRBHED_DISTILL_MAX_CHARS` and annotate how much was elided

A 2,000-line nuclei/nmap dump becomes a few dozen high-signal lines.

### 2. Content-addressed cache — `core/cache.py`
`sha256(tool + args)` keys the distilled result on disk. A repeat call returns
instantly: **zero tokens, zero process execution.** Agents retry a lot; this is
free money saved.

### 3. Near-stateless turns — `agent/loop.py`
Each turn sends `system + compact state`, not a growing transcript. Per-turn cost
is ~flat instead of O(n). See [architecture.md](architecture.md).

### 4. Finding dedup — `core/findings.py`
Findings are fingerprinted (`title|target|cwe`). Duplicates merge (keeping the
higher severity and union of evidence). The agent never re-sees or re-reports a
vuln, so the state stays small.

### 5. Hard budgets — `core/budget.py`
`NIRBHED_MAX_TOKENS`, `NIRBHED_MAX_TURNS`, `NIRBHED_MAX_SECONDS` stop a run cleanly.
A run can never silently overspend.

## Knobs

| Env var | Default | Effect |
|---------|---------|--------|
| `NIRBHED_DISTILL_MAX_CHARS` | 2000 | max chars of a single observation |
| `NIRBHED_CACHE` | 1 | 0 disables the result cache |
| `NIRBHED_MAX_TOKENS` | 120000 | total token ceiling per run |
| `NIRBHED_MAX_TURNS` | 40 | max loop iterations |
| `NIRBHED_MAX_SECONDS` | 1800 | wall-clock ceiling |

## Tip: run tools without the LLM at all
`nirbhed exec <tool> <target>` gives you distillation + caching + scope gating with
**no LLM in the loop** — perfect for the cheap, deterministic parts of a workflow.
