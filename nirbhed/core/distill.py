"""Output distillation — the heart of Nirbhed's token frugality.

Raw security-tool output is enormous and mostly noise: banners, progress bars,
ANSI codes, repeated scan lines. Feeding that straight to an LLM wastes tokens
and money. `distill()` strips the noise and keeps only salient lines, then hard
caps the result. Every observation the agent (or an MCP client) sees passes
through here first.

Each tool in the catalog declares `salience` regexes (what matters for that
tool). Lines matching any salience pattern are always kept; everything else is
dropped once we are over budget.
"""

from __future__ import annotations

import re

_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
# Spinner / progress / banner noise common to security CLIs.
_NOISE = re.compile(
    r"^\s*$"
    r"|^\s*[\|/\-\\]\s*$"
    r"|\[=+>*\s*\]"                      # progress bars
    r"|^\s*\d+(\.\d+)?%\s*$"             # bare percentages
    r"|^\s*(INF|DBG|WRN)\b"             # httpx/nuclei verbose log levels
    r"|__|====|----|\*\*\*\*"           # ascii-art banners
    r"|Made with|follow on|twitter|discord|sponsor",
    re.IGNORECASE,
)

# Generic high-signal patterns kept for any tool even without custom salience.
_DEFAULT_SALIENCE = [
    r"\b\d{1,5}/(tcp|udp)\b",                      # open ports
    r"\bhttps?://\S+",                             # urls
    r"\b(CVE-\d{4}-\d+)\b",                        # cve ids
    r"\[(critical|high|medium|low|info)\]",        # nuclei severities
    r"\b[2345]\d\d\b\s",                           # http status codes
    r"\b(open|found|vulnerable|detected|match)\b", # discovery verbs
    r"\b([0-9a-f]{2}:){5}[0-9a-f]{2}\b",           # mac addrs
    r"\b(\d{1,3}\.){3}\d{1,3}\b",                  # ipv4
]


def _compile(patterns: list[str]) -> list[re.Pattern]:
    out = []
    for p in patterns:
        try:
            out.append(re.compile(p, re.IGNORECASE))
        except re.error:
            continue
    return out


def distill(
    raw: str,
    max_chars: int = 2000,
    salience: list[str] | None = None,
    keep_tail: int = 3,
) -> str:
    """Compress raw tool output into a token-cheap, high-signal summary.

    Strategy:
      1. strip ANSI + drop obvious noise lines
      2. dedupe consecutive identical lines (scanners repeat a lot)
      3. prioritise lines matching salience; keep the tail (final status) too
      4. hard-cap to `max_chars`, noting how much was elided
    """
    if not raw:
        return "(no output)"

    text = _ANSI.sub("", raw)
    lines = text.splitlines()

    # 1 + 2: denoise and dedupe consecutive repeats.
    cleaned: list[str] = []
    prev = None
    for ln in lines:
        s = ln.rstrip()
        if _NOISE.search(s):
            continue
        if s == prev:
            continue
        cleaned.append(s)
        prev = s

    if not cleaned:
        return "(no significant output)"

    pats = _compile((salience or []) + _DEFAULT_SALIENCE)
    salient = [ln for ln in cleaned if any(p.search(ln) for p in pats)]

    # Prefer salient lines; always include the last few (exit status, totals).
    tail = cleaned[-keep_tail:] if keep_tail else []
    chosen: list[str] = []
    seen: set[str] = set()
    for ln in salient + tail:
        if ln not in seen:
            chosen.append(ln)
            seen.add(ln)

    # If nothing was salient, fall back to a head+tail slice of the cleaned text.
    if not salient:
        head = cleaned[: max(1, keep_tail)]
        chosen = []
        seen = set()
        for ln in head + tail:
            if ln not in seen:
                chosen.append(ln)
                seen.add(ln)

    body = "\n".join(chosen)
    elided = len(cleaned) - len(chosen)
    if len(body) > max_chars:
        body = body[:max_chars]
        body += "\n… [truncated]"
    if elided > 0:
        body += f"\n[{elided} lower-signal line(s) elided by distiller]"
    return body
