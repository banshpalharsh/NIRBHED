"""Output distillation — the heart of Nirbhed's token frugality.

Raw security-tool output is enormous and mostly noise: banners, progress bars,
ANSI codes, repeated scan lines. Feeding that straight to an LLM wastes tokens
and money. `distill()` strips the noise and keeps only salient lines, then hard
caps the result. Every observation the agent (or an MCP client) sees passes
through here first.

Salience is two-tier: PRIMARY signals (CVEs, severities, open ports, URLs, HTTP
statuses, IPs) are kept ahead of SECONDARY ones (generic discovery verbs), so a
real finding can never be crowded out of the character budget by chatter. That
ordering is what stops the distiller from trading accuracy for brevity.
"""

from __future__ import annotations

import re

_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
# Spinner / progress / banner / log-level noise common to security CLIs.
_NOISE = re.compile(
    r"^\s*$"
    r"|^\s*[\|/\-\\]\s*$"
    r"|\[=+>*\s*\]"                           # progress bars
    r"|^\s*\d+(\.\d+)?%\s*$"                  # bare percentages
    r"|^\s*\[?(INF|DBG|WRN|VRB|TRC|TRACE|DEBUG|VERBOSE)\]?\b"  # log levels, bracketed or not
    r"|__|====|----|\*\*\*\*"                 # ascii-art banners
    r"|Made with|follow on|twitter|discord|sponsor",
    re.IGNORECASE,
)

# PRIMARY: concrete, high-value findings. Always kept first.
_PRIMARY = [
    r"\b(CVE-\d{4}-\d+)\b",
    r"\[(critical|high|medium|low|info)\]",
    r"\b\d{1,5}/(tcp|udp)\b",
    r"\bhttps?://\S+",
    r"(?<![\w.])\b([2345]\d\d)\b(?![\w.])",         # http status codes (standalone)
    r"\b(\d{1,3}\.){3}\d{1,3}\b",                    # ipv4
    r"\b([0-9a-f]{2}:){5}[0-9a-f]{2}\b",             # mac
]
# SECONDARY: softer signals. "matched"/"open" etc., but NOT inside words like
# "no-match" or "unopened" (hyphen/word-char lookarounds prevent false hits).
_SECONDARY = [
    r"(?<![\w-])(open|found|vulnerable|detected|matched|injectable|leak|exposed)(?![\w-])",
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

    1. strip ANSI + drop obvious noise/log-level lines
    2. dedupe consecutive identical lines
    3. keep PRIMARY (findings) first, then per-tool custom salience, then
       SECONDARY (verbs), then the tail (final status) — cap to max_chars
    """
    if not raw:
        return "(no output)"

    text = _ANSI.sub("", raw)
    cleaned: list[str] = []
    prev = None
    for ln in text.splitlines():
        s = ln.rstrip()
        if _NOISE.search(s):
            continue
        if s == prev:
            continue
        cleaned.append(s)
        prev = s
    if not cleaned:
        return "(no significant output)"

    primary_pats = _compile(_PRIMARY + (salience or []))
    secondary_pats = _compile(_SECONDARY)

    primary, secondary = [], []
    for ln in cleaned:
        if any(p.search(ln) for p in primary_pats):
            primary.append(ln)
        elif any(p.search(ln) for p in secondary_pats):
            secondary.append(ln)

    tail = cleaned[-keep_tail:] if keep_tail else []
    ordered = primary + secondary + tail
    if not primary and not secondary:  # nothing salient: fall back to head+tail
        ordered = cleaned[: max(1, keep_tail)] + tail

    chosen: list[str] = []
    seen: set[str] = set()
    for ln in ordered:
        if ln not in seen:
            chosen.append(ln)
            seen.add(ln)

    body = "\n".join(chosen)
    elided = len(cleaned) - len(chosen)
    if len(body) > max_chars:
        body = body[:max_chars] + "\n… [truncated]"
    if elided > 0:
        body += f"\n[{elided} lower-signal line(s) elided by distiller]"
    return body
