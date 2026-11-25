"""Report generation: Markdown + JSON. Evidence-bound, CVSS/OWASP-tagged."""

from __future__ import annotations

import json
import time
from pathlib import Path

from nirbhed.core.evidence import EvidenceStore
from nirbhed.core.findings import FindingStore


def _sev_emoji(sev: str) -> str:
    return {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}.get(sev, "⚪")


def to_markdown(target: str, findings: FindingStore, evidence: EvidenceStore,
                budget_summary: str, cache_stats: dict) -> str:
    fs = findings.all()
    lines = [
        f"# Nirbhed Pentest Report — {target}",
        f"_Generated {time.strftime('%Y-%m-%d %H:%M:%S')}_",
        "",
        "## Summary",
        f"- Findings: **{len(fs)}**",
    ]
    counts: dict[str, int] = {}
    for f in fs:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    for sev in ["critical", "high", "medium", "low", "info"]:
        if counts.get(sev):
            lines.append(f"  - {_sev_emoji(sev)} {sev}: {counts[sev]}")
    lines += [
        f"- Budget: `{budget_summary}`",
        f"- Cache: {cache_stats.get('hits', 0)} hits / {cache_stats.get('misses', 0)} misses",
        "",
        "## Findings",
    ]
    if not fs:
        lines.append("_No findings._")
    for i, f in enumerate(fs, 1):
        lines += [
            f"### {i}. {_sev_emoji(f.severity)} {f.title}",
            f"- **Severity:** {f.severity}"
            + (f" (CVSS {f.cvss})" if f.cvss else ""),
            f"- **Target:** `{f.target}`",
        ]
        if f.owasp:
            lines.append(f"- **OWASP:** {f.owasp}")
        if f.cwe:
            lines.append(f"- **CWE:** {f.cwe}")
        lines.append(f"- **Status:** {f.status.value}")
        if f.description:
            lines += ["", f.description]
        if f.repro:
            lines += ["", "**Reproduction / PoC:**", "```", f.repro, "```"]
        if f.remediation:
            lines += ["", f"**Remediation:** {f.remediation}"]
        if f.evidence_ids:
            lines.append("")
            lines.append("**Evidence:**")
            for eid in f.evidence_ids:
                ev = evidence.get(eid)
                if ev:
                    lines += [f"- `{ev.id}` via `{ev.tool}`: `{ev.command}`",
                              "  ```", "  " + ev.output.replace("\n", "\n  "), "  ```"]
        lines.append("")
    return "\n".join(lines)


def to_json(target: str, findings: FindingStore, evidence: EvidenceStore) -> str:
    return json.dumps(
        {
            "target": target,
            "generated": time.time(),
            "findings": [f.to_dict() for f in findings.all()],
            "evidence": [e.to_dict() for e in evidence.all()],
        },
        indent=2,
    )


def write_reports(out_dir: Path, target: str, findings: FindingStore,
                  evidence: EvidenceStore, budget_summary: str,
                  cache_stats: dict) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    safe = target.replace("://", "_").replace("/", "_").replace(":", "_")
    md = out_dir / f"{safe}.md"
    js = out_dir / f"{safe}.json"
    md.write_text(to_markdown(target, findings, evidence, budget_summary, cache_stats))
    js.write_text(to_json(target, findings, evidence))
    return {"markdown": md, "json": js}
