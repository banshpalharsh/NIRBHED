"""Findings: typed vulnerability records with CVSS, OWASP tags, dedup, and a
retest status (ARTEX: Still reproducible / Fixed / Cannot confirm).

Dedup matters for token cost: the agent never re-reports or re-sees a finding it
already has, which keeps the context window (and the bill) small.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from enum import Enum

SEVERITIES = ["info", "low", "medium", "high", "critical"]


class RetestStatus(str, Enum):
    UNVERIFIED = "unverified"
    REPRODUCIBLE = "reproducible"
    FIXED = "fixed"
    CANNOT_CONFIRM = "cannot_confirm"


@dataclass
class Finding:
    title: str
    severity: str                       # one of SEVERITIES
    target: str
    description: str = ""
    owasp: str = ""                     # e.g. "A01:2021 Broken Access Control"
    cwe: str = ""                       # e.g. "CWE-89"
    cvss: float = 0.0
    evidence_ids: list[str] = field(default_factory=list)
    repro: str = ""                     # reproduction steps / PoC
    remediation: str = ""
    status: RetestStatus = RetestStatus.UNVERIFIED
    ts: float = field(default_factory=time.time)

    @property
    def fingerprint(self) -> str:
        key = f"{self.title.lower().strip()}|{self.target.lower().strip()}|{self.cwe}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["status"] = self.status.value
        d["fingerprint"] = self.fingerprint
        return d


class FindingStore:
    def __init__(self) -> None:
        self._by_fp: dict[str, Finding] = {}

    def add(self, f: Finding) -> bool:
        """Add if new. Returns True if newly added, False if duplicate (merged)."""
        if f.severity not in SEVERITIES:
            f.severity = "info"
        fp = f.fingerprint
        if fp in self._by_fp:
            existing = self._by_fp[fp]
            # merge evidence, keep the higher severity
            for e in f.evidence_ids:
                if e not in existing.evidence_ids:
                    existing.evidence_ids.append(e)
            if SEVERITIES.index(f.severity) > SEVERITIES.index(existing.severity):
                existing.severity = f.severity
            return False
        self._by_fp[fp] = f
        return True

    def all(self) -> list[Finding]:
        return sorted(
            self._by_fp.values(),
            key=lambda x: SEVERITIES.index(x.severity),
            reverse=True,
        )

    def count(self) -> int:
        return len(self._by_fp)

    def brief(self) -> str:
        """Ultra-compact summary fed back to the LLM so it knows what's already
        found without re-reading full records (token saver)."""
        if not self._by_fp:
            return "none yet"
        return "; ".join(f"[{f.severity}] {f.title}" for f in self.all())
