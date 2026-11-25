"""Scope + approval gates. Keeps the agent legal and on-target.

- Scope globs: a target host must match at least one scope entry (if any are set).
- Deny globs: always blocked, even if in scope.
- Approval profiles (ARTEX-style noise governor):
    quiet      -> read-only/recon tools auto-run; anything intrusive needs approval
    balanced   -> recon + non-destructive web tests auto-run; exploit/bruteforce gated
    aggressive -> everything auto-runs except explicitly destructive tools
"""

from __future__ import annotations

import fnmatch
from urllib.parse import urlparse

# Intrusiveness tiers assigned to catalog tools.
TIER_RECON = "recon"          # passive / read-only
TIER_ACTIVE = "active"        # active but non-destructive probing
TIER_EXPLOIT = "exploit"      # exploitation / bruteforce / fuzzing
TIER_DESTRUCTIVE = "destructive"

_AUTO_BY_PROFILE = {
    "quiet": {TIER_RECON},
    "balanced": {TIER_RECON, TIER_ACTIVE},
    "aggressive": {TIER_RECON, TIER_ACTIVE, TIER_EXPLOIT},
}


def host_of(target: str) -> str:
    if "://" in target:
        return urlparse(target).hostname or target
    return target.split("/")[0].split(":")[0]


class ScopeGate:
    def __init__(self, scope: list[str], deny: list[str], approval: str = "balanced"):
        self.scope = scope
        self.deny = deny
        self.approval = approval if approval in _AUTO_BY_PROFILE else "balanced"

    def in_scope(self, target: str) -> bool:
        host = host_of(target)
        for d in self.deny:
            if fnmatch.fnmatch(host, d):
                return False
        if not self.scope:
            return True  # no scope configured => unrestricted (local lab use)
        return any(fnmatch.fnmatch(host, s) for s in self.scope)

    def needs_approval(self, tier: str) -> bool:
        if tier == TIER_DESTRUCTIVE:
            return True
        return tier not in _AUTO_BY_PROFILE[self.approval]

    def check(self, target: str, tier: str) -> tuple[bool, str]:
        """Return (allowed_without_prompt, reason)."""
        if not self.in_scope(target):
            return False, f"out of scope: {host_of(target)}"
        if self.needs_approval(tier):
            return False, f"approval required ({tier} tier under '{self.approval}' profile)"
        return True, "ok"
