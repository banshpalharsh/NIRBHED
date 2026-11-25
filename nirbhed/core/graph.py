"""Dual graphs (ARTEX): a shared asset graph and a per-run exploration graph.

- Asset graph: root -> subdomain -> service -> endpoint. Durable attack surface.
- Exploration graph: goal -> intent -> fact -> finding. What the agent reasoned.

Kept deliberately small and serialisable. Its compact text form feeds the LLM a
map of the surface without re-sending raw scan output.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class AssetGraph:
    roots: set[str] = field(default_factory=set)
    subdomains: set[str] = field(default_factory=set)
    services: set[str] = field(default_factory=set)      # "host:port proto"
    endpoints: set[str] = field(default_factory=set)      # urls
    tested: set[str] = field(default_factory=set)         # coverage ledger

    def add_root(self, v: str) -> None:
        self.roots.add(v)

    def add_subdomain(self, v: str) -> None:
        self.subdomains.add(v)

    def add_service(self, v: str) -> None:
        self.services.add(v)

    def add_endpoint(self, v: str) -> None:
        self.endpoints.add(v)

    def mark_tested(self, v: str) -> None:
        self.tested.add(v)

    def coverage(self) -> tuple[int, int]:
        """(tested, total) across endpoints — the coverage ledger."""
        total = len(self.endpoints)
        tested = len(self.endpoints & self.tested)
        return tested, total

    def compact(self, limit: int = 40) -> str:
        def cap(s: set[str]) -> str:
            items = sorted(s)
            if len(items) > limit:
                return ", ".join(items[:limit]) + f" (+{len(items) - limit} more)"
            return ", ".join(items) if items else "-"

        t, tot = self.coverage()
        return (
            f"roots: {cap(self.roots)}\n"
            f"subdomains: {cap(self.subdomains)}\n"
            f"services: {cap(self.services)}\n"
            f"endpoints: {cap(self.endpoints)}\n"
            f"coverage: {t}/{tot} endpoints tested"
        )
