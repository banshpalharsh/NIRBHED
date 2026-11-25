"""Hard budgets: tokens, turns, wall-clock. Borrowed from ARTEX's per-task caps.

The agent loop checks `exceeded()` every turn and stops cleanly with a reason,
so a run can never silently run away with your API spend.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field


@dataclass
class Budget:
    max_tokens: int
    max_turns: int
    max_seconds: int

    tokens_used: int = 0
    turns_used: int = 0
    _start: float = field(default_factory=time.monotonic)

    def add_tokens(self, n: int) -> None:
        self.tokens_used += max(0, n)

    def tick_turn(self) -> None:
        self.turns_used += 1

    @property
    def elapsed(self) -> float:
        return time.monotonic() - self._start

    def exceeded(self) -> str | None:
        if self.tokens_used >= self.max_tokens:
            return f"token budget reached ({self.tokens_used}/{self.max_tokens})"
        if self.turns_used >= self.max_turns:
            return f"turn budget reached ({self.turns_used}/{self.max_turns})"
        if self.elapsed >= self.max_seconds:
            return f"time budget reached ({int(self.elapsed)}s/{self.max_seconds}s)"
        return None

    def summary(self) -> str:
        return (
            f"tokens={self.tokens_used}/{self.max_tokens} "
            f"turns={self.turns_used}/{self.max_turns} "
            f"time={int(self.elapsed)}s/{self.max_seconds}s"
        )
