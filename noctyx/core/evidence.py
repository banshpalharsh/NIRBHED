"""Evidence binding (ARTEX "keeps its receipts").

Every tool execution produces an Evidence record: the exact command/request and
its (distilled) response, timestamped and hashed. Findings reference evidence by
id so a report can always show the proof and a retester can reproduce it.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field


@dataclass
class Evidence:
    id: str
    tool: str
    command: str
    target: str
    output: str            # distilled output
    raw_len: int           # length of the pre-distill output (for honesty)
    ts: float = field(default_factory=time.time)

    @staticmethod
    def make(tool: str, command: str, target: str, output: str, raw_len: int) -> Evidence:
        h = hashlib.sha256(f"{tool}{command}{time.time()}".encode()).hexdigest()[:10]
        return Evidence(id=f"ev-{h}", tool=tool, command=command, target=target,
                        output=output, raw_len=raw_len)

    def to_dict(self) -> dict:
        return {
            "id": self.id, "tool": self.tool, "command": self.command,
            "target": self.target, "output": self.output, "raw_len": self.raw_len,
            "ts": self.ts,
        }


class EvidenceStore:
    def __init__(self) -> None:
        self._items: dict[str, Evidence] = {}

    def add(self, ev: Evidence) -> str:
        self._items[ev.id] = ev
        return ev.id

    def get(self, ev_id: str) -> Evidence | None:
        return self._items.get(ev_id)

    def all(self) -> list[Evidence]:
        return list(self._items.values())
