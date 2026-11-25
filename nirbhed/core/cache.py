"""Content-addressed cache for tool invocations.

Re-running the same tool with the same args against the same target is common
during a pentest (the LLM forgets, retries, chains). Caching the distilled
result means a repeat costs *zero* LLM tokens and *zero* process execution.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path


class ResultCache:
    def __init__(self, state_dir: Path, enabled: bool = True):
        self.enabled = enabled
        self.dir = state_dir / "cache"
        if enabled:
            self.dir.mkdir(parents=True, exist_ok=True)
        self.hits = 0
        self.misses = 0

    @staticmethod
    def key(tool: str, args: dict) -> str:
        payload = json.dumps({"tool": tool, "args": args}, sort_keys=True, default=str)
        return hashlib.sha256(payload.encode()).hexdigest()[:20]

    def get(self, tool: str, args: dict) -> str | None:
        if not self.enabled:
            return None
        f = self.dir / f"{self.key(tool, args)}.json"
        if not f.exists():
            self.misses += 1
            return None
        try:
            data = json.loads(f.read_text())
            self.hits += 1
            return data["result"]
        except (json.JSONDecodeError, KeyError):
            self.misses += 1
            return None

    def put(self, tool: str, args: dict, result: str) -> None:
        if not self.enabled:
            return
        f = self.dir / f"{self.key(tool, args)}.json"
        f.write_text(json.dumps({"tool": tool, "args": args, "result": result, "ts": time.time()}))

    @property
    def stats(self) -> dict:
        return {"hits": self.hits, "misses": self.misses}
