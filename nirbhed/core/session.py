"""Shared run state + operator inbox for the live viewer and human-in-the-loop.

RunState is a thread-safe snapshot of an in-progress engagement that the web
viewer polls. Inbox is the reverse channel: the operator (via the viewer or the
terminal) pushes messages and pause/stop signals that the agent reads each turn.
Both are plain stdlib + threading — no extra dependency.
"""

from __future__ import annotations

import json
import threading
import time
from collections import deque
from pathlib import Path


class Inbox:
    """Operator -> agent channel. Messages are injected into the next turn;
    pause/stop are honored at the top of each loop iteration."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._msgs: deque[str] = deque()
        self._pause = threading.Event()
        self._stop = threading.Event()

    def push(self, text: str) -> None:
        text = (text or "").strip()
        if text:
            with self._lock:
                self._msgs.append(text)

    def drain(self) -> list[str]:
        with self._lock:
            out = list(self._msgs)
            self._msgs.clear()
            return out

    def set_pause(self, on: bool) -> None:
        self._pause.set() if on else self._pause.clear()

    def request_stop(self) -> None:
        self._stop.set()

    @property
    def paused(self) -> bool:
        return self._pause.is_set()

    @property
    def stopping(self) -> bool:
        return self._stop.is_set()


class RunState:
    """Thread-safe, serializable snapshot the viewer renders."""

    def __init__(self, run_id: str, target: str, objective: str,
                 auth_masked: dict | None = None) -> None:
        self._lock = threading.Lock()
        self.run_id = run_id
        self.target = target
        self.objective = objective
        self.status = "running"          # running | paused | done | stopped
        self.phase = "recon"
        self.started = time.time()
        self.updated = time.time()
        self.budget: dict = {}
        self.graph_text = ""
        self.findings: list[dict] = []
        self.log: deque[str] = deque(maxlen=200)
        self.auth_masked = auth_masked or {}
        self.stop_reason = ""
        self._persist_path: Path | None = None

    def bind_persist(self, path: Path) -> None:
        self._persist_path = path
        path.parent.mkdir(parents=True, exist_ok=True)

    def log_line(self, text: str) -> None:
        with self._lock:
            self.log.append(f"{time.strftime('%H:%M:%S')}  {text}")
            self.updated = time.time()
        self._persist()

    def update(self, **kw) -> None:
        with self._lock:
            for k, v in kw.items():
                setattr(self, k, v)
            self.updated = time.time()
        self._persist()

    def set_findings(self, findings: list[dict]) -> None:
        with self._lock:
            self.findings = findings
            self.updated = time.time()
        self._persist()

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "run_id": self.run_id,
                "target": self.target,
                "objective": self.objective,
                "status": self.status,
                "phase": self.phase,
                "started": self.started,
                "updated": self.updated,
                "elapsed": int(time.time() - self.started),
                "budget": self.budget,
                "graph_text": self.graph_text,
                "findings": self.findings,
                "log": list(self.log),
                "auth": self.auth_masked,
                "stop_reason": self.stop_reason,
            }

    def _persist(self) -> None:
        if not self._persist_path:
            return
        try:
            tmp = self._persist_path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self.snapshot()))
            tmp.replace(self._persist_path)
        except OSError:
            pass
