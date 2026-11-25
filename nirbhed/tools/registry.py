"""Tool registry + execution engine.

Loads the declarative catalog, merges built-ins, autodetects which binaries are
installed, and exposes a single `run()` that every front-end uses. `run()`
applies the full pipeline: scope gate -> cache -> execute -> distill -> evidence.
"""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import yaml

from nirbhed.config import Config
from nirbhed.core.cache import ResultCache
from nirbhed.core.distill import distill
from nirbhed.core.evidence import Evidence, EvidenceStore
from nirbhed.core.scope import ScopeGate
from nirbhed.tools.base import ExecResult, ParamSpec, ToolSpec, run_process
from nirbhed.tools.builtins import BUILTIN_RUNNERS, BUILTIN_SPECS

_CATALOG = Path(__file__).parent.parent / "data" / "tool_specs.yaml"


def _load_specs(path: Path = _CATALOG) -> list[ToolSpec]:
    specs: list[ToolSpec] = list(BUILTIN_SPECS)
    if not path.exists():
        return specs
    data = yaml.safe_load(path.read_text()) or {}
    for entry in data.get("tools", []):
        params = {
            k: ParamSpec(**v) if isinstance(v, dict) else ParamSpec(default=str(v))
            for k, v in (entry.get("params") or {}).items()
        }
        specs.append(
            ToolSpec(
                name=entry["name"],
                category=entry.get("category", "misc"),
                tier=entry.get("tier", "active"),
                binary=entry.get("binary", ""),
                desc=entry.get("desc", ""),
                cmd=entry.get("cmd", []),
                salience=entry.get("salience", []),
                timeout=int(entry.get("timeout", 300)),
                params=params or {"target": ParamSpec(required=True)},
            )
        )
    return specs


class Registry:
    def __init__(self, config: Config):
        self.config = config
        self.specs: dict[str, ToolSpec] = {s.name: s for s in _load_specs()}
        self.cache = ResultCache(config.state_dir, enabled=config.cache)
        self.scope = ScopeGate(config.scope, config.deny, config.approval)
        self.evidence = EvidenceStore()
        self.auth = config.auth

    # ── discovery ────────────────────────────────────────────────────────────
    def available(self, include_unavailable: bool = False) -> list[ToolSpec]:
        out = []
        for s in self.specs.values():
            if s.binary == "" or s.available() or include_unavailable:
                out.append(s)
        return out

    def catalog_signature(self, only_available: bool = True) -> str:
        """Compact one-line-per-tool listing for the LLM system prompt."""
        specs = self.available() if only_available else list(self.specs.values())
        by_cat: dict[str, list[str]] = {}
        for s in sorted(specs, key=lambda x: (x.category, x.name)):
            by_cat.setdefault(s.category, []).append("  " + s.signature())
        blocks = []
        for cat, items in sorted(by_cat.items()):
            blocks.append(f"[{cat}]\n" + "\n".join(items))
        return "\n".join(blocks)

    def missing_binaries(self) -> list[str]:
        return sorted({s.binary for s in self.specs.values()
                       if s.binary and not s.available()})

    # ── execution ────────────────────────────────────────────────────────────
    def run(self, name: str, params: dict | None = None,
            allow_gated: bool = False) -> ExecResult:
        params = params or {}
        spec, blocked = self._gate(name, params, allow_gated)
        if blocked is not None:
            return blocked
        return self._do_run(spec, name, params)

    def run_many(self, calls: list[dict], allow_gated: bool = False,
                 max_workers: int = 5) -> list[tuple[str, ExecResult]]:
        """Execute several independent tool calls concurrently.

        Each call is {"tool": name, "params": {...}}. Gating (availability,
        scope/approval) is applied per call BEFORE anything runs. Results come
        back in the SAME order as `calls`, each tagged with its tool name. This
        is the recon/scan fan-out speed win — subprocess tools run in parallel
        threads while each still goes through cache -> distill -> evidence.
        """
        prepared = []
        for call in calls:
            nm = call.get("tool", "")
            pr = call.get("params", {}) or {}
            spec, blocked = self._gate(nm, pr, allow_gated)
            prepared.append((nm, pr, spec, blocked))

        results: list[tuple[str, ExecResult]] = [
            (nm, blocked) for (nm, _pr, _spec, blocked) in prepared
        ]
        pending = [(i, nm, pr, spec) for i, (nm, pr, spec, blocked)
                   in enumerate(prepared) if blocked is None]
        if pending:
            workers = max(1, min(max_workers, len(pending)))
            with ThreadPoolExecutor(max_workers=workers) as pool:
                futs = {pool.submit(self._do_run, spec, nm, pr): (i, nm)
                        for (i, nm, pr, spec) in pending}
                for fut in as_completed(futs):
                    i, nm = futs[fut]
                    try:
                        results[i] = (nm, fut.result())
                    except Exception as e:  # noqa: BLE001
                        results[i] = (nm, ExecResult(False, "", 0, nm, error=str(e)))
        return results

    def _gate(self, name: str, params: dict,
              allow_gated: bool) -> tuple[ToolSpec | None, ExecResult | None]:
        """(spec, None) if allowed to run; (spec, error-ExecResult) if blocked."""
        spec = self.specs.get(name)
        if not spec:
            return None, ExecResult(False, "", 0, name, error=f"unknown tool '{name}'")
        if spec.binary and not spec.available():
            return spec, ExecResult(False, "", 0, name,
                                    error=f"'{spec.binary}' not installed on host")
        target = params.get("target", "")
        if target:
            allowed, reason = self.scope.check(target, spec.tier)
            if not allowed and "out of scope" in reason:
                return spec, ExecResult(False, "", 0, name, error=reason)
            if not allowed and not allow_gated:
                return spec, ExecResult(False, "", 0, name, error=reason)
        elif spec.tier in ("exploit", "destructive") and not allow_gated:
            return spec, ExecResult(False, "", 0, name,
                                    error=f"approval required ({spec.tier} tier)")
        return spec, None

    def _do_run(self, spec: ToolSpec, name: str, params: dict) -> ExecResult:
        """cache -> execute -> distill -> evidence. Thread-safe for run_many."""
        target = params.get("target", "")

        # cache hit: replay distilled body + rc, re-binding a FRESH evidence record
        # so evidence ids stay valid even across sessions (the old bug: never put).
        cached = self.cache.get(name, params)
        if cached is not None:
            try:
                payload = json.loads(cached)
                body, rc = payload["body"], payload["rc"]
            except (json.JSONDecodeError, KeyError, TypeError):
                body, rc = cached, 0
            ev = Evidence.make(name, f"{name} {target}".strip(), target, body, len(body))
            self.evidence.add(ev)
            return ExecResult(
                ok=(rc in (0, None)),
                output=f"[{ev.id}] rc={rc} (cached)\n{body}",
                raw_len=len(body), command=f"{name} {target}".strip(), cached=True,
                error="" if rc in (0, None) else f"exit {rc}",
            )

        # execute
        if name in BUILTIN_RUNNERS:
            runner = BUILTIN_RUNNERS[name]
            call_params = dict(params)
            call_params["_timeout"] = spec.timeout
            # inject configured auth so http_request/python_exploit hit authed surface
            if self.auth.configured:
                if name == "http_request":
                    call_params["_auth"] = self.auth.header_map()
                elif name == "python_exploit":
                    call_params["_env"] = self.auth.env()
            raw, rc = runner(call_params)
            command = f"{name} {target}".strip()
        else:
            argv, err = spec.render(params)
            if argv is None:
                return ExecResult(False, "", 0, name, error=err)
            command = " ".join(argv)
            raw, rc = run_process(argv, spec.timeout)

        condensed = distill(raw, self.config.distill_max_chars, spec.salience)
        ev = Evidence.make(name, command, target, condensed, len(raw))
        self.evidence.add(ev)

        # cache only real completions (rc -1 timeout / -2 launch-fail are transient)
        if rc not in (-1, -2):
            self.cache.put(name, params, json.dumps({"rc": rc, "body": condensed}))

        return ExecResult(
            ok=(rc in (0, None)),
            output=f"[{ev.id}] rc={rc}\n{condensed}",
            raw_len=len(raw),
            command=command,
            error="" if rc in (0, None) else f"exit {rc}",
        )
