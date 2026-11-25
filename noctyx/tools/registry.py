"""Tool registry + execution engine.

Loads the declarative catalog, merges built-ins, autodetects which binaries are
installed, and exposes a single `run()` that every front-end uses. `run()`
applies the full pipeline: scope gate -> cache -> execute -> distill -> evidence.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from noctyx.config import Config
from noctyx.core.cache import ResultCache
from noctyx.core.distill import distill
from noctyx.core.evidence import Evidence, EvidenceStore
from noctyx.core.scope import ScopeGate
from noctyx.tools.base import ExecResult, ParamSpec, ToolSpec, run_process
from noctyx.tools.builtins import BUILTIN_RUNNERS, BUILTIN_SPECS

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
        spec = self.specs.get(name)
        if not spec:
            return ExecResult(False, "", 0, name, error=f"unknown tool '{name}'")

        if spec.binary and not spec.available():
            return ExecResult(False, "", 0, name,
                              error=f"'{spec.binary}' not installed on host")

        target = params.get("target", "")
        # scope + approval gate (built-in tools with no target skip host scope)
        if target:
            allowed, reason = self.scope.check(target, spec.tier)
            if not allowed and "out of scope" in reason:
                return ExecResult(False, "", 0, name, error=reason)
            if not allowed and not allow_gated:
                return ExecResult(False, "", 0, name, error=reason)
        elif spec.tier in ("exploit", "destructive") and not allow_gated:
            return ExecResult(False, "", 0, name,
                              error=f"approval required ({spec.tier} tier)")

        # cache
        cached = self.cache.get(name, params)
        if cached is not None:
            return ExecResult(True, cached, len(cached), f"{name}(cached)", cached=True)

        # execute
        if name in BUILTIN_RUNNERS:
            runner = BUILTIN_RUNNERS[name]
            call_params = dict(params)
            call_params["_timeout"] = spec.timeout
            raw, rc = runner(call_params)
            command = f"{name} {params.get('target', '')}".strip()
        else:
            argv, err = spec.render(params)
            if argv is None:
                return ExecResult(False, "", 0, name, error=err)
            command = " ".join(argv)
            raw, rc = run_process(argv, spec.timeout)

        # distill + evidence
        condensed = distill(raw, self.config.distill_max_chars, spec.salience)
        ev = Evidence.make(name, command, target, condensed, len(raw))
        self.evidence.add(ev)
        header = f"[{ev.id}] rc={rc}"
        return ExecResult(
            ok=(rc == 0 or rc is None),
            output=f"{header}\n{condensed}",
            raw_len=len(raw),
            command=command,
            error="" if rc in (0, None) else f"exit {rc}",
        )
