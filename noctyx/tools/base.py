"""Tool specification + safe execution.

Tools are declared as data (see data/tool_specs.yaml). Each spec renders to an
argv list — never a shell string — so target/params can't inject shell syntax.
Execution is wrapped with: scope check -> cache -> subprocess -> distill ->
evidence. One wrapper serves both the MCP server and the standalone agent.
"""

from __future__ import annotations

import shlex
import shutil
import subprocess
from dataclasses import dataclass, field


class _SafeDict(dict):
    """format_map helper: unknown placeholders render empty instead of raising."""

    def __missing__(self, key):
        return ""


@dataclass
class ParamSpec:
    required: bool = False
    default: str = ""
    help: str = ""


@dataclass
class ToolSpec:
    name: str
    category: str
    tier: str                       # scope.TIER_*
    binary: str                     # executable that must exist on PATH
    desc: str
    cmd: list[str]                  # argv template; tokens like {target}, {extra}
    salience: list[str] = field(default_factory=list)
    timeout: int = 300
    params: dict[str, ParamSpec] = field(default_factory=dict)

    def available(self) -> bool:
        return shutil.which(self.binary) is not None

    def render(self, params: dict) -> tuple[list[str] | None, str]:
        """Return (argv, error). Validates required params; substitutes safely."""
        merged = {k: v.default for k, v in self.params.items()}
        merged.update({k: str(v) for k, v in (params or {}).items() if v is not None})
        for name, spec in self.params.items():
            if spec.required and not merged.get(name):
                return None, f"missing required param '{name}'"

        argv: list[str] = []
        for part in self.cmd:
            if part == "{extra}":
                argv.extend(shlex.split(merged.get("extra", "") or ""))
                continue
            rendered = part.format_map(_SafeDict(merged))
            if rendered != "":
                argv.append(rendered)
        return argv, ""

    def signature(self) -> str:
        """One-line signature for the LLM (token-cheap)."""
        req = [n for n, s in self.params.items() if s.required]
        opt = [n for n, s in self.params.items() if not s.required]
        p = ", ".join(req + [f"{o}?" for o in opt])
        return f"{self.name}({p}) [{self.tier}] — {self.desc}"


@dataclass
class ExecResult:
    ok: bool
    output: str          # distilled
    raw_len: int
    command: str
    cached: bool = False
    error: str = ""


def run_process(argv: list[str], timeout: int) -> tuple[str, int]:
    """Run argv with no shell. Returns (combined_output, returncode).
    rc == -1 on timeout, -2 on launch failure."""
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return (proc.stdout or "") + (proc.stderr or ""), proc.returncode
    except subprocess.TimeoutExpired as e:
        partial = ""
        if e.stdout:
            partial += e.stdout if isinstance(e.stdout, str) else e.stdout.decode(errors="replace")
        if e.stderr:
            partial += e.stderr if isinstance(e.stderr, str) else e.stderr.decode(errors="replace")
        return partial + f"\n[timed out after {timeout}s]", -1
    except (FileNotFoundError, OSError) as e:
        return f"[failed to launch: {e}]", -2
