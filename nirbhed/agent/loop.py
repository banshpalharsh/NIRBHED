"""The autonomous agent: a token-frugal planner/worker ReAct loop.

Design choice for frugality: turns are (almost) STATELESS. Instead of resending a
growing transcript, each turn sends the system prompt + a COMPACT running state
(asset graph + findings brief + recent actions + last observation). The state IS
the memory. This keeps per-turn cost roughly flat instead of growing O(n), which
is what makes long runs cheap on pay-per-token models like DeepSeek.

Reliability features: robust JSON extraction, a `parallel` action for recon
fan-out, a stall detector (stops looping agents), and a false-positive guard that
refuses to store high/critical findings without evidence.
"""

from __future__ import annotations

import json
import re

from rich.console import Console

from nirbhed.agent.extract import update_graph
from nirbhed.config import Config
from nirbhed.core.budget import Budget
from nirbhed.core.evidence import EvidenceStore
from nirbhed.core.findings import Finding, FindingStore, RetestStatus
from nirbhed.core.graph import AssetGraph
from nirbhed.llm.prompts import SYSTEM, build_user_turn
from nirbhed.llm.provider import LLM
from nirbhed.tools.registry import Registry

_FENCED = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL)
_MAX_PARALLEL = 6
_STALL_LIMIT = 4


def _balanced_json(text: str) -> str | None:
    """Extract the first balanced {...} block, ignoring braces inside strings."""
    start = text.find("{")
    if start == -1:
        return None
    depth = 0
    in_str = False
    esc = False
    for i in range(start, len(text)):
        c = text[i]
        if esc:
            esc = False
            continue
        if c == "\\":
            esc = True
            continue
        if c == '"':
            in_str = not in_str
            continue
        if in_str:
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
    return None


def _parse_action(text: str) -> dict | None:
    candidates = _FENCED.findall(text)
    bal = _balanced_json(text)
    if bal:
        candidates.append(bal)
    for cand in reversed(candidates):  # prefer the last / most complete block
        for attempt in (cand, re.sub(r",\s*([}\]])", r"\1", cand)):
            try:
                obj = json.loads(attempt)
                if isinstance(obj, dict):
                    return obj
            except json.JSONDecodeError:
                continue
    return None


class Agent:
    def __init__(self, config: Config, console: Console | None = None,
                 allow_gated: bool = False):
        self.config = config
        self.console = console or Console(stderr=True)
        self.allow_gated = allow_gated
        self.registry = Registry(config)
        self.evidence: EvidenceStore = self.registry.evidence
        self.findings = FindingStore()
        self.graph = AssetGraph()
        self.llm = LLM(config.primary, config.fallback)
        self.budget = Budget(config.max_tokens, config.max_turns, config.max_seconds)
        self._root = ""

    # ── state ────────────────────────────────────────────────────────────────
    def _state(self, recent: list[str], last_obs: str) -> str:
        return (
            f"ASSET GRAPH:\n{self.graph.compact()}\n\n"
            f"FINDINGS SO FAR: {self.findings.brief()}\n\n"
            "RECENT ACTIONS (newest last):\n" + ("\n".join(recent[-6:]) or "-") + "\n\n"
            f"LAST RESULT:\n{last_obs or '-'}\n\n"
            f"BUDGET: {self.budget.summary()}"
        )

    def _absorb(self, target: str, output: str) -> None:
        update_graph(self.graph, self._root, output)
        if target:
            self.graph.mark_tested(target)

    def _record_finding(self, f: dict, default_target: str) -> tuple[bool, str]:
        """False-positive guard: high/critical require evidence; else store as
        suspected (unverified). Returns (stored, message)."""
        sev = f.get("severity", "info")
        ev_ids = f.get("evidence_ids", []) or []
        if sev in ("high", "critical") and not ev_ids:
            return False, (f"REJECTED '[{sev}] {f.get('title','?')}': no evidence. "
                           "Prove it with http_request/python_exploit and cite the ev-id, "
                           "or downgrade to low/info as suspected.")
        finding = Finding(
            title=f.get("title", "untitled"),
            severity=sev,
            target=f.get("target", default_target),
            description=f.get("description", ""),
            owasp=f.get("owasp", ""),
            cwe=f.get("cwe", ""),
            cvss=float(f.get("cvss", 0) or 0),
            evidence_ids=ev_ids,
            repro=f.get("repro", ""),
            remediation=f.get("remediation", ""),
            status=RetestStatus.REPRODUCIBLE if ev_ids else RetestStatus.UNVERIFIED,
        )
        is_new = self.findings.add(finding)
        verb = "recorded" if is_new else "merged (duplicate)"
        tail = "" if ev_ids else " [unverified/suspected]"
        return True, f"finding {verb}: [{finding.severity}] {finding.title}{tail}"

    # ── main loop ──────────────────────────────────────────────────────────────
    def run(self, target: str, objective: str) -> dict:
        self._root = target.split("://")[-1].split("/")[0]
        self.graph.add_root(self._root)
        catalog = self.registry.catalog_signature(only_available=True)
        recent: list[str] = []
        last_obs = "(none — begin with reconnaissance)"
        stop_reason = "completed"
        stall = 0

        self.console.print(f"[bold cyan]nirbhed[/] target=[yellow]{target}[/] "
                           f"tools={len(self.registry.available())}")

        while True:
            over = self.budget.exceeded()
            if over:
                stop_reason = over
                break
            if stall >= _STALL_LIMIT:
                stop_reason = "stalled (no progress after repeated invalid/empty turns)"
                break
            self.budget.tick_turn()

            messages = [
                {"role": "system", "content": SYSTEM},
                {"role": "user", "content": build_user_turn(
                    target, objective, catalog, self._state(recent, last_obs))},
            ]
            try:
                reply = self.llm.chat(messages)
            except Exception as e:  # noqa: BLE001
                stop_reason = f"llm error: {e}"
                break
            # some providers report 0 usage; charge a floor so budgets still bind
            self.budget.add_tokens(reply.total_tokens or 500)

            action = _parse_action(reply.content)
            if not action:
                stall += 1
                last_obs = "ERROR: reply was not valid JSON. Output exactly one json block."
                recent.append("(malformed reply)")
                continue

            kind = action.get("action")
            thought = action.get("thought", "")
            self.console.print(f"[dim]t{self.budget.turns_used}[/] [green]{kind}[/] {thought}")

            if kind == "finish":
                stop_reason = action.get("reason", "agent finished")
                break

            if kind == "report":
                stored, msg = self._record_finding(action.get("finding", {}) or {}, target)
                last_obs = msg
                recent.append(f"report -> {'ok' if stored else 'rejected'}")
                stall = 0 if stored else stall + 1
                continue

            if kind == "tool":
                name = action.get("tool", "")
                params = action.get("params", {}) or {}
                res = self.registry.run(name, params, allow_gated=self.allow_gated)
                if res.ok:
                    self._absorb(params.get("target", target), res.output)
                    stall = 0
                else:
                    stall += 1
                last_obs = res.output if res.ok else f"TOOL ERROR ({name}): {res.error}"
                tag = "cached" if res.cached else ("ok" if res.ok else "err")
                recent.append(f"{name}({params.get('target', '')}) -> {tag}")
                continue

            if kind == "parallel":
                calls = (action.get("tools") or [])[:_MAX_PARALLEL]
                if not calls:
                    stall += 1
                    last_obs = "ERROR: 'parallel' needs a non-empty 'tools' list."
                    recent.append("(empty parallel)")
                    continue
                results = self.registry.run_many(calls, allow_gated=self.allow_gated)
                per = max(400, self.config.distill_max_chars // max(1, len(results)))
                blocks, any_ok = [], False
                for nm, res in results:
                    if res.ok:
                        any_ok = True
                        tgt = next((c.get("params", {}).get("target", "")
                                    for c in calls if c.get("tool") == nm), "")
                        self._absorb(tgt or target, res.output)
                    body = res.output if res.ok else f"ERROR: {res.error}"
                    if len(body) > per:
                        body = body[:per] + " …[cut]"
                    blocks.append(f"### {nm}\n{body}")
                last_obs = "\n\n".join(blocks)
                recent.append(f"parallel[{len(results)}]: "
                              + ", ".join(nm for nm, _ in results))
                stall = 0 if any_ok else stall + 1
                continue

            stall += 1
            last_obs = f"ERROR: unknown action '{kind}'."
            recent.append(f"(unknown action {kind})")

        return {
            "target": target,
            "stop_reason": stop_reason,
            "findings": self.findings,
            "evidence": self.evidence,
            "budget": self.budget,
            "cache_stats": self.registry.cache.stats,
        }
