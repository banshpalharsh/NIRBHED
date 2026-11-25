"""The autonomous agent: a token-frugal planner/worker ReAct loop.

Design choice for frugality: turns are (almost) STATELESS. Instead of resending a
growing transcript, each turn sends the system prompt + a COMPACT running state
(asset graph + findings brief + recent actions + last observation). The state IS
the memory. This keeps per-turn cost roughly flat instead of growing O(n), which
is what makes long runs cheap on pay-per-token models like DeepSeek.
"""

from __future__ import annotations

import json
import re

from rich.console import Console

from noctyx.agent.extract import update_graph
from noctyx.config import Config
from noctyx.core.budget import Budget
from noctyx.core.evidence import EvidenceStore
from noctyx.core.findings import Finding, FindingStore, RetestStatus
from noctyx.core.graph import AssetGraph
from noctyx.llm.prompts import SYSTEM, build_user_turn
from noctyx.llm.provider import LLM
from noctyx.tools.registry import Registry

_JSON_BLOCK = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL)
_BARE_JSON = re.compile(r"(\{.*\})", re.DOTALL)


def _parse_action(text: str) -> dict | None:
    m = _JSON_BLOCK.search(text) or _BARE_JSON.search(text)
    if not m:
        return None
    try:
        return json.loads(m.group(1))
    except json.JSONDecodeError:
        # tolerate trailing commas / minor noise
        cleaned = re.sub(r",\s*([}\]])", r"\1", m.group(1))
        try:
            return json.loads(cleaned)
        except json.JSONDecodeError:
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

    def _state(self, recent: list[str], last_obs: str) -> str:
        return (
            f"ASSET GRAPH:\n{self.graph.compact()}\n\n"
            f"FINDINGS SO FAR: {self.findings.brief()}\n\n"
            f"RECENT ACTIONS (newest last):\n" + ("\n".join(recent[-6:]) or "-") + "\n\n"
            f"LAST RESULT:\n{last_obs or '-'}\n\n"
            f"BUDGET: {self.budget.summary()}"
        )

    def run(self, target: str, objective: str) -> dict:
        self.graph.add_root(target.split("://")[-1].split("/")[0])
        catalog = self.registry.catalog_signature(only_available=True)
        recent: list[str] = []
        last_obs = "(none — begin with reconnaissance)"
        stop_reason = "completed"

        self.console.print(f"[bold cyan]noctyx[/] target=[yellow]{target}[/] "
                           f"tools={len(self.registry.available())}")

        while True:
            over = self.budget.exceeded()
            if over:
                stop_reason = over
                break
            self.budget.tick_turn()

            messages = [
                {"role": "system", "content": SYSTEM},
                {"role": "user",
                 "content": build_user_turn(target, objective, catalog,
                                            self._state(recent, last_obs))},
            ]
            try:
                reply = self.llm.chat(messages)
            except Exception as e:  # noqa: BLE001
                stop_reason = f"llm error: {e}"
                break
            self.budget.add_tokens(reply.total_tokens)

            action = _parse_action(reply.content)
            if not action:
                last_obs = "ERROR: your previous reply was not valid JSON. Reply with one json block."
                recent.append("(malformed reply)")
                continue

            kind = action.get("action")
            thought = action.get("thought", "")
            self.console.print(f"[dim]t{self.budget.turns_used}[/] [green]{kind}[/] {thought}")

            if kind == "finish":
                stop_reason = action.get("reason", "agent finished")
                break

            if kind == "report":
                f = action.get("finding", {})
                finding = Finding(
                    title=f.get("title", "untitled"),
                    severity=f.get("severity", "info"),
                    target=f.get("target", target),
                    description=f.get("description", ""),
                    owasp=f.get("owasp", ""),
                    cwe=f.get("cwe", ""),
                    cvss=float(f.get("cvss", 0) or 0),
                    evidence_ids=f.get("evidence_ids", []) or [],
                    repro=f.get("repro", ""),
                    remediation=f.get("remediation", ""),
                    status=RetestStatus.REPRODUCIBLE if f.get("evidence_ids")
                    else RetestStatus.UNVERIFIED,
                )
                is_new = self.findings.add(finding)
                last_obs = (f"finding {'recorded' if is_new else 'merged (duplicate)'}: "
                            f"[{finding.severity}] {finding.title}")
                recent.append(f"report: {finding.title}")
                continue

            if kind == "tool":
                name = action.get("tool", "")
                params = action.get("params", {}) or {}
                res = self.registry.run(name, params, allow_gated=self.allow_gated)
                tgt = params.get("target", target)
                if res.ok:
                    update_graph(self.graph, target.split("://")[-1].split("/")[0], res.output)
                    self.graph.mark_tested(tgt)
                last_obs = res.output if res.ok else f"TOOL ERROR ({name}): {res.error}"
                tag = "cached" if res.cached else ("ok" if res.ok else "err")
                recent.append(f"{name}({params.get('target','')}) -> {tag}")
                continue

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
