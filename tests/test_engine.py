"""Tests for the v0.2 engine upgrades: caching, parallelism, FP guard, JSON
parsing, and the agent loop driven by a scripted fake LLM (no API key / network).
"""


from nirbhed.config import Config
from nirbhed.tools.base import ParamSpec, ToolSpec
from nirbhed.tools.registry import Registry


def _reg(tmp_path):
    cfg = Config.from_env()
    cfg.state_dir = tmp_path
    cfg.scope = []  # unrestricted for local echo/file tools in tests
    reg = Registry(cfg)
    # inject a fast, always-available deterministic tool
    reg.specs["echo_t"] = ToolSpec(
        name="echo_t", category="misc", tier="recon", binary="echo",
        desc="echo", cmd=["echo", "{target}"],
        params={"target": ParamSpec(required=True)},
    )
    return reg


def test_cache_is_actually_written_and_replayed(tmp_path):
    reg = _reg(tmp_path)
    r1 = reg.run("echo_t", {"target": "hello-cache"})
    assert r1.ok and not r1.cached
    assert "hello-cache" in r1.output
    r2 = reg.run("echo_t", {"target": "hello-cache"})
    assert r2.ok and r2.cached            # THE bug fix: second call is a hit
    assert "hello-cache" in r2.output
    assert reg.cache.stats["hits"] >= 1


def test_cache_hit_rebinds_fresh_evidence(tmp_path):
    reg = _reg(tmp_path)
    reg.run("echo_t", {"target": "ev"})
    before = len(reg.evidence.all())
    r2 = reg.run("echo_t", {"target": "ev"})
    assert r2.cached
    # evidence id in the replayed output must exist in the (now larger) store
    assert len(reg.evidence.all()) == before + 1
    ev_id = r2.output.split("]")[0].lstrip("[")
    assert reg.evidence.get(ev_id) is not None


def test_run_many_parallel_order_and_gating(tmp_path):
    reg = _reg(tmp_path)
    calls = [
        {"tool": "echo_t", "params": {"target": "a"}},
        {"tool": "does_not_exist", "params": {"target": "b"}},
        {"tool": "echo_t", "params": {"target": "c"}},
    ]
    results = reg.run_many(calls)
    assert [nm for nm, _ in results] == ["echo_t", "does_not_exist", "echo_t"]
    assert results[0][1].ok and "a" in results[0][1].output
    assert results[1][1].ok is False and "unknown tool" in results[1][1].error
    assert results[2][1].ok and "c" in results[2][1].output


def test_run_many_respects_scope(tmp_path):
    reg = _reg(tmp_path)
    reg.scope.scope = ["allowed.test"]
    results = reg.run_many([
        {"tool": "httpx", "params": {"target": "https://evil.test"}},
    ])
    assert results[0][1].ok is False
    assert "out of scope" in results[0][1].error


def test_timeouts_not_cached(tmp_path):
    reg = _reg(tmp_path)
    reg.specs["sleeper"] = ToolSpec(
        name="sleeper", category="misc", tier="recon", binary="sleep",
        desc="sleep", cmd=["sleep", "5"], timeout=1,
        params={"target": ParamSpec(default="x")},
    )
    r = reg.run("sleeper", {"target": "x"})
    assert "timed out" in r.output.lower() or r.error
    # a timed-out run must NOT be frozen in cache
    assert reg.cache.get("sleeper", {"target": "x"}) is None


# ── agent loop (scripted fake LLM) ───────────────────────────────────────────
import nirbhed.agent.loop as loop_mod
from nirbhed.llm.provider import LLMReply


class _FakeLLM:
    def __init__(self, scripts):
        self.scripts = scripts
        self.i = 0

    def __call__(self, *a, **k):  # used as the LLM class
        return self

    def chat(self, messages):
        s = self.scripts[min(self.i, len(self.scripts) - 1)]
        self.i += 1
        return LLMReply(content=s, prompt_tokens=50, completion_tokens=10)


def _run_agent(tmp_path, scripts):
    cfg = Config.from_env()
    cfg.state_dir = tmp_path
    cfg.scope = []
    fake = _FakeLLM(scripts)
    loop_mod.LLM = lambda *a, **k: fake  # bypass real provider
    agent = loop_mod.Agent(cfg, allow_gated=True)
    return agent.run("/tmp", "test")


def test_fp_guard_rejects_unproven_high(tmp_path):
    scripts = [
        '```json\n{"action":"report","finding":{"title":"RCE","severity":"critical","target":"t"}}\n```',
        '```json\n{"action":"finish","reason":"done"}\n```',
    ]
    res = _run_agent(tmp_path, scripts)
    assert res["findings"].count() == 0  # unproven critical refused


def test_fp_guard_allows_proven_high(tmp_path):
    scripts = [
        '```json\n{"action":"report","finding":{"title":"RCE","severity":"critical","target":"t","evidence_ids":["ev-1"]}}\n```',
        '```json\n{"action":"finish","reason":"done"}\n```',
    ]
    res = _run_agent(tmp_path, scripts)
    assert res["findings"].count() == 1


def test_stall_detector_stops_runaway(tmp_path):
    # always malformed -> must stop via stall limit, not spin forever
    res = _run_agent(tmp_path, ["not json at all"])
    assert "stall" in res["stop_reason"].lower()
    assert res["budget"].turns_used <= 6


def test_parallel_action_merges_results(tmp_path):
    scripts = [
        '```json\n{"action":"parallel","tools":[{"tool":"http_request","params":{"target":"http://x"}},{"tool":"python_exploit","params":{"code":"print(1)"}}]}\n```',
        '```json\n{"action":"finish","reason":"done"}\n```',
    ]
    res = _run_agent(tmp_path, scripts)
    assert res["stop_reason"] == "done"


def test_distill_never_drops_findings_under_noise_flood():
    from nirbhed.core.distill import distill
    noise = "\n".join(f"[DBG] probe {i} no-match ........" for i in range(5000))
    raw = noise + "\n[CVE-2024-9999] [critical] https://t/x matched\n22/tcp open ssh\n" + noise
    out = distill(raw, max_chars=2000)
    assert "CVE-2024-9999" in out          # finding survives the flood (the bug)
    assert "22/tcp open ssh" in out
    assert len(out) <= 2300


def test_json_parsing_variants():
    f = loop_mod._parse_action
    assert f('```json\n{"action":"finish"}\n```')["action"] == "finish"
    assert f('here you go {"action":"tool","tool":"x"} thanks')["action"] == "tool"
    assert f('prose {"a": {"nested": "}"}, "action":"finish"} end')["action"] == "finish"
    assert f("no json here") is None
    # trailing comma tolerance
    assert f('{"action":"finish",}')["action"] == "finish"
