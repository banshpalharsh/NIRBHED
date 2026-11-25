"""Tests for v0.3 live features: auth injection, operator inbox/state, viewer."""

import json
import urllib.request

import nirbhed.tools.builtins as builtins_mod
from nirbhed.config import AuthContext, Config
from nirbhed.core.session import Inbox, RunState
from nirbhed.tools.registry import Registry


# ── auth ─────────────────────────────────────────────────────────────────────
def test_auth_header_map_bearer_cookie_headers():
    a = AuthContext(headers={"X-API-Key": "k"}, cookie="sid=1", bearer="tok")
    h = a.header_map()
    assert h["Cookie"] == "sid=1"
    assert h["Authorization"] == "Bearer tok"
    assert h["X-API-Key"] == "k"


def test_auth_basic_encodes():
    a = AuthContext(basic="user:pass")
    assert a.header_map()["Authorization"].startswith("Basic ")


def test_auth_masked_hides_secrets():
    a = AuthContext(cookie="supersecretvalue", bearer="tok")
    m = a.masked()
    assert "supersecretvalue" not in json.dumps(m)
    assert "cookie" in m


def test_registry_injects_auth_into_http_request(tmp_path, monkeypatch):
    captured = {}

    def fake_http(params):
        captured.update(params)
        return "ok", 0

    monkeypatch.setitem(builtins_mod.BUILTIN_RUNNERS, "http_request", fake_http)
    cfg = Config.from_env()
    cfg.state_dir = tmp_path
    cfg.scope = []
    cfg.auth = AuthContext(cookie="sid=42", bearer="abc")
    reg = Registry(cfg)
    reg.run("http_request", {"target": "http://x"}, allow_gated=True)
    assert captured["_auth"]["Cookie"] == "sid=42"
    assert captured["_auth"]["Authorization"] == "Bearer abc"


def test_python_exploit_receives_auth_env(tmp_path):
    cfg = Config.from_env()
    cfg.state_dir = tmp_path
    cfg.scope = []
    cfg.auth = AuthContext(cookie="sid=from-env")
    reg = Registry(cfg)
    res = reg.run("python_exploit",
                  {"code": "import os;print('COOKIE=' + os.environ.get('NIRBHED_COOKIE','none'))"},
                  allow_gated=True)
    assert "COOKIE=sid=from-env" in res.output


# ── inbox / state ────────────────────────────────────────────────────────────
def test_inbox_push_drain_pause_stop():
    ib = Inbox()
    ib.push("focus on /api")
    ib.push("")  # ignored
    assert ib.drain() == ["focus on /api"]
    assert ib.drain() == []
    ib.set_pause(True)
    assert ib.paused
    ib.set_pause(False)
    assert not ib.paused
    ib.request_stop()
    assert ib.stopping


def test_runstate_snapshot_and_persist(tmp_path):
    st = RunState("r1", "t", "obj")
    st.bind_persist(tmp_path / "runs" / "r1" / "state.json")
    st.log_line("hello")
    st.set_findings([{"severity": "high", "title": "X", "target": "t"}])
    snap = st.snapshot()
    assert snap["target"] == "t" and snap["findings"][0]["title"] == "X"
    assert (tmp_path / "runs" / "r1" / "state.json").exists()


# ── agent honors operator stop ───────────────────────────────────────────────
import nirbhed.agent.loop as loop_mod
from nirbhed.llm.provider import LLMReply


def test_agent_stops_on_operator_signal(tmp_path):
    class Fake:
        def chat(self, m):
            return LLMReply('```json\n{"action":"tool","tool":"http_request","params":{"target":"http://x"}}\n```', 10, 2)

    loop_mod.LLM = lambda *a, **k: Fake()
    cfg = Config.from_env()
    cfg.state_dir = tmp_path
    cfg.scope = []
    ib = Inbox()
    ib.request_stop()  # stop before the first turn
    agent = loop_mod.Agent(cfg, allow_gated=True, inbox=ib)
    res = agent.run("http://x", "test")
    assert res["stop_reason"] == "stopped by operator"
    assert res["budget"].turns_used == 0


def test_agent_absorbs_operator_directive(tmp_path):
    class Fake:
        def __init__(self):
            self.n = 0

        def chat(self, m):
            self.n += 1
            if self.n == 1:
                return LLMReply('```json\n{"action":"tool","tool":"http_request","params":{"target":"http://x"}}\n```', 10, 2)
            return LLMReply('```json\n{"action":"finish","reason":"done"}\n```', 10, 2)

    loop_mod.LLM = lambda *a, **k: Fake()
    cfg = Config.from_env()
    cfg.state_dir = tmp_path
    cfg.scope = []
    ib = Inbox()
    ib.push("skip bruteforce, focus on IDOR")
    agent = loop_mod.Agent(cfg, allow_gated=True, inbox=ib)
    agent.run("http://x", "test")
    assert any("IDOR" in d for d in agent.directives)


# ── viewer HTTP ──────────────────────────────────────────────────────────────
def test_viewer_serves_state_and_accepts_chat():
    from nirbhed.viewer.server import start_viewer

    ib = Inbox()
    state = {"target": "demo", "status": "running", "findings": [], "log": []}
    srv, port = start_viewer(lambda: state, inbox=ib, port=8900)
    try:
        body = urllib.request.urlopen(f"http://127.0.0.1:{port}/api/state", timeout=3).read()
        assert json.loads(body)["target"] == "demo"
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/chat",
            data=json.dumps({"message": "hello agent"}).encode(),
            method="POST")
        urllib.request.urlopen(req, timeout=3).read()
        assert ib.drain() == ["hello agent"]
        html = urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=3).read()
        assert b"NIRBHED" in html
    finally:
        srv.shutdown()
