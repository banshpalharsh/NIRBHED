"""Offline smoke tests — no network, no external binaries required."""

from pathlib import Path

from nirbhed.config import Config
from nirbhed.core.cache import ResultCache
from nirbhed.core.distill import distill
from nirbhed.core.findings import Finding, FindingStore
from nirbhed.core.scope import TIER_EXPLOIT, TIER_RECON, ScopeGate
from nirbhed.tools.base import ParamSpec, ToolSpec
from nirbhed.tools.registry import Registry


def test_distill_strips_noise_and_caps():
    raw = "\n".join(["banner ****"] + ["progress 50%"] * 10 +
                    ["80/tcp open http", "443/tcp open https"] + ["blah"] * 200)
    out = distill(raw, max_chars=200)
    assert "80/tcp open http" in out
    assert "443/tcp open https" in out
    assert len(out) <= 300  # cap + annotations
    assert "elided" in out or "truncated" in out


def test_distill_empty():
    assert distill("") == "(no output)"


def test_cache_roundtrip(tmp_path: Path):
    c = ResultCache(tmp_path, enabled=True)
    assert c.get("nmap", {"target": "x"}) is None
    c.put("nmap", {"target": "x"}, "result-data")
    assert c.get("nmap", {"target": "x"}) == "result-data"
    assert c.stats["hits"] == 1


def test_scope_gate():
    g = ScopeGate(scope=["example.com", "*.example.com"], deny=["admin.example.com"],
                  approval="balanced")
    assert g.in_scope("https://api.example.com/x") is True
    assert g.in_scope("https://evil.com") is False
    assert g.in_scope("https://admin.example.com") is False
    ok, _ = g.check("https://example.com", TIER_RECON)
    assert ok is True
    ok, reason = g.check("https://example.com", TIER_EXPLOIT)
    assert ok is False and "approval" in reason


def test_findings_dedup_and_severity_merge():
    fs = FindingStore()
    assert fs.add(Finding("SQLi", "high", "t", cwe="CWE-89")) is True
    # same fingerprint, higher severity -> merged, severity upgraded
    assert fs.add(Finding("SQLi", "critical", "t", cwe="CWE-89")) is False
    assert fs.count() == 1
    assert fs.all()[0].severity == "critical"


def test_tool_render_is_argv_safe():
    spec = ToolSpec(
        name="t", category="web", tier="active", binary="echo",
        desc="d", cmd=["echo", "{target}", "{extra}"],
        params={"target": ParamSpec(required=True), "extra": ParamSpec()},
    )
    argv, err = spec.render({"target": "a; rm -rf /", "extra": "-x 1"})
    assert err == ""
    # the malicious ';' stays inside a single argv element — no shell parsing
    assert argv == ["echo", "a; rm -rf /", "-x", "1"]


def test_registry_loads_catalog():
    reg = Registry(Config.from_env())
    # built-ins are always present
    assert "http_request" in reg.specs
    assert "python_exploit" in reg.specs
    # catalog entries loaded from yaml
    assert "nmap_quick" in reg.specs
    assert len(reg.specs) > 40
    sig = reg.catalog_signature(only_available=True)
    assert "http_request" in sig  # built-in always available
