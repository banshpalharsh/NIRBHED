"""Central configuration. Read from environment, overridable by CLI flags.

One config object drives both front-ends (MCP server and standalone agent) so
behaviour — scope, budgets, caching, distillation — is identical either way.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _env(key: str, default: str | None = None) -> str | None:
    val = os.environ.get(key)
    return val if val not in (None, "") else default


def _env_int(key: str, default: int) -> int:
    raw = _env(key)
    try:
        return int(raw) if raw is not None else default
    except ValueError:
        return default


def _split(value: str | None) -> list[str]:
    if not value:
        return []
    return [p.strip() for p in value.split(",") if p.strip()]


def _parse_headers(value: str | None) -> dict:
    """Parse 'Key: Value' pairs separated by newlines (CLI joins --header with \\n)."""
    out: dict[str, str] = {}
    if not value:
        return out
    for line in value.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            if k.strip():
                out[k.strip()] = v.strip()
    return out


@dataclass
class ProviderConfig:
    """An OpenAI-compatible LLM endpoint. Works for DeepSeek, OpenAI, OpenRouter,
    Together, Groq, Ollama, and Anthropic's OpenAI-compatible endpoint."""

    api_key: str | None = None
    base_url: str | None = None
    model: str | None = None

    @property
    def usable(self) -> bool:
        return bool(self.api_key and self.model)


@dataclass
class AuthContext:
    """Credentials the agent uses to test AUTHENTICATED surface. Secrets are
    applied at the HTTP layer and exposed to PoCs as env vars — they are NOT put
    into the LLM context (the agent is only told auth 'is configured'), which is
    both safer and cheaper on tokens."""

    headers: dict[str, str] = field(default_factory=dict)  # extra request headers
    cookie: str = ""                                        # raw Cookie header value
    bearer: str = ""                                        # Authorization: Bearer <t>
    basic: str = ""                                         # "user:pass" -> Basic auth

    @property
    def configured(self) -> bool:
        return bool(self.headers or self.cookie or self.bearer or self.basic)

    def header_map(self) -> dict[str, str]:
        """Resolved headers to attach to a request (explicit request headers win)."""
        import base64

        out = dict(self.headers)
        if self.cookie:
            out.setdefault("Cookie", self.cookie)
        if self.bearer:
            out.setdefault("Authorization", f"Bearer {self.bearer}")
        elif self.basic:
            token = base64.b64encode(self.basic.encode()).decode()
            out.setdefault("Authorization", f"Basic {token}")
        return out

    def env(self) -> dict[str, str]:
        """Exposed to python_exploit PoCs so they can authenticate."""
        e = {}
        if self.cookie:
            e["NIRBHED_COOKIE"] = self.cookie
        if self.bearer:
            e["NIRBHED_BEARER"] = self.bearer
        if self.basic:
            e["NIRBHED_BASIC"] = self.basic
        for k, v in self.headers.items():
            e[f"NIRBHED_HDR_{k.upper().replace('-', '_')}"] = v
        return e

    def masked(self) -> dict[str, str]:
        """For the viewer: show what's set without leaking the value."""
        def m(v: str) -> str:
            return (v[:4] + "…" + v[-2:]) if len(v) > 8 else "set"
        out = {}
        if self.cookie:
            out["cookie"] = m(self.cookie)
        if self.bearer:
            out["bearer"] = m(self.bearer)
        if self.basic:
            out["basic"] = self.basic.split(":", 1)[0] + ":***"
        for k in self.headers:
            out[k] = "set"
        return out


@dataclass
class Config:
    # LLM (standalone agent mode only; MCP mode ignores these)
    primary: ProviderConfig = field(default_factory=ProviderConfig)
    fallback: ProviderConfig = field(default_factory=ProviderConfig)

    # Budgets — hard stops. A run can never exceed these.
    max_tokens: int = 120_000
    max_turns: int = 40
    max_seconds: int = 1800

    # Token frugality
    distill_max_chars: int = 2000
    cache: bool = True

    # Safety / governance
    scope: list[str] = field(default_factory=list)       # allowed host globs
    deny: list[str] = field(default_factory=list)         # always-blocked host globs
    approval: str = "balanced"                            # quiet | balanced | aggressive

    # Authenticated testing
    auth: AuthContext = field(default_factory=AuthContext)

    # Paths
    workdir: Path = field(default_factory=lambda: Path(os.getcwd()))
    state_dir: Path = field(default_factory=lambda: Path(os.getcwd()) / ".nirbhed")

    @classmethod
    def from_env(cls) -> Config:
        c = cls(
            primary=ProviderConfig(
                api_key=_env("NIRBHED_API_KEY"),
                base_url=_env("NIRBHED_BASE_URL", "https://api.deepseek.com"),
                model=_env("NIRBHED_MODEL", "deepseek-chat"),
            ),
            fallback=ProviderConfig(
                api_key=_env("NIRBHED_FALLBACK_API_KEY"),
                base_url=_env("NIRBHED_FALLBACK_BASE_URL"),
                model=_env("NIRBHED_FALLBACK_MODEL"),
            ),
            max_tokens=_env_int("NIRBHED_MAX_TOKENS", 120_000),
            max_turns=_env_int("NIRBHED_MAX_TURNS", 40),
            max_seconds=_env_int("NIRBHED_MAX_SECONDS", 1800),
            distill_max_chars=_env_int("NIRBHED_DISTILL_MAX_CHARS", 2000),
            cache=_env("NIRBHED_CACHE", "1") != "0",
            scope=_split(_env("NIRBHED_SCOPE")),
            deny=_split(_env("NIRBHED_DENY")),
            approval=_env("NIRBHED_APPROVAL", "balanced") or "balanced",
            auth=AuthContext(
                headers=_parse_headers(_env("NIRBHED_HEADERS")),
                cookie=_env("NIRBHED_COOKIE", "") or "",
                bearer=_env("NIRBHED_BEARER", "") or "",
                basic=_env("NIRBHED_BASIC", "") or "",
            ),
        )
        c.state_dir.mkdir(parents=True, exist_ok=True)
        return c
