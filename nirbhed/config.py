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
        )
        c.state_dir.mkdir(parents=True, exist_ok=True)
        return c
