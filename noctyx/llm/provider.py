"""LLM access via any OpenAI-compatible endpoint, with automatic failover.

Works with DeepSeek, OpenAI, OpenRouter, Together, Groq, Ollama, and Anthropic's
OpenAI-compatible endpoint — just point base_url + model. Pick the cheapest.
Only imported in standalone agent mode; MCP mode never touches this.
"""

from __future__ import annotations

from dataclasses import dataclass

from noctyx.config import ProviderConfig


@dataclass
class LLMReply:
    content: str
    prompt_tokens: int
    completion_tokens: int

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens


class LLM:
    """Thin wrapper. Tries primary, falls back to secondary on error/ratelimit."""

    def __init__(self, primary: ProviderConfig, fallback: ProviderConfig | None = None,
                 temperature: float = 0.2):
        try:
            from openai import OpenAI
        except ImportError as e:  # pragma: no cover
            raise RuntimeError(
                "Standalone agent mode needs the OpenAI client. "
                "Install with: pip install 'noctyx[agent]'"
            ) from e

        if not primary.usable:
            raise RuntimeError(
                "No usable LLM provider. Set NOCTYX_API_KEY + NOCTYX_MODEL "
                "(and NOCTYX_BASE_URL for non-OpenAI endpoints)."
            )
        self._OpenAI = OpenAI
        self.temperature = temperature
        self.primary = primary
        self.fallback = fallback if (fallback and fallback.usable) else None
        self._clients: dict[str, object] = {}

    def _client(self, cfg: ProviderConfig):
        key = f"{cfg.base_url}|{cfg.api_key}"
        if key not in self._clients:
            kwargs = {"api_key": cfg.api_key}
            if cfg.base_url:
                kwargs["base_url"] = cfg.base_url
            self._clients[key] = self._OpenAI(**kwargs)
        return self._clients[key]

    def _call(self, cfg: ProviderConfig, messages: list[dict]) -> LLMReply:
        client = self._client(cfg)
        resp = client.chat.completions.create(
            model=cfg.model,
            messages=messages,
            temperature=self.temperature,
        )
        usage = resp.usage
        return LLMReply(
            content=resp.choices[0].message.content or "",
            prompt_tokens=getattr(usage, "prompt_tokens", 0) or 0,
            completion_tokens=getattr(usage, "completion_tokens", 0) or 0,
        )

    def chat(self, messages: list[dict]) -> LLMReply:
        try:
            return self._call(self.primary, messages)
        except Exception as primary_err:
            if not self.fallback:
                raise
            try:
                return self._call(self.fallback, messages)
            except Exception as fb_err:
                raise RuntimeError(
                    f"both providers failed: primary={primary_err}; fallback={fb_err}"
                ) from fb_err
