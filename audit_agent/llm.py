"""Thin LLM interaction layer (Anthropic Messages API, tool use).

Only the provider SDK is used - no agent framework. The agent loop in
``audit_agent.loop`` talks to any object implementing :class:`LLMClient`,
which also makes the loop testable with a scripted fake model.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

import anthropic

DEFAULT_MODEL = "claude-opus-5-5"
FALLBACK_BETA = "server-side-fallback-2026-07-01"
# Models that accept the server-side `fallbacks: "default"` refusal fallback.
FALLBACK_MODELS = ("claude-opus-5-5", "claude-opus-5", "claude-fable-5-1", "claude-sonnet-5-5")


class LLMError(Exception):
    """Fatal error talking to the LLM provider (after the SDK's own retries)."""


@dataclass
class ToolCall:
    id: str
    name: str
    input: dict[str, Any]


@dataclass
class LLMResponse:
    stop_reason: str
    content: list[Any]                      # raw assistant content, appended unchanged to history
    tool_calls: list[ToolCall]
    text: str
    usage: dict[str, int] = field(default_factory=dict)
    model: str | None = None


class LLMClient(Protocol):
    model: str

    def create(self, system: str, tools: list[dict[str, Any]], messages: list[dict[str, Any]]) -> LLMResponse: ...


def _block_to_dict(block: Any) -> dict[str, Any]:
    if isinstance(block, dict):
        return block
    if hasattr(block, "model_dump"):
        return block.model_dump(exclude_none=True)
    return {"type": getattr(block, "type", "unknown")}


def content_for_trace(content: list[Any]) -> list[dict[str, Any]]:
    out = []
    for b in content:
        d = _block_to_dict(b)
        if d.get("type") in ("thinking", "redacted_thinking"):
            out.append({"type": d["type"], "summary": (d.get("thinking") or "")[:2000]})
        else:
            out.append(d)
    return out


def parse_response(resp: Any) -> LLMResponse:
    calls, texts = [], []
    for block in resp.content:
        btype = getattr(block, "type", None) if not isinstance(block, dict) else block.get("type")
        if btype == "tool_use":
            fields = block if isinstance(block, dict) else {k: getattr(block, k) for k in ("id", "name", "input")}
            raw_input = fields.get("input")
            calls.append(ToolCall(id=fields["id"], name=fields["name"],
                                  input=raw_input if isinstance(raw_input, dict) else {}))
        elif btype == "text":
            texts.append(block.get("text") if isinstance(block, dict) else block.text)
    usage: dict[str, int] = {}
    u = getattr(resp, "usage", None)
    if u is not None:
        for key in ("input_tokens", "output_tokens", "cache_creation_input_tokens", "cache_read_input_tokens"):
            val = u.get(key) if isinstance(u, dict) else getattr(u, key, None)
            usage[key] = int(val or 0)
    return LLMResponse(
        stop_reason=str(getattr(resp, "stop_reason", None) or (resp.get("stop_reason") if isinstance(resp, dict) else "")),
        content=list(resp.content),
        tool_calls=calls,
        text="\n".join(t for t in texts if t),
        usage=usage,
        model=getattr(resp, "model", None),
    )


class AnthropicLLM:
    """Claude via the official ``anthropic`` SDK, with prompt caching and refusal fallback."""

    def __init__(self, api_key: str, model: str = DEFAULT_MODEL, effort: str | None = "medium",
                 max_tokens: int = 16000, timeout: float = 300.0, max_retries: int = 4):
        if not api_key:
            raise LLMError("No Anthropic API key configured (set ANTHROPIC_API_KEY in the environment or .env).")
        self.model = model
        self.effort = effort or None
        self.max_tokens = max_tokens
        self.use_fallbacks = model in FALLBACK_MODELS
        self.client = anthropic.Anthropic(api_key=api_key, timeout=timeout, max_retries=max_retries)

    def _request(self, system: str, tools: list[dict[str, Any]], messages: list[dict[str, Any]]) -> Any:
        kwargs: dict[str, Any] = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "system": [{"type": "text", "text": system}],
            "tools": tools,
            "messages": messages,
            "cache_control": {"type": "ephemeral"},   # automatic incremental prompt caching
        }
        if self.effort:
            kwargs["output_config"] = {"effort": self.effort}
        if self.use_fallbacks:
            kwargs["betas"] = [FALLBACK_BETA]
            kwargs["fallbacks"] = "default"
        return self.client.beta.messages.create(**kwargs)

    def create(self, system: str, tools: list[dict[str, Any]], messages: list[dict[str, Any]]) -> LLMResponse:
        try:
            try:
                resp = self._request(system, tools, messages)
            except anthropic.BadRequestError as exc:
                msg = str(exc).lower()
                # Degrade gracefully if this account/model rejects an optional feature.
                if self.use_fallbacks and "fallback" in msg:
                    self.use_fallbacks = False
                elif self.effort and "effort" in msg:
                    self.effort = None
                else:
                    raise
                resp = self._request(system, tools, messages)
        except anthropic.AuthenticationError as exc:
            raise LLMError("Anthropic API rejected the API key (authentication failed).") from exc
        except anthropic.PermissionDeniedError as exc:
            raise LLMError(f"API key lacks permission for model {self.model}.") from exc
        except anthropic.NotFoundError as exc:
            raise LLMError(f"Model {self.model!r} not found; set LLM_MODEL to a valid model id.") from exc
        except anthropic.RateLimitError as exc:
            raise LLMError("Rate limited by the Anthropic API after several retries; try again later.") from exc
        except anthropic.BadRequestError as exc:
            raise LLMError(f"Anthropic API rejected the request: {getattr(exc, 'message', exc)}") from exc
        except anthropic.APITimeoutError as exc:
            raise LLMError("Anthropic API request timed out after retries.") from exc
        except anthropic.APIConnectionError as exc:
            raise LLMError(f"Could not connect to the Anthropic API: {exc}") from exc
        except anthropic.APIStatusError as exc:
            raise LLMError(f"Anthropic API error {exc.status_code}: {getattr(exc, 'message', exc)}") from exc
        return parse_response(resp)
