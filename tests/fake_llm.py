"""Scripted stand-in for the LLM so the agent loop can be tested offline and deterministically."""

from __future__ import annotations

import itertools
from collections.abc import Callable
from typing import Any

from audit_agent.llm import LLMResponse, ToolCall

_ids = itertools.count(1)


def call(name: str, **args: Any) -> ToolCall:
    return ToolCall(id=f"toolu_{next(_ids)}", name=name, input=args)


def respond(*calls: ToolCall, text: str = "", stop_reason: str | None = None) -> LLMResponse:
    content: list[dict[str, Any]] = []
    if text:
        content.append({"type": "text", "text": text})
    content += [{"type": "tool_use", "id": c.id, "name": c.name, "input": c.input} for c in calls]
    return LLMResponse(stop_reason=stop_reason or ("tool_use" if calls else "end_turn"), content=content,
                       tool_calls=list(calls), text=text,
                       usage={"input_tokens": 10, "output_tokens": 5, "cache_read_input_tokens": 0,
                              "cache_creation_input_tokens": 0})


def last_tool_results(messages: list[dict[str, Any]]) -> list[str]:
    """Tool-result strings the agent sent back in the latest user message."""
    content = messages[-1]["content"]
    if isinstance(content, str):
        return [content]
    return [b["content"] for b in content if b.get("type") == "tool_result"]


class FakeLLM:
    """Each step is either a fixed LLMResponse or a callable(messages) -> LLMResponse (to react to tool output)."""

    model = "fake-model"

    def __init__(self, steps: list[LLMResponse | Callable[[list[dict[str, Any]]], LLMResponse]]):
        self.steps = list(steps)
        self.calls: list[list[dict[str, Any]]] = []
        self.tool_names_offered: list[str] = []

    def create(self, system: str, tools: list[dict[str, Any]], messages: list[dict[str, Any]]) -> LLMResponse:
        self.calls.append(list(messages))
        self.tool_names_offered = [t["name"] for t in tools]
        if not self.steps:
            return respond(text="nothing more to say")
        step = self.steps.pop(0)
        return step(messages) if callable(step) else step


FULL_COVERAGE = {c: "checked" for c in [
    "repository_hygiene", "dependency_management", "code_quality", "testing", "ci_cd", "security",
    "configuration", "collaboration", "build_release"]}
