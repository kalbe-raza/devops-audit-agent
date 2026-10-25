"""The explicit agent loop: observe -> reason -> select tool -> execute -> interpret -> report.

The LLM chooses every inspection tool call. The controller here only executes
the chosen tools, validates recorded findings against the repository, enforces
budgets, and runs a coverage check plus one self-review pass before finishing.
The conversation history is append-only (never edited), which keeps the prompt
cache warm and preserves the model's reasoning across turns.
"""

from __future__ import annotations

import json
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, TextIO

from audit_agent import prompts
from audit_agent.llm import LLMClient, LLMResponse, ToolCall, content_for_trace
from audit_agent.redact import redact_text, scrub_known
from audit_agent.report import ValidationError, Violation, build_report, build_violation, normalise_category
from audit_agent.rules import CATEGORIES, SEVERITIES
from tools import TOOL_SPECS, RepoTools, ToolError, build_dispatch

AGENT_TOOL_SPECS: list[dict[str, Any]] = [
    {
        "name": "record_violation",
        "description": "Record one verified DevOps violation for the final report. Returns an id (V1, V2, ...) or a "
                       "validation error to fix (e.g. unknown file, line out of range).",
        "input_schema": {
            "type": "object",
            "properties": {
                "rule_id": {"type": "string", "description": "Catalogue id such as SEC-001."},
                "category": {"type": "string", "enum": CATEGORIES},
                "severity": {"type": "string", "enum": SEVERITIES},
                "file": {"type": ["string", "null"], "description": "Repo-relative path, or null."},
                "line": {"type": ["integer", "null"], "description": "1-based line seen in tool output, or null."},
                "description": {"type": "string"},
                "evidence": {"type": "string", "description": "Concrete facts observed; never secret values."},
                "recommendation": {"type": "string"},
            },
            "required": ["rule_id", "category", "severity", "file", "line", "description", "evidence",
                         "recommendation"],
        },
    },
    {
        "name": "withdraw_violation",
        "description": "Withdraw a previously recorded violation (wrong, unsupported or duplicate).",
        "input_schema": {"type": "object", "properties": {
            "id": {"type": "string"}, "reason": {"type": "string"}}, "required": ["id", "reason"]},
    },
    {
        "name": "finish_audit",
        "description": "Finish the investigation. First call: summary + coverage note per category (what you checked "
                       "or why not applicable); you then get a self-review step. Final call: confirm=true.",
        "input_schema": {"type": "object", "properties": {
            "summary": {"type": "string"},
            "coverage": {"type": "object", "description": "Map of category -> short note of what was checked.",
                         "additionalProperties": {"type": "string"}},
            "confirm": {"type": "boolean"}}, "required": ["summary"]},
    },
]


@dataclass
class AuditResult:
    report: dict[str, Any]
    completed: bool
    steps: int
    tool_calls: int
    usage: dict[str, int]
    summary: str = ""
    notes: list[str] = field(default_factory=list)


class TraceWriter:
    """JSON-lines trace of every LLM turn and tool call (secrets redacted)."""

    def __init__(self, path: str | None):
        self.path = path
        self._fh: TextIO | None = open(path, "w", encoding="utf-8") if path else None
        self._t0 = time.monotonic()

    def event(self, kind: str, **data: Any) -> None:
        if not self._fh:
            return
        rec = {"t": round(time.monotonic() - self._t0, 2), "event": kind, **data}
        line = json.dumps(rec, default=str, ensure_ascii=False)
        self._fh.write(scrub_known(line) + "\n")
        self._fh.flush()

    def close(self) -> None:
        if self._fh:
            self._fh.close()
            self._fh = None


def _short(args: dict[str, Any]) -> str:
    s = ", ".join(f"{k}={json.dumps(v)[:60]}" for k, v in args.items() if k not in ("evidence", "recommendation"))
    return s[:160]


class AuditAgent:
    def __init__(self, llm: LLMClient, tools: RepoTools, repo_url: str, max_steps: int = 40,
                 max_tool_output_chars: int = 10000, deadline_seconds: float = 1800,
                 trace: TraceWriter | None = None, log: Callable[[str], None] | None = None,
                 enable_pytest: bool = True):
        self.llm = llm
        self.tools = tools
        self.repo_url = repo_url
        self.max_steps = max(5, max_steps)
        self.max_chars = max(2000, max_tool_output_chars)
        self.deadline = time.monotonic() + deadline_seconds
        self.trace = trace or TraceWriter(None)
        self.log = log or (lambda msg: print(msg, file=sys.stderr))
        self.dispatch = build_dispatch(tools)
        specs = [s for s in TOOL_SPECS if enable_pytest or s["name"] != "run_pytest"]
        if not enable_pytest:
            self.dispatch.pop("run_pytest", None)
        self.tool_specs = specs + AGENT_TOOL_SPECS
        self.violations: dict[str, Violation] = {}
        self._next_id = 1
        self.finished = False
        self.review_done = False
        self.coverage_rejected = False
        self.summary = ""
        self.usage = {"input_tokens": 0, "output_tokens": 0, "cache_creation_input_tokens": 0,
                      "cache_read_input_tokens": 0}
        self.tool_call_count = 0
        self.steps_used = 0

    # ------------------------------------------------------------------ agent-level tools
    def _record(self, args: dict[str, Any]) -> str:
        v = build_violation(args, self.tools.file_exists, self.tools.line_count)
        for vid, existing in self.violations.items():
            if (existing.rule_id, existing.file, existing.line) == (v.rule_id, v.file, v.line):
                raise ValidationError(f"duplicate of {vid} (same rule_id/file/line); withdraw {vid} first to replace it")
        vid = f"V{self._next_id}"
        self._next_id += 1
        self.violations[vid] = v
        return f"recorded {vid}: {v.rule_id} {v.severity} {v.file}:{v.line}"

    def _withdraw(self, args: dict[str, Any]) -> str:
        vid = str(args.get("id", "")).strip().upper()
        if vid not in self.violations:
            raise ValidationError(f"no recorded violation with id {vid!r}; recorded: {sorted(self.violations)}")
        del self.violations[vid]
        return f"withdrawn {vid} ({str(args.get('reason', ''))[:100]})"

    def _findings_text(self) -> str:
        if not self.violations:
            return "(none recorded)"
        return "\n".join(f"{vid}: [{v.severity}] {v.rule_id} {v.category} {v.file}:{v.line} - {v.description} | "
                         f"evidence: {v.evidence[:300]}" for vid, v in self.violations.items())

    def _finish(self, args: dict[str, Any], remaining: int) -> str:
        self.summary = str(args.get("summary", ""))[:2000]
        coverage = args.get("coverage") or {}
        covered = {normalise_category(k) for k in coverage} if isinstance(coverage, dict) else set()
        missing = [] if self.review_done else [c for c in CATEGORIES if c not in covered]
        if missing and not self.coverage_rejected and remaining > 3:
            self.coverage_rejected = True
            raise ValidationError(
                "coverage notes missing for categories: " + ", ".join(missing) +
                ". Investigate them if you have not (or state why not applicable) and call finish_audit again "
                "with a coverage note for every category.")
        if not self.review_done and remaining > 1:
            self.review_done = True
            return prompts.self_review_message(self._findings_text())
        self.finished = True
        return f"audit finished with {len(self.violations)} violation(s)."

    # ------------------------------------------------------------------ execution
    def _execute(self, call: ToolCall, remaining: int) -> tuple[str, bool]:
        name, args = call.name, call.input or {}
        try:
            if name == "record_violation":
                return self._record(args), False
            if name == "withdraw_violation":
                return self._withdraw(args), False
            if name == "finish_audit":
                return self._finish(args, remaining), False
            fn = self.dispatch.get(name)
            if fn is None:
                return f"unknown tool {name!r}; available: {sorted(self.dispatch) + ['record_violation', 'withdraw_violation', 'finish_audit']}", True
            try:
                out = fn(**args)
            except TypeError as exc:
                spec = next((s for s in self.tool_specs if s["name"] == name), {})
                params = list(spec.get("input_schema", {}).get("properties", {}))
                return f"invalid arguments for {name}: {exc}. Accepted parameters: {params}", True
            out = redact_text(out)
            if len(out) > self.max_chars:
                out = out[: self.max_chars] + (f"\n[output truncated at {self.max_chars} chars; narrow the query "
                                               "(path, path_glob, line range) to see more]")
            return out, False
        except ValidationError as exc:
            return f"rejected: {exc}", True
        except ToolError as exc:
            return f"tool error: {exc}", True
        except Exception as exc:  # a tool bug must not kill the audit; the agent is told the check failed
            return f"tool {name} failed unexpectedly ({type(exc).__name__}: {str(exc)[:200]}); treat as unavailable", True

    def _account(self, resp: LLMResponse) -> None:
        for k in self.usage:
            self.usage[k] += int(resp.usage.get(k, 0))

    def run(self) -> AuditResult:
        notes: list[str] = []
        co = self.tools.checkout
        messages: list[dict[str, Any]] = [{
            "role": "user",
            "content": prompts.initial_user_message(self.repo_url, co.default_branch, co.head_commit, co.commit_count,
                                                    co.shallow, len(self.tools.tracked_files()), self.max_steps),
        }]
        self.trace.event("start", repo=self.repo_url, model=getattr(self.llm, "model", None),
                         max_steps=self.max_steps, tools=[s["name"] for s in self.tool_specs])
        idle_turns = 0
        completed = False
        for step in range(1, self.max_steps + 1):
            self.steps_used = step
            if time.monotonic() > self.deadline:
                notes.append("time budget exhausted before the agent finished")
                break
            remaining = self.max_steps - step
            resp = self.llm.create(prompts.SYSTEM_PROMPT, self.tool_specs, messages)
            self._account(resp)
            self.trace.event("llm_response", step=step, stop_reason=resp.stop_reason, usage=resp.usage,
                             text=redact_text(resp.text, remember=False)[:4000], content=content_for_trace(resp.content),
                             tool_calls=[{"id": c.id, "name": c.name, "input": c.input} for c in resp.tool_calls])
            if resp.text.strip():
                self.log(f"[step {step}] thinking aloud: {resp.text.strip().splitlines()[0][:150]}")
            messages.append({"role": "assistant", "content": resp.content})

            if resp.stop_reason == "refusal":
                notes.append("model declined to continue (refusal); report contains findings recorded so far")
                self.trace.event("refusal", step=step)
                break
            if not resp.tool_calls:
                idle_turns += 1
                if idle_turns >= 3:
                    notes.append("agent stopped calling tools without finishing")
                    break
                nudge = ("Your output was cut off by the token limit; continue more concisely." if resp.stop_reason ==
                         "max_tokens" else "No tool call received. Continue the investigation with tools, or call "
                         "finish_audit when every category has been covered.")
                messages.append({"role": "user", "content": nudge})
                continue
            idle_turns = 0

            results: list[dict[str, Any]] = []
            for call in resp.tool_calls:
                self.tool_call_count += 1
                t0 = time.monotonic()
                output, is_error = self._execute(call, remaining)
                dt = round(time.monotonic() - t0, 2)
                self.log(f"[step {step}] {call.name}({_short(call.input)}) -> "
                         f"{'ERROR ' if is_error else ''}{len(output)} chars in {dt}s")
                self.trace.event("tool_result", step=step, tool=call.name, input=call.input, is_error=is_error,
                                 duration_s=dt, output=output[:6000])
                block: dict[str, Any] = {"type": "tool_result", "tool_use_id": call.id, "content": output}
                if is_error:
                    block["is_error"] = True
                results.append(block)
            if self.finished:
                completed = True
                break
            if 0 < remaining <= 3:
                results.append({"type": "text", "text": prompts.budget_warning(remaining)})
            messages.append({"role": "user", "content": results})
        else:
            notes.append(f"step budget of {self.max_steps} turns exhausted before finish_audit")

        report = build_report(self.repo_url, list(self.violations.values()))
        self.trace.event("finish", completed=completed, steps=self.steps_used, tool_calls=self.tool_call_count,
                         usage=self.usage, violations=len(report["violations"]), summary=redact_text(self.summary, remember=False),
                         notes=notes)
        return AuditResult(report=report, completed=completed, steps=self.steps_used, tool_calls=self.tool_call_count,
                           usage=dict(self.usage), summary=self.summary, notes=notes)
