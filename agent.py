#!/usr/bin/env python3
"""DevOps repository auditing agent - CLI entry point.

Usage:
    python agent.py --repo https://github.com/<owner>/<repo> --output report.json

Exit codes: 0 success, 2 invalid input/configuration, 3 repository could not be
acquired, 4 LLM provider failure, 5 report could not be written, 1 unexpected error.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

EXIT_OK, EXIT_UNEXPECTED, EXIT_CONFIG, EXIT_REPO, EXIT_LLM, EXIT_OUTPUT = 0, 1, 2, 3, 4, 5


def _load_env() -> None:
    try:
        from dotenv import load_dotenv
    except ImportError:
        return
    # Existing environment variables always win over .env files.
    load_dotenv(Path.cwd() / ".env", override=False)
    load_dotenv(Path(__file__).resolve().parent / ".env", override=False)


def _api_key() -> str | None:
    for name in ("ANTHROPIC_API_KEY", "API_KEY", "api_key"):
        val = os.environ.get(name)
        if val and val.strip():
            return val.strip()
    return None


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="agent.py",
        description="Autonomously audit a public GitHub repository for DevOps best-practice violations.")
    p.add_argument("--repo", required=True, help="Public GitHub repository URL (https://github.com/<owner>/<repo>)")
    p.add_argument("--output", required=True, help="Path of the JSON report to write")
    p.add_argument("--trace", default=None,
                   help="Path of the JSON-lines tool-call trace (default: <output>.trace.jsonl; 'none' to disable)")
    p.add_argument("--model", default=None, help="LLM model id (default: $LLM_MODEL or claude-opus-5-5)")
    p.add_argument("--effort", default=None, choices=["low", "medium", "high", "xhigh", "max"],
                   help="Reasoning effort (default: $LLM_EFFORT or medium)")
    p.add_argument("--max-steps", type=int, default=None, help="Maximum assistant turns (default: $MAX_STEPS or 40)")
    p.add_argument("--timeout", type=int, default=None,
                   help="Overall time budget in seconds (default: $AUDIT_TIMEOUT or 1800)")
    p.add_argument("--no-pytest", action="store_true", help="Disable sandboxed test execution (run_pytest tool)")
    p.add_argument("--local-path", default=None,
                   help="Audit an existing local git checkout instead of cloning (development/testing aid)")
    p.add_argument("--quiet", action="store_true", help="Only print errors and the final summary")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    _load_env()

    from audit_agent.llm import DEFAULT_MODEL, AnthropicLLM, LLMError
    from audit_agent.loop import AuditAgent, TraceWriter
    from audit_agent.repo import RepoError, clone_repository, open_local_repository, parse_github_url
    from audit_agent.report import write_report
    from tools import RepoTools

    def err(msg: str) -> None:
        print(f"error: {msg}", file=sys.stderr)

    log = (lambda _m: None) if args.quiet else (lambda m: print(m, file=sys.stderr, flush=True))

    try:
        spec = parse_github_url(args.repo)
    except RepoError as exc:
        err(str(exc))
        return EXIT_CONFIG

    out_path = Path(args.output)
    if out_path.exists() and out_path.is_dir():
        err(f"--output {out_path} is a directory; give a file path")
        return EXIT_CONFIG
    try:
        out_path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        err(f"cannot create output directory {out_path.parent}: {exc}")
        return EXIT_OUTPUT

    key = _api_key()
    if not key:
        err("no LLM API key found. Set ANTHROPIC_API_KEY in the environment or in a .env file (see .env.example).")
        return EXIT_CONFIG

    model = args.model or os.environ.get("LLM_MODEL") or DEFAULT_MODEL
    effort = args.effort or os.environ.get("LLM_EFFORT", "medium") or None
    max_steps = args.max_steps or _int_env("MAX_STEPS", 40)
    timeout = args.timeout or _int_env("AUDIT_TIMEOUT", 1800)
    trace_path = None if (args.trace or "").lower() == "none" else (args.trace or str(out_path) + ".trace.jsonl")
    if trace_path and trace_path.endswith(".json.trace.jsonl"):
        trace_path = trace_path[: -len(".json.trace.jsonl")] + ".trace.jsonl"

    try:
        llm = AnthropicLLM(api_key=key, model=model, effort=effort,
                           max_tokens=_int_env("LLM_MAX_TOKENS", 16000),
                           timeout=float(_int_env("LLM_REQUEST_TIMEOUT", 300)))
    except LLMError as exc:
        err(str(exc))
        return EXIT_CONFIG

    checkout = None
    trace = None
    started = time.monotonic()
    try:
        log(f"Acquiring {spec.canonical_url} ...")
        try:
            checkout = (open_local_repository(args.local_path, spec.canonical_url) if args.local_path
                        else clone_repository(spec, timeout=_int_env("CLONE_TIMEOUT", 300)))
        except RepoError as exc:
            err(str(exc))
            return EXIT_REPO
        log(f"Repository ready: default branch {checkout.default_branch}, {checkout.commit_count} commits in clone.")
        tools = RepoTools(checkout, command_timeout=_int_env("TOOL_TIMEOUT", 60),
                          sandbox_timeout=_int_env("SANDBOX_TIMEOUT", 600))
        trace = TraceWriter(trace_path)
        # The report echoes the repository URL exactly as supplied (cloning uses the canonical form).
        agent = AuditAgent(llm, tools, args.repo.strip(), max_steps=max_steps,
                           max_tool_output_chars=_int_env("MAX_TOOL_OUTPUT_CHARS", 10000),
                           deadline_seconds=timeout, trace=trace, log=log,
                           enable_pytest=not args.no_pytest and os.environ.get("ENABLE_DOCKER_TESTS", "auto").lower()
                           not in {"0", "false", "no", "off"})
        try:
            result = agent.run()
        except LLMError as exc:
            err(f"LLM failure: {exc}")
            return EXIT_LLM
        try:
            write_report(result.report, out_path)
        except (OSError, ValueError) as exc:
            err(f"could not write report: {exc}")
            return EXIT_OUTPUT
        for note in result.notes:
            print(f"warning: {note}", file=sys.stderr)
        u = result.usage
        print(f"Wrote {out_path} with {len(result.report['violations'])} violation(s) "
              f"[{'completed' if result.completed else 'partial'}; {result.steps} turns, {result.tool_calls} tool calls, "
              f"{time.monotonic() - started:.0f}s; tokens in={u['input_tokens']} cache_read={u['cache_read_input_tokens']} "
              f"cache_write={u['cache_creation_input_tokens']} out={u['output_tokens']}]"
              + (f"; trace: {trace_path}" if trace_path else ""), file=sys.stderr)
        return EXIT_OK
    except KeyboardInterrupt:
        err("interrupted")
        return 130
    except Exception as exc:  # last-resort guard: never dump secrets or a raw traceback by default
        from audit_agent.redact import redact_text
        err(f"unexpected failure: {type(exc).__name__}: {redact_text(str(exc))[:500]}")
        if os.environ.get("AUDIT_DEBUG"):
            raise
        return EXIT_UNEXPECTED
    finally:
        if trace:
            trace.close()
        if checkout:
            checkout.cleanup()


if __name__ == "__main__":
    sys.exit(main())
