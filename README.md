# DevOps Repository Auditing Agent

An AI agent that inspects a public GitHub repository, finds DevOps best-practice violations and writes an
evidence-based JSON report with actionable recommendations.

The agent follows the cycle **Observe → Reason → Select tool → Execute tool → Interpret results → Report**. The
LLM (Claude, via the official `anthropic` SDK) decides which inspection tool to call next, based on what the
previous tools returned. The agent loop, tool dispatch and control flow are plain Python written for this
project. No agent framework is used: no LangChain, LangGraph, n8n or similar.

```
python agent.py --repo https://github.com/<owner>/<repo> --output report.json
```

---

## 1. Requirements

| Requirement | Notes |
|---|---|
| Python **3.11+** | Uses `tomllib` from the standard library. Tested on 3.12 and 3.14. |
| `git` on `PATH` | Used to clone the target repository and read its history. |
| Anthropic API key | Used for the LLM calls. |
| Docker (optional) | Only used by the `run_pytest` tool to run the target's tests in a sandbox. Without Docker that check is reported as unavailable; the rest of the audit is unaffected. |

## 2. Installation

```bash
git clone <this-repository-url> devops-audit-agent
cd devops-audit-agent
python3 -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## 3. Configuration

```bash
cp .env.example .env
# edit .env and set ANTHROPIC_API_KEY=<your key>
```

Settings are read from the process environment first, then from `.env` in the current directory or the project
directory. Only `ANTHROPIC_API_KEY` is required. The agent also accepts `API_KEY` / `api_key` as fallbacks.

| Variable | Default | Meaning |
|---|---|---|
| `ANTHROPIC_API_KEY` | – (required) | Anthropic API key |
| `LLM_MODEL` | `claude-opus-5-5` | Model id |
| `LLM_EFFORT` | `medium` | Reasoning effort: `low`, `medium`, `high`, `xhigh` or `max` |
| `MAX_STEPS` | `40` | Maximum number of assistant turns per audit |
| `MAX_TOOL_OUTPUT_CHARS` | `10000` | Truncation limit for a single tool result |
| `AUDIT_TIMEOUT` | `1800` | Overall time budget in seconds |
| `CLONE_TIMEOUT` / `TOOL_TIMEOUT` | `300` / `60` | Timeouts in seconds for `git clone` and for each git/ruff command |
| `ENABLE_DOCKER_TESTS` | `auto` | Set to `false` to disable sandboxed test execution |
| `SANDBOX_IMAGE` / `SANDBOX_TIMEOUT` | `python:3.12-slim` / `600` | Image and timeout for the test sandbox |

## 4. Usage

```bash
python agent.py --repo https://github.com/<owner>/<repo> --output report.json
```

The run is fully unattended and never prompts. Progress is printed to stderr. When the inspection completes, the
agent writes:

* `report.json`: the report, in the exact format required by the assignment.
* `report.trace.jsonl`: a JSON-lines trace of every LLM turn and every tool call, with inputs, outputs, timings
  and token usage. Secrets are redacted.

Optional flags:

| Flag | Purpose |
|---|---|
| `--trace PATH` / `--trace none` | Write the trace somewhere else, or turn it off |
| `--model ID`, `--effort LEVEL`, `--max-steps N`, `--timeout SEC` | Override the matching environment settings |
| `--no-pytest` | Remove the sandboxed `run_pytest` tool |
| `--quiet` | Print only errors and the final summary line |
| `--local-path DIR` | Audit an existing local git checkout instead of cloning (for development and testing) |

**Exit codes:** `0` success (a valid JSON report was written) · `2` invalid input or configuration (bad URL,
missing API key) · `3` the repository could not be cloned (not found, private, timeout, empty) · `4` the LLM
provider failed (authentication, model, rate limit or network errors after retries) · `5` the report could not
be written · `1` unexpected error. On every non-zero exit a one-line `error: ...` message is printed to stderr
and no report file is written.

### Output contract

```json
{
  "repository": "https://github.com/example/demo-project",
  "violations": [
    {
      "rule_id": "SEC-001",
      "category": "security",
      "severity": "critical",
      "file": "config.py",
      "line": 17,
      "description": "Hardcoded API credential",
      "evidence": "Credential assigned directly in source code",
      "recommendation": "Use a secrets manager or environment variable"
    }
  ]
}
```

* The report always has exactly these two keys. Every violation has exactly these eight fields.
* `severity` is one of `critical`, `high`, `medium`, `low`.
* `file` and `line` are JSON `null` when they don't apply, for example a missing README.
* A clean repository produces `"violations": []`.
* Secret values never appear in the report.
* `category` is one of `repository_hygiene`, `dependency_management`, `code_quality`, `testing`, `ci_cd`,
  `security`, `configuration`, `collaboration`, `build_release`.

`sample_report.json` is a real, unedited output of this agent (see section 8).

---

## 5. Architecture

```
agent.py                 CLI: argument parsing, configuration, exit codes, cleanup
tools.py                 Inspection tools (read-only) and their JSON schemas
audit_agent/
  loop.py                The agent loop: LLM turn -> tool dispatch -> results -> next turn; finding registry,
                         coverage check, self-review, budgets, trace
  llm.py                 LLM interaction (Anthropic Messages API with tool use, prompt caching, refusal
                         fallback, typed error handling) behind a small LLMClient protocol
  prompts.py             System prompt (method, evidence rules, precision rules, safety) and controller messages
  rules.py               DevOps rule catalogue: rule ids, default severities, acceptable alternatives
  report.py              Validation of findings against the repository, de-duplication, JSON contract
  redact.py              Secret detection and redaction for every tool output, trace entry and report field
  repo.py                GitHub URL validation and hardened, read-only cloning
  sandbox.py             Docker sandbox used by run_pytest
tests/                   Offline tests (tools, redaction, report, agent loop with a scripted LLM, CLI)
evaluation/              Injected-defect scenarios, ground truth, scorer, final results, sample trace
```

### How the agent loop works

```
            ┌───────────────────────────── system prompt + tool schemas (cached) ─────────────────────────┐
 clone ──►  │ user: repo URL, default branch, size, budget                                                │
            │ ┌──► LLM turn: reasons about what it has seen, chooses one or more tools ──────────────┐    │
            │ │                                                                                       ▼    │
            │ │    controller executes the chosen tools (read-only, redacted, truncated, timeouts)   tool  │
            │ │    record_violation → validated against the repo (file exists? line in range?)      calls │
            │ └─── tool results appended to the conversation  ◄─────────────────────────────────────────┘  │
            │      finish_audit → coverage check (all 9 categories) → one self-review pass → confirm       │
            └───────────────────────────────────────────────────────────────────────────────────────────────┘
                     ──► de-duplicate, sort, validate the contract ──► report.json + trace
```

* **The LLM directs the investigation.** No checklist runs ahead of the model. Each turn the model sees all
  previous tool results and picks the next calls. Typically it starts with `list_files`, then reads the
  manifests and workflows it found, then follows up on suspicious items with targeted `read_file`,
  `search_code` or `git_log` calls. The trace file shows the exact sequence for every run.
* **Specialised tools return candidates, not verdicts.** `inspect_ci`, `dependency_overview`,
  `find_tracked_artifacts` and `scan_secrets` parse files and emit heuristic flags. The prompt requires the model
  to confirm each flag in the actual file and to judge whether it's a genuine problem in context.
* **Findings are validated by code.** `record_violation` rejects a finding when the file isn't tracked, the line
  is past the end of the file, the severity or category is invalid, the text fields are empty, or the finding
  duplicates an existing one. The model gets the error back and can correct itself. Secret values are redacted
  from every text field.
* **Precision safeguards.**
  * Each rule in the catalogue lists the acceptable alternatives that must not be reported, for example ruff
    instead of flake8, GitLab CI instead of GitHub Actions, or pinned requirements instead of a lockfile.
  * The prompt forbids inferring remote settings such as branch protection.
  * Before finishing, the model reviews all of its findings once and withdraws duplicates and unsupported
    claims.
* **Recall safeguards.** `finish_audit` is rejected until the model has written a coverage note for each of the
  nine inspection categories.
* **Budgets and robustness.**
  * Limits on steps, time and tool-output size, plus a warning when the step budget is nearly used up.
  * Retries with backoff on rate limits and server errors (handled by the SDK).
  * Unknown tools, bad arguments and tool exceptions come back to the model as error results; they never crash
    the run.
  * If the step budget runs out, the findings recorded so far are still written as a valid report, with a
    warning on stderr.
* **Prompt caching.** The conversation is append-only and the system prompt and tool list never change, so
  each turn re-reads the history from cache. A typical audit (5–8 turns, 15–40 tool calls, 15–100 s) reads
  40k–140k tokens from cache and produces 1k–10k output tokens, roughly US$0.05–0.35 with Claude Opus 5.5.

### Tools

| Tool | Purpose |
|---|---|
| `list_files(path?, max_entries?)` | Lists the tracked files with sizes and file-type counts. Large repos get a per-directory summary. |
| `read_file(path, start_line?, end_line?)` | Returns a file's contents with line numbers, paged at 400 lines, with secrets redacted. |
| `search_code(pattern, path_glob?, ignore_case?, max_results?)` | Runs a regex search over tracked files (`git grep -E`) and returns `path:line:text`. |
| `git_log(max_count?, path?, show_files?, search?)` | Shows commit history. Can show changed files per commit, filter by path, or find commits whose diff matches a regex (pickaxe). |
| `find_tracked_artifacts()` | Checks `.gitignore`, tracked files that match ignore rules, generated/temp/IDE/local files, credential files, and large files. |
| `scan_secrets(include_history?)` | Detects credentials in the working tree and in git history by token format, sensitive assignment, and URL credentials. Reports kind, entropy and placeholder likelihood, never the value. |
| `inspect_ci()` | Parses GitHub Actions workflows (triggers, permissions, jobs, steps, action refs) and lists other CI systems. Flags failure masking, script injection, broad permissions, branch-filter mismatches, `pull_request_target`, ungated deploys, auto-merge, deprecated actions and runners, and misplaced or invalid workflow files. |
| `dependency_overview()` | Parses manifests and lockfiles statically, without executing anything: requirements, pyproject, setup.py (via `ast`), setup.cfg, Pipfile, package.json and Dockerfiles. Reports constraint strength, duplicates, conflicts between files, missing lockfiles, Python-version declarations, and imports that no manifest declares. |
| `run_ruff(path?)` | Runs the ruff linter (static analysis only). Uses the repository's own ruff config if it has one, otherwise ruff's defaults. |
| `run_pytest(test_path?)` | Runs the target's pytest suite in the Docker sandbox (see Safety). |
| `record_violation`, `withdraw_violation`, `finish_audit` | Agent-level tools for managing findings and ending the audit. |

---

## 6. Safety

* **The target repository is never modified.**
  * It is cloned into a private temporary directory and deleted afterwards.
  * Nothing is pushed.
  * Git runs with hooks disabled, no submodules, LFS smudging skipped, `file://`/`ext::` protocols blocked, the
    user's global git config ignored, and terminal prompts disabled.
  * Every tool only reads.
* **Path safety.** Tool paths are resolved inside the clone. `..`, absolute paths, symlinks that point outside
  the clone, and the `.git` directory are refused.
* **Untrusted code is never executed on the host.**
  * Ruff and all the parsers are static; `setup.py` is parsed with `ast`, never run.
  * `run_pytest` uses two throw-away containers. The first installs dependencies, with the repository mounted
    read-only. The second runs the tests with `--network none`, a read-only root filesystem, user `nobody`, all
    Linux capabilities dropped, `no-new-privileges`, and memory, CPU and PID limits.
  * No host environment variables (so no API keys) are passed into either container.
* **Secrets are never exposed.**
  * All tool output is redacted before it reaches the LLM, the trace or the report.
  * Redaction keeps the secret's kind, length, entropy and whether it looks like a placeholder, so the agent can
    still reason about it.
  * Any value detected once in repository content is scrubbed everywhere it reappears.
  * The API key is read from the environment and never logged.
* **Prompt injection.** Repository content is marked as untrusted data in the system prompt, and the model is
  told never to follow instructions found inside it.
* **No invented results.** If a check is unavailable (no Docker, tool timeout, invalid config), the tool says so
  explicitly and the prompt forbids guessing its result.

---

## 7. Tests

```bash
pytest          # 81 offline tests, finishes in a few seconds; no API key needed
ruff check .
```

* The tests build small git repositories on the fly.
* A scripted fake LLM (`tests/fake_llm.py`) drives the real agent loop, so tests cover tool selection and
  follow-up calls, validation feedback, de-duplication and withdrawal, the coverage check and self-review,
  budget exhaustion, unknown tools and bad arguments, an append-only history, redaction in the trace and the
  report, the CLI's exit codes, and an end-to-end CLI run.
* One test needs network access (cloning a repository that doesn't exist) and is skipped when offline.
* The Docker sandbox was checked by hand: it reports assertion failures, the network is unreachable, no API keys
  are present inside, and tests run as an unprivileged user.

---

## 8. Evaluation

See [EVALUATION.md](EVALUATION.md) for precision and recall against repositories with known injected defects,
and for runs on real public repositories. `sample_report.json` is a real, unedited output of the command
in section 4.

## 9. Limitations

* Only public GitHub repositories are supported. The clone is limited to the last 500 commits of the default
  branch, so older history is not scanned.
* `run_pytest` needs Docker. It can't provide external services such as databases or network APIs, so tests
  that need them fail inside the sandbox. The agent is told to treat those failures as environment limits, not
  test failures.
* Like any LLM-driven audit, results can vary somewhat from run to run. The validation, coverage check and
  self-review reduce this but don't remove it.
* Remote GitHub settings (branch protection, repository secrets, default token permissions) can't be seen from
  the files and are deliberately not reported.
