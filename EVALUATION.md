# Evaluation

The assignment grades detection precision and recall on unseen repositories of three kinds: (A) obvious defects,
(B) subtler CI, security and configuration defects, and (C) a mostly healthy repository that tests for false
positives. The hidden repositories aren't available, so the agent was measured in two ways:

1. **Five local repositories with known injected defects**, built by `evaluation/build_scenarios.py`, with the
   expected answers in `evaluation/ground_truth.json`. Two scenarios were added beyond the A/B/C pattern:
   * D: a mix of subtle defects across a Python API and a Node frontend.
   * E: a healthy project that uses *alternative* tooling (GitLab CI, Poetry with a lockfile, tox,
     flake8/pre-commit, unittest, a label-only `pull_request_target`). E checks that acceptable alternatives
     aren't reported.
2. **Real public GitHub repositories**, cloned by the agent and checked by hand.

All numbers below come from real runs of `agent.py` with `claude-opus-5-5` at effort `medium`.

## How to reproduce

```bash
python evaluation/build_scenarios.py /tmp/eval_repos
for s in a b c d e; do
  python agent.py --repo https://github.com/example/scenario-$s --local-path /tmp/eval_repos/scenario_$s \
                  --output /tmp/eval_reports/scenario_$s.json
done
python evaluation/score.py /tmp/eval_reports
```

**Scoring rule** (`evaluation/score.py`):
* A reported violation matches a ground-truth entry when its `rule_id` is one of the entry's accepted rule ids,
  its `file` is one of the accepted files (when the entry lists files), and its line is within ±2 (when the
  entry gives a line).
* Each ground-truth entry can be matched at most once. Any report that doesn't match an entry counts against
  precision.
* Entries marked `optional` are real defects that weren't planted on purpose, found while building the
  fixtures. Reporting one counts as correct for precision, but optional entries aren't part of the recall
  denominator.

## Results on the injected-defect scenarios

The final run is saved in `evaluation/results/`: one report per scenario, plus `score.txt`.

| Scenario | Planted defects | Reported | Correct | Recall | Precision |
|---|---:|---:|---:|---:|---:|
| A: obvious | 14 | 17 | 14 | **14/14** | 0.82 strict (3 per-kind splits, see below) |
| B: subtle CI/security/config | 12 | 12 | 12 (1 optional) | **12/12** | 1.00 |
| C: healthy | 0 | 0 | 0 | – | 1.00 |
| D: mixed subtle | 12 | 17 | 16 (4 optional) | **12/12** | 0.94 |
| E: healthy, alternative tooling | 0 | 2 | 1 (optional) | – | 0.50 |
| **Overall** | **38** | **48** | **43** | **1.00 (38/38)** | **0.90 strict (43/48)** |

**The 5 findings that don't match an entry, judged one by one:**
* **A, three findings.** The ground truth counts "tracked temporary files" (a `.pyc`, `.DS_Store` and
  `server.log`) as one defect, and the hardcoded paths in `app.py` and `utils.py` as one defect. The agent
  reported each committed file kind and each path separately, which is what the prompt asks for because each
  needs its own fix. These are correct and supported by evidence; they are splits, not false claims.
* **D, `BLD-002` on `.github/workflow/release.yml`** ("publishes the image without running tests"). The
  statement is true, but it overlaps D7: that workflow sits in the wrong directory and never runs. Borderline
  duplicate.
* **E, `BLD-001`** ("the Docker image is never built or validated in CI"). True, but in a healthy project with
  no release pipeline this is debatable. Counted as a **false positive**.

Counting splits as correct, adjudicated precision is 46/48 = 0.96. No reported finding was factually wrong.

**The healthy scenarios.**
* C produced no findings in every round.
* In E, the unfamiliar tooling (GitLab CI instead of GitHub Actions, Poetry with a lockfile, tox,
  flake8/pre-commit, unittest, a label-only `pull_request_target`, a placeholder `.env.sample`) was never
  reported. E's matched finding is a real defect the fixture contains by accident: the Dockerfile runs
  `python -m ledger`, but the package has no `__main__.py`.

### How the agent improved between rounds

| Round | Changes | Precision | Recall |
|---|---|---:|---:|
| 1 | First full version | 1.00 (41/41) | 0.95 (36/38): missed TLS `verify=False`, which was merged into the debug finding, and B's version mismatch |
| 2 | Split rule SEC-008 into SEC-008/009/010; added guidance on grouping findings by kind | 0.93 (41/44) | 0.95 (36/38): B's lint `continue-on-error` was merged into the `\|\| true` finding; version mismatch still missed |
| 3 | Self-review now splits bundled findings; `dependency_overview` lists every version declaration | 0.93 (43/46) | **1.00 (38/38)** |
| 4 (final) | Global secret scrubbing limited to distinctive values; previously a placeholder like `password` in a sample URL caused every later occurrence of the word to be scrubbed | 0.90 (43/48) | **1.00 (38/38)** |

Rounds 3 and 4 differ only in redaction, so the precision difference between them (two extra borderline
findings) is run-to-run LLM variation. The rule catalogue and tools contain general DevOps knowledge only. No scenario-specific answers were added. The
version-declaration listing, for example, works on any repository.

## Results on real public repositories

| Repository | Kind | Result | Manual check |
|---|---|---|---|
| [pallets/flask](https://github.com/pallets/flask) | Large, healthy | **0 violations** (7 turns, 13 tool calls, 38 s) | The agent inspected CI, secrets, dependencies and ruff output. It read the test fixture `tests/test_apps/.env` and correctly dismissed it. |
| [pallets/itsdangerous](https://github.com/pallets/itsdangerous) | Healthy | **1 low** (first run); **1 low + 1 medium** (repeat run from a fresh install) | Correct: `pyproject.toml:86` sets `[tool.coverage.run] source = ["jinja2", "tests"]`, a copy-paste error, so coverage measures the wrong package. Line number is exact. The repeat run also reported `BLD-002`: `publish.yaml` publishes to PyPI on any tag push (`tags: ['*']`, L4) with only `needs: [build]` and no test job. That is factually accurate, and the agent explicitly declined to guess the remote environment protection, but many projects deliberately accept this practice. Counted as debatable, and an example of run-to-run variation. |
| [we45/Vulnerable-Flask-App](https://github.com/we45/Vulnerable-Flask-App) | Deliberately insecure | **15 violations** → `sample_report.json` | Each file:line was checked against the clone: hardcoded secret key (`app/app.py:28`), template injection (`:114`), SQL injection (`:261`), `yaml.load` (`:329`), JWT decoded with `verify = False` and always accepted (`:97`), bare except (`:193`), `python:2.7.14-jessie` base image, `wait-action@master`, `ubuntu-18.04` runner, `tests/` containing only an assertion-free ZAP script, the committed `app/test.db`, a one-line `.gitignore`, and inconsistent Python 2.7.15/3.7.10 declarations. All were confirmed. |

`sample_report.json` is the unedited output of:

```bash
python agent.py --repo https://github.com/we45/Vulnerable-Flask-App --output sample_report.json
```

Its trace is in `evaluation/sample_trace.jsonl`. It shows the model picking each tool in turn:
1. `list_files` and `find_tracked_artifacts`.
2. Eleven targeted `read_file` calls on the files it had just discovered.
3. `git_log` and `run_ruff`.
4. Recording the findings, one self-review pass, then confirmation.

Neither the report nor the trace contains the repository's secret values.

## Robustness checks

| Check | Result |
|---|---|
| Nonexistent repository | Exit 3: `error: Failed to clone ...: repository not found or not public`. No report is written. |
| Non-GitHub or malformed URL | Exit 2 with the expected URL format. |
| Missing API key, LLM failure, step budget exhausted, unknown tool, bad tool arguments, path escape | Covered by the automated tests (`tests/test_cli.py`, `tests/test_agent_loop.py`). |
| Sandboxed pytest | Reports assertion failures. Inside the sandbox the network is unreachable, `ANTHROPIC_API_KEY` is absent, and tests run as uid 65534. |
| Fresh install on Python 3.11 (`python:3.11-slim` container) | `pip install -r requirements.txt`, all tests and `ruff check .` pass. |

## Cost and latency

A typical audit takes 5–8 turns, 15–40 tool calls and 15–100 seconds. Because the history is append-only and
prompt-cached, almost all input is read from cache. The sample run read 159k tokens from cache, wrote 23k to
cache, and produced 9k output tokens. At Claude Opus 5.5 list prices that's roughly **US$0.05–0.35 per audit**. To
reduce cost, set `LLM_MODEL` to a smaller model; to trade depth for cost, change `LLM_EFFORT`.

## Limitations of this evaluation

* The scenarios were written by the same author as the agent, so they may share blind spots. The real-repo runs
  are a partial check on that.
* LLM output varies somewhat between runs. The numbers above are single runs per scenario per round, not
  averages.
* How findings are grouped (one per kind and location versus one per root cause) affects precision under any
  strict scorer. The agent reports one finding per distinct, separately fixable defect.
