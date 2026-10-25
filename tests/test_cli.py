import json

import agent
import audit_agent.llm as llm_module
from audit_agent.llm import LLMError
from tests.fake_llm import FULL_COVERAGE, FakeLLM, call, respond


def _install_fake(monkeypatch, steps):
    holder = {}

    class _Fake(FakeLLM):
        def __init__(self, **_kw):
            super().__init__(list(steps))
            holder["llm"] = self

    monkeypatch.setattr(llm_module, "AnthropicLLM", _Fake)
    monkeypatch.setattr(agent, "_api_key", lambda: "test-key")
    return holder


def test_invalid_url_exits_nonzero(tmp_path, capsys):
    code = agent.main(["--repo", "not-a-url", "--output", str(tmp_path / "r.json")])
    assert code == agent.EXIT_CONFIG
    assert "Not a valid public GitHub repository URL" in capsys.readouterr().err
    assert not (tmp_path / "r.json").exists()


def test_missing_api_key_exits_nonzero(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(agent, "_api_key", lambda: None)
    code = agent.main(["--repo", "https://github.com/a/b", "--output", str(tmp_path / "r.json")])
    assert code == agent.EXIT_CONFIG
    assert "API key" in capsys.readouterr().err


def test_missing_required_args_exit_nonzero(capsys):
    try:
        agent.main(["--output", "x.json"])
    except SystemExit as exc:
        assert exc.code != 0
    else:
        raise AssertionError("argparse should exit")


def test_end_to_end_with_fake_llm(defect_repo, tmp_path, monkeypatch):
    finding = dict(rule_id="CI-003", category="ci_cd", severity="high", file=".github/workflows/ci.yml", line=11,
                   description="Test failures are masked", evidence="ci.yml:11 runs 'pytest || true' so failing tests "
                   "never fail the job", recommendation="Remove '|| true' so pytest's exit code gates the job")
    _install_fake(monkeypatch, [
        respond(call("inspect_ci")),
        respond(call("read_file", path=".github/workflows/ci.yml")),
        respond(call("record_violation", **finding)),
        respond(call("finish_audit", summary="s", coverage=FULL_COVERAGE)),
        respond(call("finish_audit", summary="s", confirm=True)),
    ])
    out = tmp_path / "report.json"
    code = agent.main(["--repo", "https://github.com/example/demo", "--local-path", str(defect_repo),
                       "--output", str(out), "--no-pytest", "--quiet"])
    assert code == 0
    data = json.loads(out.read_text())
    assert data["repository"] == "https://github.com/example/demo"
    assert data["violations"][0]["rule_id"] == "CI-003"
    trace = (tmp_path / "report.trace.jsonl").read_text().splitlines()
    assert any('"tool": "inspect_ci"' in line for line in trace)


def test_llm_failure_exits_nonzero_without_report(defect_repo, tmp_path, monkeypatch, capsys):
    def boom(_messages):
        raise LLMError("Anthropic API rejected the API key (authentication failed).")
    _install_fake(monkeypatch, [boom])
    out = tmp_path / "report.json"
    code = agent.main(["--repo", "https://github.com/example/demo", "--local-path", str(defect_repo),
                       "--output", str(out), "--no-pytest", "--quiet"])
    assert code == agent.EXIT_LLM
    assert "authentication failed" in capsys.readouterr().err
    assert not out.exists()


def test_repo_acquisition_failure(tmp_path, monkeypatch, capsys):
    _install_fake(monkeypatch, [])
    code = agent.main(["--repo", "https://github.com/example/demo", "--local-path", str(tmp_path),
                       "--output", str(tmp_path / "r.json"), "--quiet"])
    assert code == agent.EXIT_REPO
    assert "not a git repository" in capsys.readouterr().err
