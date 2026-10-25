import json

from audit_agent.loop import AuditAgent, TraceWriter
from audit_agent.report import validate_report
from tests.conftest import FAKE_AWS_KEY
from tests.fake_llm import FULL_COVERAGE, FakeLLM, call, last_tool_results, respond

URL = "https://github.com/example/demo"

SECRET_FINDING = dict(rule_id="SEC-001", category="security", severity="critical", file="settings.py", line=1,
                      description="Hardcoded AWS access key", evidence="scan_secrets reported an aws_access_key_id at "
                      "settings.py:1 (placeholder_like=no)", recommendation="Rotate the key and load it from the "
                      "environment or a secrets manager")


def _agent(llm, tools, tmp_path=None, **kw):
    trace = TraceWriter(str(tmp_path / "trace.jsonl")) if tmp_path else None
    return AuditAgent(llm, tools, URL, trace=trace, log=lambda _m: None, enable_pytest=False, **kw)


def test_llm_directs_follow_up_tool_calls(defect_tools, tmp_path):
    """The second tool call depends on what the first tool returned (dynamic selection)."""
    def follow_up(messages):
        listing = last_tool_results(messages)[0]
        assert "settings.py" in listing
        return respond(call("read_file", path="settings.py"), call("scan_secrets"))

    def record(messages):
        results = last_tool_results(messages)
        assert "AWS_KEY" in results[0] and FAKE_AWS_KEY not in results[0]
        assert "aws_access_key_id" in results[1]
        return respond(call("record_violation", **SECRET_FINDING))

    llm = FakeLLM([
        respond(call("list_files")),
        follow_up,
        record,
        respond(call("finish_audit", summary="done", coverage=FULL_COVERAGE)),
        lambda m: (respond(call("finish_audit", summary="done", confirm=True))
                   if "Self-review" in last_tool_results(m)[0] else respond()),
    ])
    agent = _agent(llm, defect_tools, tmp_path)
    result = agent.run()
    agent.trace.close()
    assert result.completed
    validate_report(result.report)
    assert result.report["repository"] == URL
    assert [v["rule_id"] for v in result.report["violations"]] == ["SEC-001"]
    trace = [json.loads(line) for line in (tmp_path / "trace.jsonl").read_text().splitlines()]
    tools_called = [e["tool"] for e in trace if e["event"] == "tool_result"]
    assert tools_called[:3] == ["list_files", "read_file", "scan_secrets"]
    assert FAKE_AWS_KEY not in (tmp_path / "trace.jsonl").read_text()


def test_invalid_findings_are_rejected_and_reported_back(defect_tools):
    bad = dict(SECRET_FINDING, file="does/not/exist.py")
    beyond = dict(SECRET_FINDING, line=999)
    llm = FakeLLM([
        respond(call("record_violation", **bad), call("record_violation", **beyond),
                call("record_violation", **dict(SECRET_FINDING, severity="urgent"))),
        lambda m: respond(call("finish_audit", summary="x", coverage=FULL_COVERAGE)),
        respond(call("finish_audit", summary="x", confirm=True)),
    ])
    agent = _agent(llm, defect_tools)
    result = agent.run()
    errors = last_tool_results(llm.calls[1])
    assert all(e.startswith("rejected") for e in errors)
    assert "not a tracked file" in errors[0] and "beyond the end" in errors[1] and "severity" in errors[2]
    assert result.report["violations"] == []


def test_duplicates_and_withdrawal(defect_tools):
    llm = FakeLLM([
        respond(call("record_violation", **SECRET_FINDING)),
        respond(call("record_violation", **SECRET_FINDING)),
        respond(call("withdraw_violation", id="V1", reason="test")),
        respond(call("finish_audit", summary="x", coverage=FULL_COVERAGE)),
        respond(call("finish_audit", summary="x", confirm=True)),
    ])
    agent = _agent(llm, defect_tools)
    result = agent.run()
    assert "duplicate of V1" in last_tool_results(llm.calls[2])[0]
    assert result.report["violations"] == []


def test_coverage_check_and_self_review(defect_tools):
    llm = FakeLLM([
        respond(call("finish_audit", summary="too early")),
        respond(call("finish_audit", summary="ok", coverage=FULL_COVERAGE)),
        respond(call("finish_audit", summary="ok", confirm=True)),
    ])
    agent = _agent(llm, defect_tools)
    result = agent.run()
    assert "coverage notes missing" in last_tool_results(llm.calls[1])[0]
    assert "Self-review" in last_tool_results(llm.calls[2])[0]
    assert result.completed and result.steps == 3


def test_unknown_tool_and_bad_arguments_do_not_crash(defect_tools):
    llm = FakeLLM([
        respond(call("rm_rf", path="/"), call("read_file", nonsense=1), call("read_file", path="../../etc/passwd")),
        respond(call("finish_audit", summary="x", coverage=FULL_COVERAGE)),
        respond(call("finish_audit", summary="x", confirm=True)),
    ])
    result = _agent(llm, defect_tools).run()
    out = last_tool_results(llm.calls[1])
    assert "unknown tool" in out[0] and "invalid arguments" in out[1] and "escapes the repository" in out[2]
    assert result.completed


def test_step_budget_exhaustion_still_writes_valid_report(defect_tools):
    llm = FakeLLM([respond(call("record_violation", **SECRET_FINDING))] + [respond(call("list_files"))] * 10)
    result = _agent(llm, defect_tools, max_steps=5).run()
    assert not result.completed
    assert any("budget" in n for n in result.notes)
    validate_report(result.report)
    assert len(result.report["violations"]) == 1


def test_model_that_stops_calling_tools_is_nudged_then_stopped(defect_tools):
    llm = FakeLLM([respond(text="I think we're done")] * 3)
    result = _agent(llm, defect_tools).run()
    assert "No tool call received" in llm.calls[1][-1]["content"]
    assert not result.completed and result.report["violations"] == []


def test_pytest_tool_hidden_when_disabled(defect_tools):
    llm = FakeLLM([respond(call("finish_audit", summary="x", coverage=FULL_COVERAGE)),
                   respond(call("finish_audit", summary="x", confirm=True))])
    _agent(llm, defect_tools).run()
    assert "run_pytest" not in llm.tool_names_offered
    assert {"list_files", "read_file", "search_code", "git_log", "record_violation"} <= set(llm.tool_names_offered)


def test_history_is_append_only(defect_tools):
    """Earlier turns are never edited (keeps prompt caching and model reasoning valid)."""
    llm = FakeLLM([respond(call("list_files")), respond(call("git_log")),
                   respond(call("finish_audit", summary="x", coverage=FULL_COVERAGE)),
                   respond(call("finish_audit", summary="x", confirm=True))])
    _agent(llm, defect_tools).run()
    for earlier, later in zip(llm.calls, llm.calls[1:], strict=False):
        assert later[: len(earlier)] == earlier
