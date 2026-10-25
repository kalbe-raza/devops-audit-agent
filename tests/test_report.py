import json

import pytest

from audit_agent.report import (
    REPORT_FIELDS,
    ValidationError,
    build_report,
    build_violation,
    validate_report,
    write_report,
)

EXISTS = {"config.py": 20, ".github/workflows/ci.yml": 30}


def _build(**overrides):
    raw = dict(rule_id="SEC-001", category="security", severity="critical", file="config.py", line=17,
               description="Hardcoded API credential", evidence="Credential assigned directly in source code",
               recommendation="Use a secrets manager or environment variable")
    raw.update(overrides)
    return build_violation(raw, lambda f: f in EXISTS, lambda f: EXISTS.get(f))


def test_valid_violation_has_exact_fields():
    v = _build()
    assert list(v.to_dict()) == list(REPORT_FIELDS)


def test_absence_findings_use_null():
    v = _build(rule_id="HYG-001", category="repository_hygiene", severity="medium", file=None, line=None)
    assert v.file is None and v.line is None
    v = _build(rule_id="HYG-001", category="repository_hygiene", severity="medium", file="null", line="null")
    assert v.file is None and v.line is None


@pytest.mark.parametrize("overrides,msg", [
    ({"severity": "blocker"}, "severity"),
    ({"category": "ml"}, "category"),
    ({"rule_id": "bad"}, "rule_id"),
    ({"file": "missing.py"}, "not a tracked file"),
    ({"line": 99}, "beyond the end"),
    ({"line": -1}, "positive integer"),
    ({"file": None, "line": 3}, "line must be null"),
    ({"evidence": ""}, "evidence"),
])
def test_invalid_violations(overrides, msg):
    with pytest.raises(ValidationError, match=msg):
        _build(**overrides)


def test_category_aliases_and_rule_category_consistency():
    assert _build(category="Security").category == "security"
    assert _build(rule_id="CI-003", category="security").category == "ci_cd"


def test_secret_values_are_redacted_in_text_fields():
    v = _build(evidence='Found password = "Zx81!kqLmP0" in config')
    assert "Zx81!kqLmP0" not in v.evidence


def test_build_report_dedupes_and_sorts():
    a = _build(severity="low")
    b = _build(severity="high")
    c = _build(rule_id="CI-003", category="ci_cd", severity="high", file=".github/workflows/ci.yml", line=5)
    report = build_report("https://github.com/x/y", [a, b, c])
    validate_report(report)
    assert len(report["violations"]) == 2
    assert all(v["severity"] == "high" for v in report["violations"])


def test_empty_report_is_valid(tmp_path):
    out = write_report(build_report("https://github.com/x/y", []), tmp_path / "sub" / "r.json")
    data = json.loads(out.read_text())
    assert data == {"repository": "https://github.com/x/y", "violations": []}


def test_validate_report_rejects_extra_fields():
    with pytest.raises(ValueError):
        validate_report({"repository": "x", "violations": [], "extra": 1})
    bad = build_report("x", [_build()])
    bad["violations"][0]["extra"] = 1
    with pytest.raises(ValueError):
        validate_report(bad)
