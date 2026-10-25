"""Violation validation, de-duplication and JSON report writing."""

from __future__ import annotations

import json
import os
import re
import tempfile
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from audit_agent.redact import redact_text
from audit_agent.rules import CATEGORIES, CATEGORY_PREFIX, RULE_CATEGORY, SEVERITIES

REPORT_FIELDS = ("rule_id", "category", "severity", "file", "line", "description", "evidence", "recommendation")

CATEGORY_ALIASES = {
    "hygiene": "repository_hygiene", "repository hygiene": "repository_hygiene", "repo_hygiene": "repository_hygiene",
    "dependency management": "dependency_management", "dependencies": "dependency_management",
    "code quality": "code_quality", "tests": "testing", "test": "testing", "ci": "ci_cd", "ci/cd": "ci_cd",
    "github actions": "ci_cd", "github_actions": "ci_cd", "github actions / ci": "ci_cd", "cicd": "ci_cd",
    "config": "configuration", "build and release": "build_release", "build_and_release": "build_release",
    "build": "build_release", "release": "build_release",
}


@dataclass
class Violation:
    rule_id: str
    category: str
    severity: str
    file: str | None
    line: int | None
    description: str
    evidence: str
    recommendation: str

    def to_dict(self) -> dict[str, Any]:
        return {k: asdict(self)[k] for k in REPORT_FIELDS}


class ValidationError(Exception):
    pass


def normalise_category(value: Any) -> str:
    v = str(value or "").strip().lower()
    v = CATEGORY_ALIASES.get(v, v).replace(" ", "_").replace("-", "_")
    return v


def build_violation(raw: dict[str, Any], file_exists: Callable[[str], bool],
                    line_count: Callable[[str], int | None]) -> Violation:
    """Validate the agent's arguments against the schema and the repository; raise ValidationError on problems."""
    problems = []
    rule_id = str(raw.get("rule_id") or "").strip().upper()
    if not re.fullmatch(r"[A-Z]{2,4}-\d{3}", rule_id):
        problems.append("rule_id must look like ABC-123 (use the catalogue IDs)")
    category = normalise_category(raw.get("category"))
    if not category and rule_id in RULE_CATEGORY:
        category = RULE_CATEGORY[rule_id]
    if category not in CATEGORIES:
        problems.append(f"category must be one of {CATEGORIES}")
    elif rule_id in RULE_CATEGORY and RULE_CATEGORY[rule_id] != category:
        category = RULE_CATEGORY[rule_id]
    elif rule_id and category in CATEGORY_PREFIX and not rule_id.startswith(CATEGORY_PREFIX[category] + "-"):
        problems.append(f"custom rule_id for category {category} must start with {CATEGORY_PREFIX[category]}-")
    severity = str(raw.get("severity") or "").strip().lower()
    if severity not in SEVERITIES:
        problems.append(f"severity must be one of {SEVERITIES}")

    file = raw.get("file")
    if isinstance(file, str):
        file = file.strip().removeprefix("./").lstrip("/") or None
        if file in ("null", "none", "None", "N/A", "n/a", "-"):
            file = None
    elif file is not None:
        problems.append("file must be a string path or null")
        file = None
    line = raw.get("line")
    if isinstance(line, str) and line.strip().isdigit():
        line = int(line.strip())
    if line in ("", "null", "None", 0):
        line = None
    if line is not None and (not isinstance(line, int) or isinstance(line, bool) or line < 1):
        problems.append("line must be a positive integer or null")
        line = None
    if file is not None and not file_exists(file):
        problems.append(f"file {file!r} is not a tracked file in the repository (use null for absent files, or the "
                        "exact path from list_files)")
    if file is None and line is not None:
        problems.append("line must be null when file is null")
    if file is not None and line is not None and file_exists(file):
        n = line_count(file)
        if n is not None and line > n:
            problems.append(f"line {line} is beyond the end of {file} ({n} lines)")

    texts = {}
    for key, minimum in (("description", 8), ("evidence", 15), ("recommendation", 10)):
        val = str(raw.get(key) or "").strip()
        if len(val) < minimum:
            problems.append(f"{key} is missing or too short")
        texts[key] = redact_text(val, remember=False)[:1500]
    if problems:
        raise ValidationError("; ".join(problems))
    return Violation(rule_id=rule_id, category=category, severity=severity, file=file, line=line, **texts)


def _dedupe_key(v: Violation) -> tuple:
    return (v.rule_id, v.file, v.line)


def deduplicate(violations: list[Violation]) -> list[Violation]:
    seen: dict[tuple, Violation] = {}
    order = {s: i for i, s in enumerate(SEVERITIES)}
    for v in violations:
        k = _dedupe_key(v)
        if k in seen:
            if order[v.severity] < order[seen[k].severity]:
                seen[k] = v
            continue
        seen[k] = v
    return list(seen.values())


def build_report(repo_url: str, violations: list[Violation]) -> dict[str, Any]:
    order = {s: i for i, s in enumerate(SEVERITIES)}
    items = sorted(deduplicate(violations), key=lambda v: (order[v.severity], v.category, v.rule_id, v.file or "",
                                                           v.line or 0))
    return {"repository": repo_url, "violations": [v.to_dict() for v in items]}


def validate_report(report: dict[str, Any]) -> None:
    """Strict check of the output contract; raises ValueError."""
    if set(report) != {"repository", "violations"}:
        raise ValueError("report must contain exactly 'repository' and 'violations'")
    if not isinstance(report["repository"], str) or not isinstance(report["violations"], list):
        raise ValueError("invalid report types")
    for i, v in enumerate(report["violations"]):
        if set(v) != set(REPORT_FIELDS):
            raise ValueError(f"violation {i} fields mismatch: {sorted(v)}")
        if v["severity"] not in SEVERITIES:
            raise ValueError(f"violation {i} has invalid severity")
        if v["file"] is not None and not isinstance(v["file"], str):
            raise ValueError(f"violation {i} file must be string or null")
        if v["line"] is not None and (not isinstance(v["line"], int) or isinstance(v["line"], bool)):
            raise ValueError(f"violation {i} line must be int or null")
        for key in ("rule_id", "category", "description", "evidence", "recommendation"):
            if not isinstance(v[key], str) or not v[key]:
                raise ValueError(f"violation {i} {key} must be a non-empty string")


def write_report(report: dict[str, Any], output: str | os.PathLike[str]) -> Path:
    validate_report(report)
    out = Path(output)
    if out.parent and not out.parent.exists():
        out.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    json.loads(text)
    fd, tmp = tempfile.mkstemp(prefix=".report-", suffix=".json", dir=str(out.parent or "."))
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
    umask = os.umask(0)
    os.umask(umask)
    os.chmod(tmp, 0o666 & ~umask)  # mkstemp creates 0600; use normal file permissions
    os.replace(tmp, out)
    return out
