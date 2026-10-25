"""Secret detection and redaction.

Every piece of repository content that leaves a tool (towards the LLM, the trace
file or the final report) passes through :func:`redact_text`. Secret values are
replaced by a short annotation that keeps the information the agent needs to
reason (kind, length, whether it looks like a placeholder) without the value.
"""

from __future__ import annotations

import math
import re
import threading
from dataclasses import dataclass

PLACEHOLDER_HINTS = (
    "your", "xxx", "changeme", "change_me", "example", "dummy", "placeholder",
    "replace", "insert", "todo", "fixme", "sample", "fake", "<", ">", "changeit",
    "****", "...", "none", "null", "secret_here", "key_here", "redacted",
)


@dataclass(frozen=True)
class _Pattern:
    kind: str
    regex: re.Pattern[str]
    group: int = 0  # capture group that holds the secret value


# Provider-specific token formats (high confidence).
_TOKEN_PATTERNS = [
    _Pattern("private_key_block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    _Pattern("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    _Pattern("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b")),
    _Pattern("github_pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{40,}\b")),
    _Pattern("gitlab_token", re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,}\b")),
    _Pattern("slack_token", re.compile(r"\bxox[abposr]-[A-Za-z0-9\-]{10,}\b")),
    _Pattern("slack_webhook", re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+")),
    _Pattern("stripe_key", re.compile(r"\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}\b")),
    _Pattern("google_api_key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    _Pattern("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9\-_]{20,}")),
    _Pattern("openai_key", re.compile(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_\-]{20,}")),
    _Pattern("sendgrid_key", re.compile(r"\bSG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}\b")),
    _Pattern("twilio_key", re.compile(r"\bSK[0-9a-fA-F]{32}\b")),
    _Pattern("npm_token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    _Pattern("pypi_token", re.compile(r"\bpypi-[A-Za-z0-9_\-]{50,}\b")),
    _Pattern("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")),
]

# Credentials embedded in URLs: scheme://user:password@host
_URL_CREDENTIALS = re.compile(r"(?P<prefix>\b[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s:/@'\"]+:)(?P<secret>[^\s@/'\"]{3,})(?P<suffix>@)")

_SENSITIVE_NAME = (
    r"(?:[A-Za-z0-9_\-]*?(?:password|passwd|pwd|secret|token|api[_\-]?key|apikey|access[_\-]?key|"
    r"private[_\-]?key|client[_\-]?secret|auth[_\-]?key|credential|signing[_\-]?key|encryption[_\-]?key|"
    r"webhook[_\-]?url|conn(?:ection)?[_\-]?string|dsn)[A-Za-z0-9_\-]*)"
)
# name = "value" / name: 'value' / "name": "value"
_QUOTED_ASSIGNMENT = re.compile(
    r"(?P<prefix>[\"']?(?P<name>" + _SENSITIVE_NAME + r")[\"']?\s*(?::=|=|:|=>)\s*[bru]?)"
    r"(?P<quote>[\"'])(?P<secret>[^\"'\n]{4,})(?P=quote)",
    re.IGNORECASE,
)
# NAME=value (dotenv / shell / ini style, unquoted)
_BARE_ASSIGNMENT = re.compile(
    r"(?:^|(?<=[\s|:;,]))(?P<prefix>(?:export\s+)?(?P<name>" + _SENSITIVE_NAME + r")\s*[=:]\s*)"
    r"(?P<secret>[^\s\"'#\[{(<][^\s#]{3,})",
    re.IGNORECASE,
)

_lock = threading.Lock()
_seen_secrets: set[str] = set()


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(value)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def looks_like_reference(value: str) -> bool:
    """True when the value refers to a secret instead of containing it."""
    v = value.strip()
    return (
        v.startswith(("$", "%", "{{", "<%", "env(", "os.environ", "process.env", "ENV["))
        or "${{" in v
        or "secrets." in v
        or v.lower() in {"true", "false", "none", "null", "required", "optional", "str", "string"}
        or "(" in v
        or v.endswith((",", ":"))
        or re.fullmatch(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+", v) is not None
        or re.fullmatch(r"[\w./\-]*\.[A-Za-z]{1,5}(?::\d+)?[,;.]?", v) is not None  # file reference like app.py:12
    )


def looks_like_code_identifier(value: str) -> bool:
    """Unquoted values that are type annotations or identifiers (``SecretStr``, ``Optional[str]``)."""
    v = value.strip().rstrip(",;")
    if "[" in v or "]" in v:
        return True
    return bool(re.fullmatch(r"[A-Za-z_]+", v)) and (bool(re.search(r"[a-z][A-Z]", v)) or v[0].isupper() and v[1:].islower())


def looks_like_placeholder(value: str) -> bool:
    v = value.lower()
    if any(h in v for h in PLACEHOLDER_HINTS):
        return True
    return len(set(v)) <= 2


def _annotation(kind: str, value: str) -> str:
    placeholder = "yes" if looks_like_placeholder(value) else "no"
    return f"[REDACTED:{kind} len={len(value)} entropy={_entropy(value):.1f} placeholder={placeholder}]"


def _remember(value: str) -> None:
    # Only distinctive values are scrubbed globally; short ones (e.g. "password", "admin123") would mangle
    # ordinary words elsewhere. Every value is still redacted wherever a detection pattern matches it.
    if (len(value) >= 10 and _entropy(value) >= 3.0 and not looks_like_placeholder(value)
            and not looks_like_reference(value)):
        with _lock:
            _seen_secrets.add(value)


def redact_line(line: str, remember: bool = True) -> str:
    _keep = _remember if remember else (lambda _v: None)
    out = line
    for pat in _TOKEN_PATTERNS:
        def _sub(m: re.Match[str], kind: str = pat.kind) -> str:
            val = m.group(0)
            if kind == "private_key_block":
                return "[REDACTED:private_key_block_header]"
            _keep(val)
            return _annotation(kind, val)
        out = pat.regex.sub(_sub, out)

    def _url_sub(m: re.Match[str]) -> str:
        val = m.group("secret")
        if looks_like_reference(val) or val.startswith("[REDACTED"):
            return m.group(0)
        _keep(val)
        return m.group("prefix") + _annotation("url_password", val) + m.group("suffix")
    out = _URL_CREDENTIALS.sub(_url_sub, out)

    def _assign_sub(m: re.Match[str]) -> str:
        val = m.group("secret")
        if looks_like_reference(val) or val.startswith("[REDACTED"):
            return m.group(0)
        _keep(val)
        quote = m.groupdict().get("quote") or ""
        return m.group("prefix") + quote + _annotation("assigned_secret", val) + quote
    out = _QUOTED_ASSIGNMENT.sub(_assign_sub, out)

    def _bare_sub(m: re.Match[str]) -> str:
        return m.group(0) if looks_like_code_identifier(m.group("secret")) else _assign_sub(m)
    out = _BARE_ASSIGNMENT.sub(_bare_sub, out)
    return out


def redact_text(text: str, remember: bool = True) -> str:
    """Redact secrets line by line (line structure and numbering are preserved).

    ``remember`` records detected values so they are scrubbed if they reappear verbatim anywhere later;
    pass False for text written by the agent itself (only repository content defines known secrets).
    """
    if not text:
        return text
    redacted = "\n".join(redact_line(line, remember) for line in text.split("\n"))
    return scrub_known(redacted)


def scrub_known(text: str) -> str:
    """Remove any previously detected secret value that may reappear verbatim."""
    with _lock:
        known = sorted(_seen_secrets, key=len, reverse=True)
    for value in known:
        if value in text:
            text = text.replace(value, "[REDACTED]")
    return text


def contains_secret(text: str) -> bool:
    return redact_text(text) != text


def reset_known_secrets() -> None:
    with _lock:
        _seen_secrets.clear()


def detect_secrets(line: str) -> list[dict]:
    """Return metadata (never the value) for each probable secret on a line."""
    found: list[dict] = []
    spans: list[tuple[int, int]] = []

    def _add(kind: str, value: str, start: int, end: int) -> None:
        if any(s <= start < e for s, e in spans):
            return
        spans.append((start, end))
        _remember(value)
        found.append({
            "kind": kind,
            "length": len(value),
            "entropy": round(_entropy(value), 1),
            "placeholder": looks_like_placeholder(value),
        })

    for pat in _TOKEN_PATTERNS:
        for m in pat.regex.finditer(line):
            _add(pat.kind, m.group(0), m.start(), m.end())
    for m in _URL_CREDENTIALS.finditer(line):
        val = m.group("secret")
        if not looks_like_reference(val):
            _add("url_password", val, m.start("secret"), m.end("secret"))
    for rx in (_QUOTED_ASSIGNMENT, _BARE_ASSIGNMENT):
        for m in rx.finditer(line):
            val = m.group("secret")
            if looks_like_reference(val) or (rx is _BARE_ASSIGNMENT and looks_like_code_identifier(val)):
                continue
            _add("assigned_secret:" + m.group("name").lower(), val, m.start("secret"), m.end("secret"))
    return found
