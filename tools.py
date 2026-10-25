"""Inspection tools available to the DevOps auditing agent.

Every tool is read-only with respect to the inspected repository: tools only list,
read, search and parse files, query git history, or run static analysers. The
single tool that executes repository code (``run_pytest``) does so exclusively
inside an isolated Docker sandbox (see ``audit_agent.sandbox``).

All text returned by a tool is passed through secret redaction before it reaches
the LLM, the trace file or the report.
"""

from __future__ import annotations

import ast
import fnmatch
import json
import os
import re
import subprocess
import sys
import tempfile
import tomllib
from collections import Counter, defaultdict
from collections.abc import Callable
from pathlib import Path, PurePosixPath
from typing import Any

import yaml

from audit_agent.redact import detect_secrets, redact_text
from audit_agent.repo import RepoCheckout, run_git
from audit_agent.sandbox import run_tests_in_sandbox

MAX_READ_BYTES = 2_000_000
MAX_READ_LINES = 400
TEXT_SNIFF_BYTES = 8192


class ToolError(Exception):
    """A tool failed in an expected way; the message is returned to the agent."""


# --------------------------------------------------------------------------- helpers

def _human_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024
    return f"{n}B"


def _is_binary(data: bytes) -> bool:
    return b"\x00" in data[:TEXT_SNIFF_BYTES]


VALID_GHA_EVENTS = {
    "branch_protection_rule", "check_run", "check_suite", "create", "delete", "deployment",
    "deployment_status", "discussion", "discussion_comment", "fork", "gollum", "issue_comment",
    "issues", "label", "merge_group", "milestone", "page_build", "project", "project_card",
    "project_column", "public", "pull_request", "pull_request_comment", "pull_request_review",
    "pull_request_review_comment", "pull_request_target", "push", "registry_package", "release",
    "repository_dispatch", "schedule", "status", "watch", "workflow_call", "workflow_dispatch",
    "workflow_run",
}

UNTRUSTED_CONTEXT = re.compile(
    r"\$\{\{\s*(github\.event\.(issue\.(title|body)|pull_request\.(title|body|head\.ref|head\.label|"
    r"head\.repo\.default_branch)|comment\.body|review\.body|review_comment\.body|pages\.[^}]*page_name|"
    r"commits[^}]*\.(message|author\.(email|name))|head_commit\.(message|author\.(email|name))|"
    r"workflow_run\.(head_branch|head_commit\.message|display_title)|discussion\.(title|body))|"
    r"github\.head_ref|inputs\.[A-Za-z0-9_\-]+)\s*\}\}"
)

MASKING_PATTERNS = [
    (re.compile(r"\|\|\s*true\b"), "'|| true' ignores the command's failure"),
    (re.compile(r"\|\|\s*:\s*($|;)"), "'|| :' ignores the command's failure"),
    (re.compile(r"\|\|\s*exit\s+0\b"), "'|| exit 0' ignores the command's failure"),
    (re.compile(r"\|\|\s*echo\b"), "'|| echo' ignores the command's failure"),
    (re.compile(r"(^|;|\n)\s*exit\s+0\s*($|\n)"), "explicit 'exit 0' forces success"),
    (re.compile(r"\bset\s+\+e\b"), "'set +e' disables fail-fast"),
    (re.compile(r"--exit-zero\b"), "'--exit-zero' makes the linter always succeed"),
    (re.compile(r"--collect-only\b"), "'--collect-only' collects tests without running them"),
    (re.compile(r"\s-k\s+[\"']?not\b"), "'-k not ...' deselects tests"),
    (re.compile(r"--deselect\b|--ignore[= ]"), "tests are deselected/ignored"),
    (re.compile(r"--no-verify\b"), "'--no-verify' skips verification hooks"),
    (re.compile(r"--continue-on-collection-errors\b"), "collection errors are tolerated"),
    (re.compile(r"\bpytest\b[^\n|;]*--maxfail=\d+[^\n]*\|\|"), "pytest failure handled by '||'"),
    (re.compile(r"--cov-fail-under[= ]0\b"), "coverage gate set to 0"),
]

TEST_COMMAND = re.compile(r"\b(pytest|py\.test|unittest|tox|nox|make\s+test|npm\s+(run\s+)?test|yarn\s+test|"
                          r"pnpm\s+test|go\s+test|cargo\s+test|mvn\s+(-\S+\s+)*(test|verify)|gradle\w*\s+test|"
                          r"manage\.py\s+test|hatch\s+(run\s+)?test|poetry\s+run\s+pytest|uv\s+run\s+pytest|"
                          r"coverage\s+run)\b")
LINT_COMMAND = re.compile(r"\b(ruff|flake8|pylint|black|isort|mypy|pyright|pre-commit|eslint|prettier|"
                          r"golangci-lint|clippy|rubocop|pycodestyle|pydocstyle|bandit|yapf|autopep8|"
                          r"super-linter|lint)\b")
DEPLOY_HINT = re.compile(r"\b(deploy|publish|release|twine\s+upload|docker\s+push|gh-pages|heroku|kubectl\s+apply|"
                         r"helm\s+upgrade|terraform\s+apply|aws\s+s3\s+(sync|cp)|npm\s+publish|"
                         r"pypa/gh-action-pypi-publish|serverless\s+deploy|vercel|netlify|firebase\s+deploy|"
                         r"flyctl\s+deploy|rsync|scp\s)", re.IGNORECASE)
AUTOMERGE_HINT = re.compile(r"(gh\s+pr\s+merge|enable-pull-request-automerge|pascalgn/automerge|auto-approve|"
                            r"gh\s+pr\s+review\s+--approve|automerge|auto-merge|merge_method|github\.rest\.pulls\.merge|"
                            r"pulls\.createReview)", re.IGNORECASE)
DEPRECATED_ACTIONS = {
    "actions/checkout": 3, "actions/setup-python": 4, "actions/setup-node": 3, "actions/cache": 3,
    "actions/upload-artifact": 4, "actions/download-artifact": 4, "actions/setup-java": 3,
    "actions/setup-go": 3, "actions/github-script": 6, "docker/build-push-action": 3,
    "codecov/codecov-action": 3,
}
RETIRED_RUNNERS = {"ubuntu-16.04", "ubuntu-18.04", "ubuntu-20.04", "windows-2016", "windows-2019",
                   "macos-10.15", "macos-11", "macos-12", "macos-13"}
EOL_PYTHON = {"2.7", "3.5", "3.6", "3.7", "3.8"}

IMPORT_TO_DIST = {
    "yaml": "pyyaml", "cv2": "opencv-python", "sklearn": "scikit-learn", "PIL": "pillow",
    "bs4": "beautifulsoup4", "dotenv": "python-dotenv", "jwt": "pyjwt", "dateutil": "python-dateutil",
    "attr": "attrs", "OpenSSL": "pyopenssl", "Crypto": "pycryptodome", "magic": "python-magic",
    "docx": "python-docx", "serial": "pyserial", "git": "gitpython", "jose": "python-jose",
    "multipart": "python-multipart", "telegram": "python-telegram-bot", "skimage": "scikit-image",
    "MySQLdb": "mysqlclient", "psycopg2": "psycopg2", "zmq": "pyzmq", "win32api": "pywin32",
    "fitz": "pymupdf", "Levenshtein": "python-levenshtein", "google": "google-*", "pkg_resources": "setuptools",
    "setuptools": "setuptools", "_pytest": "pytest", "flask_sqlalchemy": "flask-sqlalchemy",
    "flask_cors": "flask-cors", "jinja2": "jinja2", "markupsafe": "markupsafe", "dns": "dnspython",
    "Bio": "biopython", "slugify": "python-slugify", "socketio": "python-socketio", "decouple": "python-decouple",
    "pydantic_settings": "pydantic-settings", "rest_framework": "djangorestframework", "lxml": "lxml",
    "sentry_sdk": "sentry-sdk", "ldap": "python-ldap", "nacl": "pynacl", "redis": "redis",
}

SENSITIVE_FILE_PATTERNS = [
    ".env", ".env.*", "*.env", ".envrc", "*.pem", "*.key", "*.p12", "*.pfx", "*.jks", "*.keystore", "id_rsa",
    "id_rsa*", "id_dsa*", "id_ecdsa*", "id_ed25519*", "*.ppk", ".npmrc", ".pypirc", ".netrc", "credentials",
    "credentials.json", "*credentials*.json", "service-account*.json", "*.tfstate", "*.tfstate.*", "*.tfvars",
    ".htpasswd", "secrets.*", "*secret*.yml", "*secret*.yaml", "*.kdbx", ".git-credentials", ".dockercfg",
    ".docker/config.json", "kubeconfig", "*.kubeconfig",
]
SAFE_ENV_TEMPLATES = (".env.example", ".env.sample", ".env.template", ".env.dist", ".env.defaults",
                      "example.env", "sample.env", ".env.test.example")
ARTIFACT_PATTERNS = {
    "python bytecode / caches": ["*.pyc", "*.pyo", "__pycache__/*", ".pytest_cache/*", ".mypy_cache/*",
                                 ".ruff_cache/*", ".tox/*", ".nox/*", ".hypothesis/*"],
    "virtual environments": ["venv/*", ".venv/*", "env/*", "virtualenv/*", "*/site-packages/*", "pyvenv.cfg"],
    "build / dist outputs": ["build/*", "dist/*", "*.egg-info/*", "*.whl", "target/*", "out/*", "*.o", "*.so",
                             "*.class", "*.exe", "*.dll"],
    "dependency directories": ["node_modules/*", "bower_components/*", "vendor/bundle/*"],
    "coverage / test reports": [".coverage", ".coverage.*", "coverage.xml", "htmlcov/*", "coverage/*",
                                "junit*.xml", "test-results/*", "nosetests.xml"],
    "logs / temporary files": ["*.log", "*.tmp", "*.temp", "*.swp", "*.swo", "*~", "*.bak", "*.orig", "tmp/*",
                               "temp/*", "nohup.out", "*.pid"],
    "OS metadata": [".DS_Store", "Thumbs.db", "desktop.ini", "__MACOSX/*"],
    "editor / IDE local settings": [".idea/*", ".vscode/settings.json", ".vscode/launch.json", "*.iml",
                                    "*.code-workspace", ".project", ".classpath", "*.sublime-workspace"],
    "local configuration overrides": ["*.local", "*.local.*", "local_settings.py", "settings_local.py",
                                      "*.local.json", "docker-compose.override.yml", "config.local.*"],
    "databases / data dumps": ["*.sqlite", "*.sqlite3", "*.db", "*.dump", "*.rdb"],
    "jupyter checkpoints": [".ipynb_checkpoints/*"],
    "archives": ["*.zip", "*.tar", "*.tar.gz", "*.tgz", "*.rar", "*.7z"],
}


def _match_any(path: str, patterns: list[str]) -> bool:
    name = PurePosixPath(path).name
    for pat in patterns:
        if "/" in pat:
            prefix = pat.rstrip("*").rstrip("/")
            if path.startswith(prefix + "/") or f"/{prefix}/" in f"/{path}" or fnmatch.fnmatch(path, pat):
                return True
        elif fnmatch.fnmatch(name, pat):
            return True
    return False


# --------------------------------------------------------------------------- tool class

class RepoTools:
    """Read-only inspection tools bound to one checked-out repository."""

    def __init__(self, checkout: RepoCheckout, command_timeout: int = 60, sandbox_timeout: int = 600):
        self.checkout = checkout
        self.root = checkout.root.resolve()
        self.timeout = command_timeout
        self.sandbox_timeout = sandbox_timeout
        self._tracked: list[str] | None = None

    # ------------------------------------------------------------------ internals
    def tracked_files(self) -> list[str]:
        if self._tracked is None:
            proc = run_git(["ls-files", "-z"], self.root, timeout=self.timeout)
            if proc.returncode != 0:
                raise ToolError(f"git ls-files failed: {proc.stderr.strip()[:200]}")
            self._tracked = sorted(p for p in proc.stdout.split("\0") if p)
        return self._tracked

    def _resolve(self, rel: str) -> Path:
        if rel is None:
            raise ToolError("path is required")
        rel = str(rel).strip().lstrip("/") or "."
        if rel.startswith("./"):
            rel = rel[2:] or "."
        candidate = (self.root / rel)
        try:
            resolved = candidate.resolve()
        except (OSError, RuntimeError) as exc:
            raise ToolError(f"cannot resolve path {rel!r}: {exc}") from exc
        if resolved != self.root and self.root not in resolved.parents:
            raise ToolError(f"path {rel!r} escapes the repository root (symlink or '..'); refusing to read it")
        parts = PurePosixPath(rel).parts
        if parts and parts[0] == ".git":
            raise ToolError("the .git directory is internal git metadata; use git_log instead")
        return resolved

    def _read_text(self, rel: str) -> str | None:
        try:
            p = self._resolve(rel)
        except ToolError:
            return None
        if not p.is_file() or p.stat().st_size > MAX_READ_BYTES:
            return None
        data = p.read_bytes()
        if _is_binary(data):
            return None
        return data.decode("utf-8", errors="replace")

    def file_exists(self, rel: str) -> bool:
        return rel in set(self.tracked_files())

    def line_count(self, rel: str) -> int | None:
        text = self._read_text(rel)
        return None if text is None else len(text.splitlines())

    # ------------------------------------------------------------------ list_files
    def list_files(self, path: str = ".", max_entries: int = 300) -> str:
        files = self.tracked_files()
        prefix = "" if path in (None, "", ".", "./") else str(path).strip("/").removeprefix("./") + "/"
        sel = [f for f in files if f.startswith(prefix)] if prefix else files
        if prefix and not sel:
            if (self.root / prefix.rstrip("/")).is_file():
                sel = [prefix.rstrip("/")]
            else:
                raise ToolError(f"no tracked files under {path!r}")
        max_entries = max(20, min(int(max_entries or 300), 1000))
        header = (f"{len(sel)} tracked files under '{prefix or '.'}' (repository total: {len(files)}). "
                  f"Default branch: {self.checkout.default_branch}.")
        lines = [header]
        if len(sel) <= max_entries:
            for f in sel:
                p = self.root / f
                size = ""
                try:
                    if p.is_symlink():
                        size = f" -> symlink to {os.readlink(p)}"
                    elif p.is_file():
                        size = f" ({_human_size(p.stat().st_size)})"
                except OSError:
                    pass
                lines.append(f"{f}{size}")
        else:
            depth = len(PurePosixPath(prefix).parts) + 1
            dirs: Counter[str] = Counter()
            top_files = []
            for f in sel:
                parts = PurePosixPath(f).parts
                if len(parts) <= depth:
                    top_files.append(f)
                else:
                    dirs["/".join(parts[:depth]) + "/"] += 1
            lines.append("Too many files to list individually; summary by directory (use path=<dir> to drill down):")
            for d, n in sorted(dirs.items()):
                lines.append(f"{d}  [{n} files]")
            lines.append("Files at this level:")
            lines.extend(top_files[:max_entries])
        exts = Counter(PurePosixPath(f).suffix.lower() or PurePosixPath(f).name for f in sel)
        lines.append("File types: " + ", ".join(f"{e}:{n}" for e, n in exts.most_common(15)))
        return "\n".join(lines)

    # ------------------------------------------------------------------ read_file
    def read_file(self, path: str, start_line: int = 1, end_line: int | None = None) -> str:
        p = self._resolve(path)
        if not p.exists():
            raise ToolError(f"file {path!r} does not exist in the repository")
        if p.is_dir():
            raise ToolError(f"{path!r} is a directory; use list_files(path={path!r})")
        size = p.stat().st_size
        if size > MAX_READ_BYTES:
            raise ToolError(f"{path!r} is {_human_size(size)}; too large to read (limit {_human_size(MAX_READ_BYTES)})")
        data = p.read_bytes()
        if _is_binary(data):
            return f"{path} is a binary file ({_human_size(size)}); contents not shown."
        text = data.decode("utf-8", errors="replace")
        all_lines = text.splitlines()
        total = len(all_lines)
        start = max(1, int(start_line or 1))
        end = total if end_line in (None, 0) else min(total, int(end_line))
        if end - start + 1 > MAX_READ_LINES:
            end = start + MAX_READ_LINES - 1
        tracked = "tracked" if path.strip("/").removeprefix("./") in set(self.tracked_files()) else "NOT tracked by git"
        out = [f"{path} ({total} lines, {_human_size(size)}, {tracked}) showing lines {start}-{end}:"]
        width = len(str(end))
        for i in range(start - 1, end):
            out.append(f"{str(i + 1).rjust(width)}| {redact_text(all_lines[i])}")
        if end < total:
            out.append(f"... {total - end} more lines; call read_file with start_line={end + 1} to continue")
        if total == 0:
            out.append("(empty file)")
        return redact_text("\n".join(out))

    # ------------------------------------------------------------------ search_code
    def search_code(self, pattern: str, path_glob: str | None = None, ignore_case: bool = False,
                    max_results: int = 60) -> str:
        if not pattern or not isinstance(pattern, str):
            raise ToolError("pattern must be a non-empty regular expression string")
        if len(pattern) > 500:
            raise ToolError("pattern too long (max 500 characters)")
        try:
            re.compile(pattern)
        except re.error as exc:
            raise ToolError(f"invalid regular expression: {exc}") from exc
        max_results = max(1, min(int(max_results or 60), 200))
        args = ["grep", "-n", "-I", "-E", "--no-color", "--full-name"]
        if ignore_case:
            args.append("-i")
        args += ["-e", pattern, "--"]
        if path_glob:
            # Plain git pathspecs already match '*.py' at any depth; '**' needs glob magic.
            args.append(f":(glob){path_glob}" if "**" in path_glob else path_glob)
        try:
            proc = run_git(args, self.root, timeout=self.timeout)
        except subprocess.TimeoutExpired as exc:
            raise ToolError(f"search timed out after {self.timeout}s; use a narrower pattern or path_glob") from exc
        if proc.returncode == 1:
            return f"No matches for /{pattern}/" + (f" in {path_glob}" if path_glob else "") + " (tracked files only)."
        if proc.returncode not in (0, 1):
            raise ToolError(f"search failed: {proc.stderr.strip()[:300]}")
        hits = proc.stdout.splitlines()
        files = Counter(h.split(":", 1)[0] for h in hits)
        out = [f"{len(hits)} matching lines in {len(files)} files for /{pattern}/ (format path:line:text):"]
        for h in hits[:max_results]:
            fpath, _, rest = h.partition(":")
            lno, _, text = rest.partition(":")
            h = f"{fpath}:{lno}:{redact_text(text)}"
            out.append(h if len(h) <= 300 else h[:300] + " ...[line truncated]")
        if len(hits) > max_results:
            out.append(f"... {len(hits) - max_results} more matches not shown. Files with most matches: "
                       + ", ".join(f"{f} ({n})" for f, n in files.most_common(10)))
        return redact_text("\n".join(out))

    # ------------------------------------------------------------------ git_log
    def git_log(self, max_count: int = 30, path: str | None = None, show_files: bool = False,
                search: str | None = None) -> str:
        max_count = max(1, min(int(max_count or 30), 200))
        fmt = "--pretty=format:%h | %ad | %an | %s"
        args = ["log", f"--max-count={max_count}", "--date=short", fmt, "--no-color"]
        if search:
            try:
                re.compile(search)
            except re.error as exc:
                raise ToolError(f"invalid search regex: {exc}") from exc
            args += ["-G", search, "-p", "--unified=0", "--no-ext-diff"]
        elif show_files:
            args.append("--name-status")
        if path:
            self._resolve(path) if not path.startswith(":") else None
            args += ["--", path]
        try:
            proc = run_git(args, self.root, timeout=self.timeout)
        except subprocess.TimeoutExpired as exc:
            raise ToolError("git log timed out") from exc
        if proc.returncode != 0:
            raise ToolError(f"git log failed: {proc.stderr.strip()[:300]}")
        body = proc.stdout
        if search:
            # keep commit headers, file headers and changed lines that match the search pattern
            rx = re.compile(search)
            kept = []
            for line in body.splitlines():
                if " | " in line and not line.startswith(("+", "-", " ")):
                    kept.append(line)
                elif line.startswith("diff --git"):
                    kept.append("  " + line.split(" b/", 1)[-1].join(["file: ", ""]))
                elif line.startswith(("+", "-")) and not line.startswith(("+++", "---")) and rx.search(line):
                    kept.append(("  added:   " if line[0] == "+" else "  removed: ") + line[1:][:240])
            body = "\n".join(kept) or "(no commits change lines matching the pattern)"
        total = run_git(["rev-list", "--count", "HEAD"], self.root).stdout.strip()
        authors = run_git(["shortlog", "-sn", "--no-merges", "HEAD"], self.root).stdout.strip().splitlines()
        header = (f"Commits in clone: {total}{' (shallow clone; older history truncated)' if self.checkout.shallow else ''}; "
                  f"distinct authors: {len(authors)}. Showing up to {max_count}"
                  f"{' commits touching ' + path if path else ''}{' whose diff matches /' + search + '/' if search else ''}:")
        return redact_text(header + "\n" + (body or "(no commits)"))

    # ------------------------------------------------------------------ find_tracked_artifacts
    def find_tracked_artifacts(self) -> str:
        files = self.tracked_files()
        out: list[str] = []
        gi = self.root / ".gitignore"
        out.append(f".gitignore at root: {'present' if gi.is_file() else 'ABSENT'}"
                   + (f" ({len(gi.read_text(errors='replace').splitlines())} lines)" if gi.is_file() else ""))
        nested = [f for f in files if f.endswith("/.gitignore")]
        if nested:
            out.append("Nested .gitignore files: " + ", ".join(nested[:10]))
        ignored = run_git(["ls-files", "-ci", "--exclude-standard"], self.root, timeout=self.timeout)
        ign = [x for x in ignored.stdout.splitlines() if x]
        out.append(f"\nTracked files that match the repo's own ignore rules ({len(ign)}):")
        out.extend(f"  {x}" for x in ign[:30])
        if len(ign) > 30:
            out.append(f"  ... {len(ign) - 30} more")
        out.append("\nTracked files matching common generated/temporary/local patterns:")
        any_hit = False
        for label, pats in ARTIFACT_PATTERNS.items():
            hits = [f for f in files if _match_any(f, pats)]
            if hits:
                any_hit = True
                out.append(f"  [{label}] {len(hits)} file(s): " + ", ".join(hits[:12]) + (" ..." if len(hits) > 12 else ""))
        if not any_hit:
            out.append("  none")
        sens = [f for f in files if _match_any(f, SENSITIVE_FILE_PATTERNS)
                and PurePosixPath(f).name.lower() not in SAFE_ENV_TEMPLATES]
        templates = [f for f in files if PurePosixPath(f).name.lower() in SAFE_ENV_TEMPLATES]
        out.append("\nTracked files that commonly hold credentials/local secrets: " + (", ".join(sens) if sens else "none"))
        if templates:
            out.append("Environment templates (acceptable, check they hold no real values): " + ", ".join(templates))
        large = []
        for f in files:
            try:
                s = (self.root / f).stat().st_size
            except OSError:
                continue
            if s > 1_000_000:
                large.append(f"{f} ({_human_size(s)})")
        out.append("\nTracked files larger than 1MB: " + (", ".join(large[:15]) if large else "none"))
        out.append("\nNote: matches are candidates; confirm with read_file/list_files before reporting.")
        return "\n".join(out)

    # ------------------------------------------------------------------ scan_secrets
    def scan_secrets(self, include_history: bool = True) -> str:
        files = self.tracked_files()
        findings = []
        for f in files:
            text = self._read_text(f)
            if text is None:
                continue
            for i, line in enumerate(text.splitlines(), 1):
                if len(line) > 2000:
                    line = line[:2000]
                for d in detect_secrets(line):
                    findings.append((f, i, d, redact_text(line.strip())[:200]))
        out = [f"Working-tree secret scan of {len(files)} tracked files: {len(findings)} candidate(s)."]
        for f, i, d, ctx in findings[:60]:
            out.append(f"  {f}:{i} kind={d['kind']} len={d['length']} entropy={d['entropy']} "
                       f"placeholder_like={'yes' if d['placeholder'] else 'no'} | {ctx}")
        if len(findings) > 60:
            out.append(f"  ... {len(findings) - 60} more")
        if include_history:
            out.append("\nGit history scan (secrets in past commits that are no longer present in HEAD):")
            current = {(f, d["kind"]) for f, _, d, _ in findings}
            try:
                proc = run_git(["log", "-p", "--no-color", "--unified=0", "--max-count=500", "--no-ext-diff",
                                "--pretty=format:@@COMMIT %h %ad %s", "--date=short"], self.root, timeout=self.timeout)
                hist = []
                commit, fname = "", ""
                for line in proc.stdout.splitlines()[:400_000]:
                    if line.startswith("@@COMMIT "):
                        commit = line[9:]
                    elif line.startswith("+++ b/"):
                        fname = line[6:]
                    elif line.startswith("+") and not line.startswith("+++"):
                        for d in detect_secrets(line[1:][:2000]):
                            key = (fname, d["kind"])
                            if not d["placeholder"] and key not in current:
                                hist.append(f"  commit {commit[:60]} file={fname} kind={d['kind']} len={d['length']} "
                                            f"entropy={d['entropy']}")
                                current.add(key)
                out.extend(hist[:30] or ["  none found"])
            except subprocess.TimeoutExpired:
                out.append("  history scan timed out (not completed)")
        out.append("\nValues are never shown. 'placeholder_like=yes' usually means a dummy/example value; "
                   "references such as ${{ secrets.X }} or os.environ[...] are not reported. Verify context with read_file.")
        return "\n".join(out)

    # ------------------------------------------------------------------ inspect_ci
    def inspect_ci(self) -> str:
        files = self.tracked_files()
        default = self.checkout.default_branch or "main"
        wf = [f for f in files if re.match(r"^\.github/workflows/[^/]+\.ya?ml$", f)]
        misplaced = [f for f in files if f.startswith(".github/") and re.search(r"\.ya?ml(\.\w+)?$", f)
                     and f not in wf and not f.startswith(".github/ISSUE_TEMPLATE")
                     and PurePosixPath(f).name not in {"dependabot.yml", "dependabot.yaml", "FUNDING.yml",
                                                       "release.yml", "labeler.yml", "config.yml", "stale.yml",
                                                       "release-drafter.yml", "CODEOWNERS"}]
        other_ci = {
            "GitLab CI": ".gitlab-ci.yml", "Travis CI": ".travis.yml", "Jenkins": "Jenkinsfile",
            "CircleCI": ".circleci/config.yml", "Azure Pipelines": "azure-pipelines.yml",
            "Bitbucket Pipelines": "bitbucket-pipelines.yml", "Drone": ".drone.yml", "AppVeyor": "appveyor.yml",
            "pre-commit": ".pre-commit-config.yaml", "tox": "tox.ini", "nox": "noxfile.py", "Makefile": "Makefile",
            "Dependabot": ".github/dependabot.yml", "Renovate": "renovate.json", "CODEOWNERS": ".github/CODEOWNERS",
        }
        out = [f"Default branch: {default}", f"GitHub Actions workflow files: {len(wf)}"]
        present = [f"{k} ({v})" for k, v in other_ci.items() if v in files or v.replace(".yml", ".yaml") in files]
        if "CODEOWNERS" in files or "docs/CODEOWNERS" in files:
            present.append("CODEOWNERS")
        out.append("Other CI/automation config present: " + (", ".join(present) if present else "none"))
        if misplaced:
            out.append("YAML files under .github/ that are NOT in .github/workflows/*.yml|yaml (GitHub will not run "
                       "them as workflows): " + ", ".join(misplaced))
        any_tests = any_lint = False
        for f in wf:
            text = self._read_text(f) or ""
            lines = text.splitlines()

            def line_of(snippet: str, after: int = 0, lines: list[str] = lines) -> str:
                needle = snippet.strip().splitlines()[0][:60] if snippet.strip() else ""
                for idx in range(after, len(lines)):
                    if needle and needle in lines[idx]:
                        return f"~L{idx + 1}"
                return "L?"

            out.append(f"\n== {f}")
            try:
                doc = yaml.safe_load(text)
            except yaml.YAMLError as exc:
                out.append(f"  YAML PARSE ERROR (workflow will not run): {str(exc).splitlines()[0][:200]}")
                continue
            if not isinstance(doc, dict):
                out.append("  not a mapping; GitHub cannot parse this workflow")
                continue
            flags: list[str] = []
            out.append(f"  name: {doc.get('name', '(unnamed)')}")
            on = doc.get("on", doc.get(True))
            triggers = self._describe_triggers(on, default, flags)
            out.append(f"  triggers: {triggers}")
            perms = doc.get("permissions", "<not set: GITHUB_TOKEN gets the repository/org default permissions>")
            out.append(f"  top-level permissions: {json.dumps(perms) if not isinstance(perms, str) else perms}")
            self._check_permissions(perms, "workflow", flags, on)
            if "env" in doc:
                out.append(f"  workflow env keys: {list(doc['env'].keys()) if isinstance(doc['env'], dict) else doc['env']}")
            jobs = doc.get("jobs") or {}
            if not isinstance(jobs, dict) or not jobs:
                flags.append("no jobs defined")
                jobs = {}
            event_names = set(self._event_names(on))
            for jname, job in jobs.items():
                if not isinstance(job, dict):
                    continue
                jline = line_of(f"{jname}:")
                desc = [f"runs-on={job.get('runs-on')}"]
                for key in ("needs", "if", "environment", "continue-on-error", "permissions", "timeout-minutes", "uses"):
                    if key in job:
                        desc.append(f"{key}={json.dumps(job[key]) if not isinstance(job[key], str) else job[key]}")
                strat = job.get("strategy", {}) if isinstance(job.get("strategy"), dict) else {}
                if strat.get("matrix"):
                    desc.append(f"matrix={json.dumps(strat['matrix'])[:200]}")
                out.append(f"  job '{jname}' ({jline}): " + "; ".join(desc))
                self._check_permissions(job.get("permissions"), f"job '{jname}'", flags, on)
                ro = job.get("runs-on")
                for r in (ro if isinstance(ro, list) else [ro]):
                    if isinstance(r, str) and r in RETIRED_RUNNERS:
                        flags.append(f"job '{jname}' uses retired/deprecated runner '{r}' ({jline})")
                if job.get("continue-on-error") in (True, "true"):
                    flags.append(f"job '{jname}' has continue-on-error: true -> failures never fail the workflow ({jline})")
                if str(job.get("if", "")).strip() in ("false", "${{ false }}", "0"):
                    flags.append(f"job '{jname}' is disabled with if: false ({jline})")
                needs = job.get("needs")
                needs_list = needs if isinstance(needs, list) else ([needs] if needs else [])
                for n in needs_list:
                    if n not in jobs:
                        flags.append(f"job '{jname}' needs unknown job '{n}' (workflow invalid) ({jline})")
                pyvers = json.dumps(strat.get("matrix", {}))
                for v in EOL_PYTHON:
                    if re.search(rf'"{re.escape(v)}"|\b{re.escape(v)}\b(?!\.)', pyvers) and "python" in pyvers.lower():
                        flags.append(f"job '{jname}' matrix tests end-of-life Python {v} ({jline})")
                steps = job.get("steps") or []
                job_text_parts = []
                for si, step in enumerate(steps if isinstance(steps, list) else [], 1):
                    if not isinstance(step, dict):
                        continue
                    label = step.get("name") or step.get("uses") or (str(step.get("run", ""))[:40])
                    sdesc = []
                    if "uses" in step:
                        uses = str(step["uses"])
                        sdesc.append(f"uses {uses}")
                        self._check_action_ref(uses, f"job '{jname}' step {si}", flags, line_of(uses))
                        with_ = step.get("with") or {}
                        if isinstance(with_, dict):
                            if "ref" in with_:
                                sdesc.append(f"with.ref={with_['ref']}")
                            if "python-version" in with_:
                                sdesc.append(f"python-version={with_['python-version']}")
                                if str(with_["python-version"]) in EOL_PYTHON:
                                    flags.append(f"job '{jname}' step {si} uses end-of-life Python {with_['python-version']}")
                            if "persist-credentials" in with_:
                                sdesc.append(f"persist-credentials={with_['persist-credentials']}")
                        if (uses.startswith("actions/checkout") and isinstance(with_, dict)
                                and "github.event.pull_request.head" in str(with_.get("ref", "")) + str(with_.get("repository", ""))
                                and event_names & {"pull_request_target", "workflow_run"}):
                            flags.append(f"CRITICAL PATTERN: job '{jname}' checks out untrusted PR head code in a "
                                         f"privileged {sorted(event_names & {'pull_request_target', 'workflow_run'})} workflow "
                                         f"({line_of('github.event.pull_request.head')})")
                    if "run" in step:
                        run = str(step["run"])
                        job_text_parts.append(run)
                        short = " ".join(run.split())
                        sdesc.append(f"run: {short[:220]}{'...' if len(short) > 220 else ''}")
                        rline = line_of(run)
                        for rx, why in MASKING_PATTERNS:
                            if rx.search(run):
                                flags.append(f"job '{jname}' step {si} ({rline}): {why}")
                        for m in UNTRUSTED_CONTEXT.finditer(run):
                            flags.append(f"job '{jname}' step {si} ({rline}): untrusted expression {m.group(0)} "
                                         "interpolated directly into a shell script (script injection)")
                        if re.search(r"(echo|printf|cat)\b[^\n]*\$\{\{\s*secrets\.", run) or re.search(r"\bset\s+-x\b", run) and "secrets." in run:
                            flags.append(f"job '{jname}' step {si} ({rline}): secret value printed to logs")
                        if re.search(r"\b(printenv|env)\s*($|\||>)", run):
                            flags.append(f"job '{jname}' step {si} ({rline}): dumps environment to logs")
                        if re.search(r"curl[^\n|]*\|\s*(sudo\s+)?(ba)?sh\b", run):
                            flags.append(f"job '{jname}' step {si} ({rline}): pipes remote script into shell")
                        if "::set-output" in run or "::save-state" in run:
                            flags.append(f"job '{jname}' step {si} ({rline}): deprecated ::set-output/::save-state command")
                    if step.get("continue-on-error") in (True, "true"):
                        flags.append(f"job '{jname}' step {si} '{label}' has continue-on-error: true "
                                     f"({line_of('continue-on-error', int(jline[2:]) - 1 if jline.startswith('~L') else 0)})")
                    if str(step.get("if", "")).strip() in ("false", "${{ false }}", "0"):
                        flags.append(f"job '{jname}' step {si} '{label}' disabled with if: false")
                    if step.get("env"):
                        sdesc.append(f"env keys={list(step['env'].keys()) if isinstance(step['env'], dict) else step['env']}")
                    if step.get("if"):
                        sdesc.append(f"if={step['if']}")
                    if "uses" in step:
                        job_text_parts.append(str(step["uses"]))
                    out.append(f"    step {si}: " + "; ".join(sdesc))
                job_text = "\n".join(job_text_parts)
                has_tests = bool(TEST_COMMAND.search(job_text))
                has_lint = bool(LINT_COMMAND.search(job_text))
                any_tests |= has_tests
                any_lint |= has_lint
                if DEPLOY_HINT.search(job_text) or DEPLOY_HINT.search(str(jname)):
                    gate = "needs=" + str(needs_list) if needs_list else "NO needs: dependency on a test/build job"
                    flags.append(f"job '{jname}' looks like deploy/publish ({jline}); {gate}; triggers={sorted(event_names)}; "
                                 f"if={job.get('if', '<none>')}; environment={job.get('environment', '<none>')}")
                if AUTOMERGE_HINT.search(job_text):
                    flags.append(f"job '{jname}' performs PR approval/merge automation ({jline}); if={job.get('if', '<none>')}")
            flags = list(dict.fromkeys(flags))
            if flags:
                out.append("  heuristic flags (verify each with read_file before reporting):")
                out.extend(f"   - {x}" for x in flags)
            else:
                out.append("  heuristic flags: none")
        out.append(f"\nAcross all workflows: test command found={any_tests}; lint/format/type-check command found={any_lint}.")
        return redact_text("\n".join(out))

    @staticmethod
    def _event_names(on: Any) -> list[str]:
        if isinstance(on, str):
            return [on]
        if isinstance(on, list):
            return [str(x) for x in on]
        if isinstance(on, dict):
            return [str(k) for k in on]
        return []

    def _describe_triggers(self, on: Any, default: str, flags: list[str]) -> str:
        if on is None:
            flags.append("no 'on:' triggers -> workflow never runs")
            return "<none>"
        names = self._event_names(on)
        parts = []
        for name in names:
            if name not in VALID_GHA_EVENTS:
                flags.append(f"unknown trigger event '{name}' (typo? GitHub will reject/ignore it)")
            cfg = on.get(name) if isinstance(on, dict) else None
            detail = ""
            if isinstance(cfg, dict):
                bits = []
                for key in ("branches", "branches-ignore", "tags", "paths", "paths-ignore", "types"):
                    if key in cfg:
                        bits.append(f"{key}={cfg[key]}")
                if name == "schedule":
                    bits.append(str(cfg))
                detail = "(" + ", ".join(bits) + ")" if bits else ""
                br = cfg.get("branches")
                if name in ("push", "pull_request", "pull_request_target") and isinstance(br, (list, str)):
                    brs = br if isinstance(br, list) else [br]
                    if not any(fnmatch.fnmatch(default, str(b)) for b in brs):
                        flags.append(f"'{name}' branch filter {brs} does not match the default branch '{default}' "
                                     f"-> the workflow does not run for the main line of development")
                bri = cfg.get("branches-ignore")
                if isinstance(bri, list) and any(fnmatch.fnmatch(default, str(b)) for b in bri):
                    flags.append(f"'{name}' branches-ignore excludes the default branch '{default}'")
                pi = cfg.get("paths-ignore")
                if isinstance(pi, list) and any(p in ("**", "**/*", "**.py", "*.py", "**/*.py", "src/**") for p in pi):
                    flags.append(f"'{name}' paths-ignore {pi} skips the workflow for source-code changes")
            elif isinstance(on, list) and name == "schedule":
                detail = ""
            parts.append(name + detail)
        if names and not set(names) & {"push", "pull_request", "pull_request_target", "merge_group", "workflow_call"}:
            flags.append(f"workflow only runs on {names}; it is not triggered by pushes or pull requests")
        if "pull_request_target" in names:
            flags.append("uses pull_request_target (runs with base-repo secrets and write token; dangerous if PR code is "
                         "checked out/executed)")
        return ", ".join(parts)

    @staticmethod
    def _check_permissions(perms: Any, scope: str, flags: list[str], on: Any) -> None:
        if perms is None or (isinstance(perms, str) and perms.startswith("<not set")):
            return
        if perms in ("write-all",):
            flags.append(f"{scope} grants permissions: write-all to GITHUB_TOKEN")
        elif isinstance(perms, dict):
            writes = [k for k, v in perms.items() if str(v) == "write"]
            if writes:
                flags.append(f"{scope} grants write permissions: {writes} (check they are needed)")

    @staticmethod
    def _check_action_ref(uses: str, where: str, flags: list[str], line: str) -> None:
        if uses.startswith(("./", "docker://")):
            return
        if "@" not in uses:
            flags.append(f"{where}: action '{uses}' has no version ref ({line})")
            return
        name, ref = uses.rsplit("@", 1)
        if ref in ("master", "main", "latest", "HEAD", "develop", "dev"):
            flags.append(f"{where}: action '{uses}' pinned to mutable branch ref '{ref}' ({line})")
        m = re.match(r"v?(\d+)", ref)
        base = "/".join(name.split("/")[:2])
        if m and base in DEPRECATED_ACTIONS and int(m.group(1)) < DEPRECATED_ACTIONS[base]:
            flags.append(f"{where}: '{uses}' is a deprecated major version (minimum maintained: "
                         f"v{DEPRECATED_ACTIONS[base]}) ({line})")

    # ------------------------------------------------------------------ dependency_overview
    def dependency_overview(self) -> str:
        files = self.tracked_files()
        names = {f: PurePosixPath(f).name for f in files}
        manifest_names = {
            "requirements.txt", "pyproject.toml", "setup.py", "setup.cfg", "Pipfile", "Pipfile.lock", "poetry.lock",
            "uv.lock", "pdm.lock", "environment.yml", "environment.yaml", "conda.yml", "constraints.txt",
            "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json", "bun.lockb",
            "go.mod", "go.sum", "Cargo.toml", "Cargo.lock", "Gemfile", "Gemfile.lock", "pom.xml", "build.gradle",
            "build.gradle.kts", "composer.json", "composer.lock", "Dockerfile", "docker-compose.yml",
            "docker-compose.yaml", "compose.yml", "compose.yaml", ".python-version", "runtime.txt", ".tool-versions",
            ".nvmrc", "tox.ini", "noxfile.py", "Makefile", "MANIFEST.in",
        }
        found = [f for f in files if names[f] in manifest_names or re.match(r"^requirements[\w.\-]*\.(txt|in)$", names[f])
                 or (f.startswith("requirements/") and f.endswith((".txt", ".in"))) or names[f].startswith("Dockerfile")]
        found = [f for f in found if not _match_any(f, ["node_modules/*", "venv/*", ".venv/*", "site-packages/*"])]
        out = ["Dependency / build manifests found: " + (", ".join(found) if found else "NONE")]
        declared: dict[str, list[tuple[str, str]]] = defaultdict(list)
        python_versions: list[str] = []

        for f in found:
            n = names[f]
            text = self._read_text(f) or ""
            if re.match(r"^requirements.*\.(txt|in)$", n) or f.startswith("requirements/") or n == "constraints.txt":
                out.append(f"\n[{f}]")
                out.extend("  " + x for x in self._parse_requirements(f, text, declared))
            elif n == "pyproject.toml":
                out.append(f"\n[{f}]")
                out.extend("  " + x for x in self._parse_pyproject(f, text, declared, python_versions))
            elif n == "setup.py":
                out.append(f"\n[{f}] (parsed statically, not executed)")
                out.extend("  " + x for x in self._parse_setup_py(f, text, declared, python_versions))
            elif n == "setup.cfg":
                m = re.search(r"install_requires\s*=\s*\n((?:[ \t]+.+\n?)+)", text)
                if m:
                    reqs = [x.strip() for x in m.group(1).splitlines() if x.strip()]
                    out.append(f"\n[{f}] install_requires: {reqs}")
                    for r in reqs:
                        nm, spec = self._split_req(r)
                        if nm:
                            declared[nm].append((f, spec))
                m = re.search(r"python_requires\s*=\s*(.+)", text)
                if m:
                    python_versions.append(f"{f}: python_requires {m.group(1).strip()}")
            elif n == "Pipfile":
                out.append(f"\n[{f}] Pipfile present; Pipfile.lock {'present' if any(names[x] == 'Pipfile.lock' for x in files) else 'ABSENT'}")
                for line in text.splitlines():
                    mm = re.match(r'^\s*([A-Za-z0-9_.\-]+)\s*=\s*"(.*)"', line)
                    if mm and mm.group(1) not in ("url", "verify_ssl", "name", "python_version"):
                        declared[mm.group(1).lower()].append((f, mm.group(2)))
                    if "python_version" in line:
                        python_versions.append(f"{f}: {line.strip()}")
            elif n == "package.json":
                out.append(f"\n[{f}]")
                out.extend("  " + x for x in self._parse_package_json(f, text, files))
            elif n in (".python-version", "runtime.txt"):
                python_versions.append(f"{f}: {text.strip()[:40]}")
            elif n.startswith("Dockerfile"):
                froms = re.findall(r"^\s*FROM\s+(\S+)", text, re.MULTILINE | re.IGNORECASE)
                user = re.findall(r"^\s*USER\s+(\S+)", text, re.MULTILINE | re.IGNORECASE)
                out.append(f"\n[{f}] FROM {froms}; USER {user or '<not set: runs as root>'}; "
                           f".dockerignore {'present' if '.dockerignore' in files else 'ABSENT'}")
                for b in froms:
                    if b.startswith("python:"):
                        python_versions.append(f"{f}: {b}")
                    if ":" not in b and b.lower() != "scratch" and not b.startswith("$"):
                        out.append(f"  base image '{b}' has no tag (implicit :latest)")
                    elif b.endswith(":latest"):
                        out.append(f"  base image '{b}' uses mutable :latest tag")
                for i, line in enumerate(text.splitlines(), 1):
                    if re.match(r"^\s*(ENV|ARG)\s+\S*(PASSWORD|SECRET|TOKEN|API_KEY|ACCESS_KEY)\S*[ =]\S+", line, re.I):
                        out.append(f"  {f}:{i} credential-like value set via ENV/ARG")
        lock_names = {"poetry.lock", "uv.lock", "pdm.lock", "Pipfile.lock", "package-lock.json", "yarn.lock",
                      "pnpm-lock.yaml", "npm-shrinkwrap.json", "bun.lockb", "go.sum", "Cargo.lock", "Gemfile.lock",
                      "composer.lock"}
        locks = [f for f in found if names[f] in lock_names]
        out.append("\nLockfiles: " + (", ".join(locks) if locks else "none"))
        multi = {k: v for k, v in declared.items() if len({s for _, s in v}) > 1}
        if multi:
            out.append("Packages declared in several places with DIFFERENT constraints:")
            for k, v in sorted(multi.items()):
                out.append(f"  {k}: " + "; ".join(f"{s or '<unconstrained>'} in {f}" for f, s in v))
        if python_versions:
            out.append("Python version declarations (check consistency with CI matrix): " + " | ".join(python_versions))
        versions = self._version_declarations()
        if versions:
            out.append("Project version declarations (should agree): " + " | ".join(versions))
        out.extend(self._undeclared_imports(declared))
        return redact_text("\n".join(out))

    def _version_declarations(self) -> list[str]:
        found = []
        rx = re.compile(r"""^\s*(?:__version__|version|VERSION)\s*[=:]\s*["']([0-9][\w.+\-]*)["']""", re.MULTILINE)
        for f in self.tracked_files():
            name = PurePosixPath(f).name
            if len(PurePosixPath(f).parts) > 3 or not (
                    name in ("pyproject.toml", "setup.py", "setup.cfg", "__init__.py", "_version.py", "version.py",
                             "__about__.py", "package.json", "Cargo.toml") or name == "VERSION"):
                continue
            text = self._read_text(f) or ""
            if name == "package.json":
                m = re.search(r'"version"\s*:\s*"([^"]+)"', text)
            elif name == "VERSION":
                m = re.match(r"\s*([0-9][\w.+\-]*)", text)
            else:
                m = rx.search(text)
            if m:
                line = text[: m.start(1)].count("\n") + 1
                found.append(f"{f}:{line} -> {m.group(1)}")
        return found

    @staticmethod
    def _split_req(req: str) -> tuple[str | None, str]:
        req = req.split(";")[0].split("#")[0].strip().strip("'\",")
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._\-]*)(\[[^\]]*\])?\s*(.*)$", req)
        if not m:
            return None, req
        return m.group(1).lower().replace("_", "-"), m.group(3).strip()

    def _parse_requirements(self, f: str, text: str, declared: dict) -> list[str]:
        lines_out, counts = [], Counter()
        weak: list[str] = []
        for i, raw in enumerate(text.splitlines(), 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith(("-r", "--requirement", "-c", "--constraint")):
                lines_out.append(f"L{i}: includes {line}")
                continue
            if line.startswith(("--index-url", "-i", "--extra-index-url", "--trusted-host", "--find-links", "-f")):
                note = ""
                if "http://" in line:
                    note = " (INSECURE plain-http index)"
                if line.startswith("--extra-index-url"):
                    note += " (extra index: dependency-confusion risk)"
                if line.startswith("--trusted-host"):
                    note += " (disables TLS verification for host)"
                lines_out.append(f"L{i}: {line}{note}")
                continue
            if line.startswith(("-e", "git+", "http", "./", ".")) or "@" in line and "://" in line:
                kind = "vcs/url/editable" + (" without pinned commit" if ("git+" in line and "@" not in line.split("git+")[-1]) else "")
                counts[kind] += 1
                lines_out.append(f"L{i}: {line[:120]} -> {kind}")
                continue
            name, spec = self._split_req(line)
            if not name:
                continue
            declared[name].append((f, spec))
            if "==" in spec or "===" in spec:
                kind = "pinned (==)"
            elif "~=" in spec:
                kind = "compatible (~=)"
            elif ">" in spec and "<" in spec:
                kind = "bounded range"
            elif ">" in spec:
                kind = "lower-bound only (>=)"
                weak.append(f"{name}{spec} (L{i})")
            elif "<" in spec or "!=" in spec:
                kind = "upper-bound/exclusion only"
            else:
                kind = "UNCONSTRAINED"
                weak.append(f"{name} (L{i})")
            counts[kind] += 1
        dupes = [n for n, v in declared.items() if sum(1 for ff, _ in v if ff == f) > 1]
        summary = [f"{sum(counts.values())} requirements: " + ", ".join(f"{k}={v}" for k, v in counts.items())]
        if weak:
            summary.append("unconstrained/lower-bound-only entries: " + ", ".join(weak[:25]))
        if dupes:
            summary.append("DUPLICATE entries in this file: " + ", ".join(dupes))
        return summary + lines_out[:20]

    def _parse_pyproject(self, f: str, text: str, declared: dict, pyv: list[str]) -> list[str]:
        try:
            data = tomllib.loads(text)
        except tomllib.TOMLDecodeError as exc:
            return [f"INVALID TOML: {exc}"]
        out = []
        proj = data.get("project", {})
        bs = data.get("build-system")
        out.append(f"build-system: {bs if bs else 'ABSENT'}")
        if proj:
            deps = proj.get("dependencies", [])
            out.append(f"[project] name={proj.get('name')} version={proj.get('version', proj.get('dynamic'))} "
                       f"requires-python={proj.get('requires-python')}")
            out.append(f"dependencies ({len(deps)}): {deps[:40]}")
            for r in deps:
                n, s = self._split_req(r)
                if n:
                    declared[n].append((f, s))
            opt = proj.get("optional-dependencies", {})
            if opt:
                out.append("optional-dependencies: " + json.dumps(opt)[:600])
                for group in opt.values():
                    for r in group:
                        n, s = self._split_req(r)
                        if n:
                            declared[n].append((f + "[optional]", s))
            if proj.get("requires-python"):
                pyv.append(f"{f}: requires-python {proj['requires-python']}")
        groups = data.get("dependency-groups", {})
        if groups:
            out.append("dependency-groups: " + json.dumps(groups)[:400])
            for group in groups.values():
                for r in group:
                    if isinstance(r, str):
                        n, s = self._split_req(r)
                        if n:
                            declared[n].append((f + "[group]", s))
        poetry = data.get("tool", {}).get("poetry", {})
        if poetry:
            pdeps = poetry.get("dependencies", {})
            out.append(f"[tool.poetry] dependencies: {json.dumps(pdeps)[:500]}")
            for n, s in pdeps.items():
                if n.lower() == "python":
                    pyv.append(f"{f}: poetry python {s}")
                else:
                    declared[n.lower()].append((f, s if isinstance(s, str) else json.dumps(s)))
            for gname, g in poetry.get("group", {}).items():
                for n, s in (g.get("dependencies") or {}).items():
                    declared[n.lower()].append((f + f"[{gname}]", s if isinstance(s, str) else json.dumps(s)))
        tools = sorted(data.get("tool", {}).keys())
        out.append(f"[tool.*] sections: {tools}")
        return out

    def _parse_setup_py(self, f: str, text: str, declared: dict, pyv: list[str]) -> list[str]:
        out = []
        try:
            tree = ast.parse(text)
        except SyntaxError as exc:
            return [f"setup.py has a syntax error: {exc}"]
        for node in ast.walk(tree):
            if isinstance(node, ast.keyword) and node.arg in ("install_requires", "tests_require", "python_requires",
                                                               "extras_require", "setup_requires"):
                try:
                    val = ast.literal_eval(node.value)
                except (ValueError, SyntaxError):
                    val = "<computed dynamically>"
                out.append(f"{node.arg}: {val}")
                if node.arg == "install_requires" and isinstance(val, (list, tuple)):
                    for r in val:
                        n, s = self._split_req(str(r))
                        if n:
                            declared[n].append((f, s))
                if node.arg == "python_requires":
                    pyv.append(f"{f}: python_requires {val}")
        return out or ["no install_requires found"]

    def _parse_package_json(self, f: str, text: str, files: list[str]) -> list[str]:
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            return [f"INVALID JSON: {exc}"]
        d = Path(f).parent.as_posix()
        d = "" if d == "." else d + "/"
        locks = [x for x in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json", "bun.lockb")
                 if d + x in files]
        out = [f"name={data.get('name')} private={data.get('private')} lockfile={locks or 'ABSENT'}",
               f"scripts: {json.dumps(data.get('scripts', {}))[:400]}"]
        for key in ("dependencies", "devDependencies"):
            deps = data.get(key, {}) or {}
            loose = [f"{k}@{v}" for k, v in deps.items() if v in ("*", "latest", "") or str(v).startswith((">", "x"))]
            out.append(f"{key}: {len(deps)} entries" + (f"; unbounded: {loose}" if loose else ""))
        return out

    def _undeclared_imports(self, declared: dict) -> list[str]:
        files = [f for f in self.tracked_files() if f.endswith(".py")]
        if not files or not declared:
            return [] if not files else ["(Python files present but no Python dependency manifest declares packages.)"]
        local = set()
        for f in files:
            parts = PurePosixPath(f).parts
            local.add(PurePosixPath(parts[-1]).stem)
            local.update(parts[:-1])
        std = set(sys.stdlib_module_names) | {"__future__"}
        imports: dict[str, str] = {}
        for f in files[:800]:
            text = self._read_text(f)
            if not text:
                continue
            try:
                tree = ast.parse(text)
            except SyntaxError:
                continue
            for node in ast.walk(tree):
                mods = []
                if isinstance(node, ast.Import):
                    mods = [a.name for a in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                    mods = [node.module]
                for mname in mods:
                    top = mname.split(".")[0]
                    if top not in std and top not in local and top not in imports:
                        imports[top] = f"{f}:{node.lineno}"
        norm_declared = {k.lower().replace("_", "-") for k in declared}
        missing = []
        for top, where in sorted(imports.items()):
            dist = IMPORT_TO_DIST.get(top, top).lower().replace("_", "-")
            if dist.endswith("*"):
                if any(d.startswith(dist[:-1]) for d in norm_declared):
                    continue
            elif dist in norm_declared or top.lower().replace("_", "-") in norm_declared:
                continue
            missing.append(f"{top} (first import at {where})")
        res = [f"Third-party imports found: {sorted(imports)[:50]}"]
        if missing:
            res.append("Imports with NO matching declared dependency (could be transitive, optional, test-only, or a "
                       "different distribution name - verify): " + ", ".join(missing[:30]))
        return res

    # ------------------------------------------------------------------ run_ruff
    def run_ruff(self, path: str | None = None) -> str:
        target = "."
        if path:
            self._resolve(path)
            target = path
        cmd = [sys.executable, "-m", "ruff", "check", "--output-format=json", "--no-cache", "--exit-zero",
               "--force-exclude", target]
        # An empty HOME/XDG_CONFIG_HOME ensures only the repository's own ruff configuration is honoured.
        with tempfile.TemporaryDirectory(prefix="ruff-home-") as home:
            env = {"PATH": os.environ.get("PATH", ""), "HOME": home, "XDG_CONFIG_HOME": home}
            try:
                proc = subprocess.run(cmd, cwd=self.root, capture_output=True, text=True, errors="replace",
                                      timeout=self.timeout * 2, check=False, env=env)
            except FileNotFoundError as exc:
                raise ToolError("ruff is not installed in the agent environment; check unavailable") from exc
            except subprocess.TimeoutExpired as exc:
                raise ToolError("ruff timed out; check unavailable") from exc
        if proc.returncode not in (0, 1):
            err = proc.stderr.strip().splitlines()
            raise ToolError("ruff could not run (often an invalid ruff config in the repo): " + (err[-1] if err else "")[:300])
        try:
            results = json.loads(proc.stdout or "[]")
        except json.JSONDecodeError as exc:
            raise ToolError(f"could not parse ruff output: {exc}") from exc
        cfg = [f for f in ("ruff.toml", ".ruff.toml", "pyproject.toml", "setup.cfg", ".flake8", "tox.ini", ".pylintrc")
               if (self.root / f).is_file()]
        uses_cfg = any(("[tool.ruff" in (self._read_text(c) or "")) for c in cfg if c.endswith("pyproject.toml")) or \
            any(c in ("ruff.toml", ".ruff.toml") for c in cfg)
        by_code: dict[str, list] = defaultdict(list)
        for r in results:
            by_code[str(r.get("code") or "syntax-error")].append(r)
        out = [f"ruff {'(repository ruff config)' if uses_cfg else '(ruff default rule set; repo has no ruff config)'} "
               f"found {len(results)} issue(s) in {len({r.get('filename') for r in results})} file(s)."]
        for code, items in sorted(by_code.items(), key=lambda kv: -len(kv[1]))[:25]:
            msg = items[0].get("message", "")
            locs = ", ".join(f"{os.path.relpath(i['filename'], self.root)}:{i['location']['row']}" for i in items[:5])
            out.append(f"  {code} x{len(items)}: {msg[:120]} | e.g. {locs}")
        out.append("Note: style findings alone are rarely DevOps violations; syntax errors (E9/invalid-syntax), "
                   "undefined names (F821) and bare excepts (E722) indicate real defects.")
        return redact_text("\n".join(out))

    # ------------------------------------------------------------------ run_pytest
    def run_pytest(self, test_path: str | None = None) -> str:
        if test_path:
            self._resolve(test_path)
            test_path = test_path.strip("/").removeprefix("./")
        res = run_tests_in_sandbox(self.root, test_path, timeout=self.sandbox_timeout)
        if not res.get("available"):
            return f"run_pytest UNAVAILABLE: {res.get('reason')}. Do not infer test results; rely on static evidence."
        if not res.get("completed"):
            return f"run_pytest did not complete: {res.get('reason')}. Treat test status as unknown."
        lines = [f"pytest exit code: {res.get('pytest_exit_code')} (0=all passed, 1=test failures, 2=interrupted/"
                 f"collection errors, 3=internal error, 4=usage error, 5=no tests collected)",
                 "Dependency installation log (tail):", res.get("install_log", "").strip()[-1200:] or "(quiet)",
                 "pytest output (tail):", res.get("output", "").strip()]
        lines.append("Interpretation guidance: ImportError/ModuleNotFoundError during collection usually indicates "
                     "missing/undeclared dependencies or an environment limitation (no network, no services), not "
                     "necessarily failing tests. AssertionError failures are genuine test failures.")
        return redact_text("\n".join(lines))


# --------------------------------------------------------------------------- tool schemas

TOOL_SPECS: list[dict[str, Any]] = [
    {
        "name": "list_files",
        "description": "List files tracked by git (what is committed). For large repositories returns a per-directory "
                       "summary; pass path to drill into a directory. Also shows sizes and file-type counts.",
        "input_schema": {"type": "object", "properties": {
            "path": {"type": "string", "description": "Directory relative to repo root ('.' for all)."},
            "max_entries": {"type": "integer", "description": "Max individual entries (default 300)."}}},
    },
    {
        "name": "read_file",
        "description": "Read a text file with line numbers (max 400 lines per call; use start_line/end_line to page). "
                       "Secret values are redacted automatically.",
        "input_schema": {"type": "object", "properties": {
            "path": {"type": "string"}, "start_line": {"type": "integer"}, "end_line": {"type": "integer"}},
            "required": ["path"]},
    },
    {
        "name": "search_code",
        "description": "Search tracked files with a POSIX extended regex (git grep -E). Returns path:line:text. Use "
                       "path_glob (e.g. '*.py', 'src/**') to narrow. Good for hardcoded paths, credentials, debug flags, "
                       "unsafe calls, config usage.",
        "input_schema": {"type": "object", "properties": {
            "pattern": {"type": "string"}, "path_glob": {"type": "string"},
            "ignore_case": {"type": "boolean"}, "max_results": {"type": "integer"}},
            "required": ["pattern"]},
    },
    {
        "name": "git_log",
        "description": "Inspect commit history: recent commits (hash | date | author | subject). show_files=true adds "
                       "changed files per commit; path limits to a file/dir; search=<regex> lists commits whose diff "
                       "added/removed matching lines (pickaxe), e.g. to find secrets or files removed later.",
        "input_schema": {"type": "object", "properties": {
            "max_count": {"type": "integer"}, "path": {"type": "string"},
            "show_files": {"type": "boolean"}, "search": {"type": "string"}}},
    },
    {
        "name": "find_tracked_artifacts",
        "description": "Repository hygiene check: .gitignore presence, tracked files that match ignore rules, tracked "
                       "generated/temporary/IDE/local files, credential-type files, and large files.",
        "input_schema": {"type": "object", "properties": {}},
    },
    {
        "name": "scan_secrets",
        "description": "Scan all tracked files (and optionally git history) for hardcoded credentials using provider "
                       "token formats and sensitive assignments. Reports file:line, kind, entropy and placeholder "
                       "likelihood; values are never revealed.",
        "input_schema": {"type": "object", "properties": {"include_history": {"type": "boolean"}}},
    },
    {
        "name": "inspect_ci",
        "description": "Parse GitHub Actions workflows (triggers, permissions, jobs, steps, action refs) and other CI "
                       "configs. Emits heuristic flags (failure masking, injection, broad permissions, branch filter "
                       "mismatches, pull_request_target, deploy gating, deprecated actions) that MUST be verified.",
        "input_schema": {"type": "object", "properties": {}},
    },
    {
        "name": "dependency_overview",
        "description": "Find and statically parse dependency manifests/lockfiles (requirements*, pyproject, setup.py, "
                       "Pipfile, package.json, Dockerfile...). Reports constraint strength, duplicates, conflicting "
                       "specs across files, missing lockfiles, Python version declarations and third-party imports "
                       "not declared in any manifest.",
        "input_schema": {"type": "object", "properties": {}},
    },
    {
        "name": "run_ruff",
        "description": "Run the ruff linter statically (no code execution) on the repo or a sub-path; summarises "
                       "issues by rule code. Useful to evidence syntax errors, undefined names and obvious "
                       "maintainability problems.",
        "input_schema": {"type": "object", "properties": {"path": {"type": "string"}}},
    },
    {
        "name": "run_pytest",
        "description": "Run the repository's pytest suite inside an isolated Docker sandbox (dependencies installed "
                       "first, tests run with no network, non-root, resource limits). Slow (1-5 min); use only when "
                       "a Python test-suite exists and its pass/fail status matters. Reports UNAVAILABLE if Docker "
                       "is missing.",
        "input_schema": {"type": "object", "properties": {
            "test_path": {"type": "string", "description": "Optional test file/dir relative to the repo root."}}},
    },
]


def build_dispatch(tools: RepoTools) -> dict[str, Callable[..., str]]:
    return {
        "list_files": tools.list_files,
        "read_file": tools.read_file,
        "search_code": tools.search_code,
        "git_log": tools.git_log,
        "find_tracked_artifacts": tools.find_tracked_artifacts,
        "scan_secrets": tools.scan_secrets,
        "inspect_ci": tools.inspect_ci,
        "dependency_overview": tools.dependency_overview,
        "run_ruff": tools.run_ruff,
        "run_pytest": tools.run_pytest,
    }
