"""Repository URL validation and safe, read-only acquisition of the target repo.

The target is cloned into a private temporary directory. Nothing is ever pushed,
git hooks are disabled, submodules and LFS objects are not fetched, and no
repository code is executed by this module.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

GITHUB_URL = re.compile(
    r"^(?:https?://)?(?:www\.)?github\.com/(?P<owner>[A-Za-z0-9](?:[A-Za-z0-9\-]{0,38}))/"
    r"(?P<name>[A-Za-z0-9._\-]{1,100}?)(?:\.git)?"
    r"(?:/tree/(?P<ref>[A-Za-z0-9._/\-]{1,200}))?/?$"
)
GITHUB_SSH = re.compile(r"^git@github\.com:(?P<owner>[A-Za-z0-9\-]+)/(?P<name>[A-Za-z0-9._\-]+?)(?:\.git)?$")


class RepoError(Exception):
    """Raised when the repository cannot be validated or acquired."""


@dataclass
class RepoSpec:
    owner: str
    name: str
    ref: str | None = None

    @property
    def canonical_url(self) -> str:
        return f"https://github.com/{self.owner}/{self.name}"

    @property
    def clone_url(self) -> str:
        return f"{self.canonical_url}.git"


@dataclass
class RepoCheckout:
    root: Path
    url: str
    default_branch: str | None
    head_commit: str | None
    commit_count: int | None
    shallow: bool
    _tmpdir: str | None = field(default=None, repr=False)

    def cleanup(self) -> None:
        if self._tmpdir and os.path.isdir(self._tmpdir):
            shutil.rmtree(self._tmpdir, ignore_errors=True)


def parse_github_url(url: str) -> RepoSpec:
    if not url or not isinstance(url, str):
        raise RepoError("Repository URL is empty.")
    url = url.strip()
    m = GITHUB_URL.match(url) or GITHUB_SSH.match(url)
    if not m:
        raise RepoError(
            f"Not a valid public GitHub repository URL: {url!r}. "
            "Expected the form https://github.com/<owner>/<repo>"
        )
    name = m.group("name")
    if name in {".", ".."}:
        raise RepoError(f"Invalid repository name in URL: {url!r}")
    ref = m.groupdict().get("ref")
    return RepoSpec(owner=m.group("owner"), name=name, ref=ref.rstrip("/") if ref else None)


def safe_git_env() -> dict[str, str]:
    """Environment for git subprocesses: never prompt, never run hooks or LFS filters."""
    env = {k: v for k, v in os.environ.items() if not k.upper().endswith(("_API_KEY", "_TOKEN", "API_KEY"))}
    env.update({
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "/bin/true",
        "GIT_LFS_SKIP_SMUDGE": "1",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "LC_ALL": "C",
    })
    return env


SAFE_GIT_FLAGS = [
    "-c", "core.hooksPath=/dev/null",
    "-c", "protocol.file.allow=never",
    "-c", "protocol.ext.allow=never",
    "-c", "core.fsmonitor=false",
    "-c", "core.symlinks=true",
    "-c", "safe.directory=*",
]


def run_git(args: list[str], cwd: Path | None, timeout: int = 60) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *SAFE_GIT_FLAGS, *args],
        cwd=str(cwd) if cwd else None,
        env=safe_git_env(),
        capture_output=True,
        text=True,
        errors="replace",
        timeout=timeout,
        check=False,
    )


def _describe(root: Path, url: str, tmpdir: str | None) -> RepoCheckout:
    head = run_git(["rev-parse", "HEAD"], root)
    branch = run_git(["symbolic-ref", "--short", "-q", "refs/remotes/origin/HEAD"], root)
    default_branch = branch.stdout.strip().removeprefix("origin/") or None
    if not default_branch:
        cur = run_git(["rev-parse", "--abbrev-ref", "HEAD"], root)
        default_branch = cur.stdout.strip() or None
    count = run_git(["rev-list", "--count", "HEAD"], root)
    shallow = run_git(["rev-parse", "--is-shallow-repository"], root).stdout.strip() == "true"
    return RepoCheckout(
        root=root,
        url=url,
        default_branch=default_branch,
        head_commit=head.stdout.strip() or None,
        commit_count=int(count.stdout.strip()) if count.stdout.strip().isdigit() else None,
        shallow=shallow,
        _tmpdir=tmpdir,
    )


def clone_repository(spec: RepoSpec, timeout: int = 300, max_commits: int = 500) -> RepoCheckout:
    if shutil.which("git") is None:
        raise RepoError("git executable not found on PATH; it is required to inspect repositories.")
    tmpdir = tempfile.mkdtemp(prefix="devops-audit-")
    dest = Path(tmpdir) / "repo"
    args = ["clone", "--quiet", "--no-tags", "--single-branch", f"--depth={max_commits}",
            "--no-recurse-submodules"]
    if spec.ref:
        args += ["--branch", spec.ref]
    args += [spec.clone_url, str(dest)]
    try:
        proc = run_git(args, None, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        shutil.rmtree(tmpdir, ignore_errors=True)
        raise RepoError(f"Cloning {spec.canonical_url} timed out after {timeout}s.") from exc
    if proc.returncode != 0:
        shutil.rmtree(tmpdir, ignore_errors=True)
        err = (proc.stderr or "").strip().splitlines()
        detail = err[-1] if err else "unknown error"
        if "could not read Username" in (proc.stderr or "") or "not found" in (proc.stderr or "").lower():
            detail = "repository not found or not public"
        raise RepoError(f"Failed to clone {spec.canonical_url}: {detail}")
    checkout = _describe(dest, spec.canonical_url, tmpdir)
    if not checkout.head_commit:
        checkout.cleanup()
        raise RepoError(f"Repository {spec.canonical_url} appears to be empty (no commits).")
    return checkout


def open_local_repository(path: str, url: str | None = None) -> RepoCheckout:
    """Use an existing local git repository (development/testing aid). It is only read."""
    root = Path(path).expanduser().resolve()
    if not (root / ".git").exists():
        raise RepoError(f"{root} is not a git repository.")
    return _describe(root, url or root.as_uri(), None)
