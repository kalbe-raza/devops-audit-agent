"""Isolated execution of the target repository's test-suite.

Untrusted repository code is never executed on the host. Tests run in two
throw-away Docker containers that share only a dependency volume:

1. ``install`` - network enabled (needed for pip), repository mounted read-only,
   dependencies installed into the volume.
2. ``test`` - ``--network none``, read-only root filesystem, non-root user, all
   capabilities dropped, memory/CPU/PID limits, repository copied to a tmpfs.

No host environment variables (and therefore no API keys) are passed to either
container. If Docker is unavailable the check is reported as unavailable; no
result is ever guessed.
"""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import uuid
from pathlib import Path

DEFAULT_IMAGE = "python:3.12-slim"

_HARDENING = [
    "--rm",
    "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges",
    "--pids-limit", "256",
    "--memory", "1536m",
    "--cpus", "2",
    "--env", "PIP_DISABLE_PIP_VERSION_CHECK=1",
    "--env", "PYTHONDONTWRITEBYTECODE=1",
    "--env", "HOME=/tmp",
]

_INSTALL_SCRIPT = r"""
set -u
cp -a /src/. /tmp/work/ 2>/dev/null || true
cd /tmp/work
status=0
pip install --quiet --no-input --target /deps pytest >/tmp/pip.log 2>&1 || status=1
for f in requirements.txt requirements-dev.txt requirements_dev.txt requirements-test.txt test-requirements.txt dev-requirements.txt requirements/dev.txt requirements/test.txt; do
  if [ -f "$f" ]; then
    echo "installing $f"
    pip install --quiet --no-input --target /deps -r "$f" >>/tmp/pip.log 2>&1 || { echo "pip failed for $f"; status=1; }
  fi
done
if [ -f pyproject.toml ] || [ -f setup.py ] || [ -f setup.cfg ]; then
  echo "installing project"
  pip install --quiet --no-input --target /deps ".[test]" >>/tmp/pip.log 2>&1 \
    || pip install --quiet --no-input --target /deps . >>/tmp/pip.log 2>&1 \
    || { echo "pip failed for project"; status=1; }
fi
if [ "$status" -ne 0 ]; then echo "--- pip log tail ---"; tail -n 25 /tmp/pip.log; fi
chmod -R a+rX /deps 2>/dev/null || true
exit 0
"""

_TEST_SCRIPT = r"""
set -u
mkdir -p /tmp/work && cp -a /src/. /tmp/work/ 2>/dev/null || true
cd /tmp/work
export PYTHONPATH="/tmp/work:/tmp/work/src:/deps"
python -m pytest -q -rfE --tb=short --maxfail=25 -p no:cacheprovider --color=no {extra} 2>&1 | tail -n 120
echo "PYTEST_EXIT_CODE=${{PIPESTATUS[0]}}"
"""


def docker_available() -> tuple[bool, str]:
    if os.environ.get("ENABLE_DOCKER_TESTS", "auto").lower() in {"0", "false", "no", "off"}:
        return False, "sandboxed test execution disabled by ENABLE_DOCKER_TESTS"
    if shutil.which("docker") is None:
        return False, "docker executable not found"
    try:
        proc = subprocess.run(["docker", "info", "--format", "{{.ServerVersion}}"], capture_output=True,
                              text=True, timeout=20, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"docker daemon not reachable: {exc}"
    if proc.returncode != 0:
        return False, "docker daemon not reachable (permission denied or not running)"
    return True, proc.stdout.strip()


def _docker(args: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["docker", *args], capture_output=True, text=True, errors="replace",
                          timeout=timeout, check=False, env={"PATH": os.environ.get("PATH", "")})


def run_tests_in_sandbox(repo_root: Path, test_path: str | None = None, timeout: int = 600) -> dict:
    """Run pytest for ``repo_root`` in isolated containers. Returns a result dict.

    ``test_path`` must already be validated by the caller as a relative path inside the repo.
    """
    ok, info = docker_available()
    if not ok:
        return {"available": False, "reason": info}
    image = os.environ.get("SANDBOX_IMAGE", DEFAULT_IMAGE)
    volume = f"devops-audit-deps-{uuid.uuid4().hex[:12]}"
    src = f"{repo_root.resolve()}:/src:ro"
    safe_args = shlex.quote(test_path) if test_path else ""
    try:
        create = _docker(["volume", "create", volume], 30)
        if create.returncode != 0:
            return {"available": False, "reason": f"could not create docker volume: {create.stderr.strip()[:200]}"}
        try:
            install = _docker(["run", *_HARDENING, "--network", "bridge", "--tmpfs", "/tmp:rw,exec,size=1g",
                               "-v", src, "-v", f"{volume}:/deps", image, "sh", "-c", _INSTALL_SCRIPT],
                              timeout)
        except subprocess.TimeoutExpired:
            return {"available": True, "completed": False, "reason": f"dependency installation exceeded {timeout}s"}
        if install.returncode != 0 and "Unable to find image" in install.stderr and "Error" in install.stderr:
            return {"available": False, "reason": f"sandbox image {image} unavailable: {install.stderr.strip()[-200:]}"}
        try:
            test = _docker(["run", *_HARDENING, "--network", "none", "--read-only", "--user", "65534:65534",
                            "--tmpfs", "/tmp:rw,exec,size=1g", "-v", src, "-v", f"{volume}:/deps:ro",
                            image, "bash", "-c", _TEST_SCRIPT.format(extra=safe_args)], timeout)
        except subprocess.TimeoutExpired:
            return {"available": True, "completed": False, "reason": f"test run exceeded {timeout}s",
                    "install_log": install.stdout[-1500:]}
        out = test.stdout
        code = None
        for line in out.splitlines()[::-1]:
            if line.startswith("PYTEST_EXIT_CODE="):
                code = int(line.split("=", 1)[1]) if line.split("=", 1)[1].isdigit() else None
                break
        return {
            "available": True,
            "completed": True,
            "pytest_exit_code": code,
            "install_log": install.stdout[-1500:],
            "output": out[-6000:],
            "stderr": test.stderr[-800:],
        }
    finally:
        _docker(["volume", "rm", "-f", volume], 60)
