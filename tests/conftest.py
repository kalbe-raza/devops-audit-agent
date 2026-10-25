from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from audit_agent.redact import reset_known_secrets  # noqa: E402
from audit_agent.repo import open_local_repository  # noqa: E402
from tools import RepoTools  # noqa: E402

# Built at runtime so that no credential-shaped literal is committed in this repository.
FAKE_AWS_KEY = "AKIA" + "Z7QW3RTY8UIOPLKJ"
FAKE_GH_TOKEN = "ghp_" + "Zq9Xw8Vu7Ts6Rq5Po4Nm3Lk2Ji1Hg0FeDcBa"


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(["git", "-c", "user.name=Test", "-c", "user.email=test@example.com", *args], cwd=cwd,
                   check=True, capture_output=True)


def make_repo(root: Path, commits: list[tuple[str, dict[str, str | bytes], list[str]]]) -> Path:
    """Create a git repo with the given (message, files, deleted_paths) commits on branch main."""
    root.mkdir(parents=True, exist_ok=True)
    _git(root, "init", "-q", "-b", "main")
    for message, files, deletes in commits:
        for rel, content in files.items():
            path = root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(content, bytes):
                path.write_bytes(content)
            else:
                path.write_text(content)
        for rel in deletes:
            (root / rel).unlink()
        _git(root, "add", "-A")
        _git(root, "commit", "-q", "-m", message)
    return root


@pytest.fixture(autouse=True)
def _clean_secret_memory():
    reset_known_secrets()
    yield
    reset_known_secrets()


@pytest.fixture
def defect_repo(tmp_path: Path) -> Path:
    return make_repo(tmp_path / "defect", [
        ("init", {
            "app.py": "import requests\nDATA = '/home/alice/data.csv'\n\ndef get():\n"
                      "    return requests.get('https://x.example', verify=False)\n",
            "settings.py": f'AWS_KEY = "{FAKE_AWS_KEY}"\nDEBUG = True\n',
            "requirements.txt": "requests\nflask>=2.0\n",
            ".env": "DB_PASSWORD=Zx81!kqLmP0\n",
            "__pycache__/app.cpython-312.pyc": b"\x00\x01\x02",
            ".github/workflows/ci.yml": (
                "name: CI\non:\n  push:\n    branches: [master]\npermissions: write-all\njobs:\n  test:\n"
                "    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@main\n"
                "      - run: pytest || true\n        continue-on-error: true\n"
                "      - run: echo \"${{ github.event.head_commit.message }}\"\n"),
        }, []),
        ("add token", {"deploy.py": f'TOKEN = "{FAKE_GH_TOKEN}"\n'}, []),
        ("remove token", {}, ["deploy.py"]),
    ])


@pytest.fixture
def healthy_repo(tmp_path: Path) -> Path:
    return make_repo(tmp_path / "healthy", [
        ("init", {
            "README.md": "# Demo\n\nRun `pytest`.\n",
            ".gitignore": "__pycache__/\n.env\n.venv/\n",
            ".env.example": "API_TOKEN=your-token-here\n",
            "pyproject.toml": "[project]\nname='demo'\nversion='1.0.0'\ndependencies=['click>=8,<9']\n"
                              "[tool.ruff]\nline-length=100\n",
            "demo/__init__.py": "",
            "demo/main.py": "import os\n\nimport click\n\nTOKEN = os.environ.get('API_TOKEN')\n",
            "tests/test_main.py": "def test_ok():\n    assert 1 + 1 == 2\n",
            ".github/workflows/ci.yml": (
                "name: CI\non:\n  push:\n    branches: [main]\n  pull_request:\npermissions:\n  contents: read\n"
                "jobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n"
                "      - run: pip install -e . pytest ruff\n      - run: ruff check .\n      - run: pytest -q\n"),
        }, []),
    ])


@pytest.fixture
def defect_tools(defect_repo: Path) -> RepoTools:
    return RepoTools(open_local_repository(str(defect_repo)))


@pytest.fixture
def healthy_tools(healthy_repo: Path) -> RepoTools:
    return RepoTools(open_local_repository(str(healthy_repo)))
