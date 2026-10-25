"""Build the local evaluation repositories (scenarios A-E) with known injected DevOps defects.

Usage: python evaluation/build_scenarios.py <output-dir>

Scenario A: obvious defects. Scenario B: subtle CI/security/configuration defects. Scenario C: healthy.
Scenario D: mixed subtle defects across a Python API + Node frontend. Scenario E: healthy project that uses
alternative tooling (GitLab CI, Poetry + lock, tox, flake8/pre-commit, unittest) to probe false positives.
Credential-shaped strings are assembled at runtime so no secret-like literal is committed.
Ground truth: evaluation/ground_truth.json.
"""

import shutil
import subprocess
import sys
from pathlib import Path

BASE = Path(sys.argv[1] if len(sys.argv) > 1 else "eval_repos").resolve()


def git(cwd, *a):
    subprocess.run(["git", "-c", "user.name=Dev", "-c", "user.email=dev@example.com", *a], cwd=cwd, check=True,
                   capture_output=True)


def write(root, files):
    for p, c in files.items():
        f = root / p
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_bytes(c) if isinstance(c, bytes) else f.write_text(c)


def make(name, commits):
    root = BASE / name
    shutil.rmtree(root, ignore_errors=True)
    root.mkdir(parents=True)
    git(root, "init", "-q", "-b", "main")
    for msg, files, deletes in commits:
        write(root, files)
        for d in deletes:
            (root / d).unlink()
        git(root, "add", "-A")
        git(root, "commit", "-q", "-m", msg)

FAKE_AWS = "AKIA" + "Q3EXAMPL7Z2LKJHG"
FAKE_STRIPE = "sk_live_" + "51HfQ2kLmN8pQrStUvWxYz01"
GH_TOKEN = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"

# ---------------- Scenario A: obvious
make("scenario_a", [
 ("initial app", {
  "app.py": "from flask import Flask\nimport requests\nfrom config import STRIPE_KEY\n\napp = Flask(__name__)\nDATA_FILE = '/home/john/projects/shop/data/input.csv'\n\n@app.route('/')\ndef index():\n    try:\n        r = requests.get('https://api.example.com', verify=False)\n        return r.text\n    except:\n        pass\n\nif __name__ == '__main__':\n    app.run(host='0.0.0.0', debug=True)\n",
  "config.py": f"# payment settings\nSTRIPE_KEY = \"{FAKE_STRIPE}\"\nDB_HOST = 'prod-db.internal.example.com'\n",
  "requirements.txt": "flask\nrequests\n",
  ".env": f"AWS_ACCESS_KEY_ID={FAKE_AWS}\nDB_PASSWORD=Sup3rS3cretPassw0rd!\n",
  "__pycache__/config.cpython-311.pyc": b"\x00\x01binary",
  ".DS_Store": b"\x00\x00\x00\x01Bud1",
  "server.log": "2024-01-01 started\n",
 }, []),
 ("add utils", {"utils.py": "import os\n\ndef load():\n    return open('C:\\\\Users\\\\john\\\\Desktop\\\\data.csv').read()\n"}, []),
])

# ---------------- Scenario B: subtle CI/security/config
make("scenario_b", [
 ("init", {
  "README.md": "# Inventory Service\n\nSmall inventory API.\n\n## Setup\n\n```\npip install -r requirements.txt\npytest\n```\n",
  ".gitignore": "__pycache__/\n*.pyc\n.venv/\n.env\ndist/\nbuild/\n",
  "pyproject.toml": "[project]\nname = \"inventory\"\nversion = \"0.3.0\"\nrequires-python = \">=3.10\"\ndependencies = [\"requests>=2.32,<3\", \"pydantic>=2.5,<3\"]\n\n[tool.ruff]\nline-length = 100\n\n[tool.pytest.ini_options]\ntestpaths = [\"tests\"]\n",
  "requirements.txt": "requests==2.31.0\npydantic==2.6.1\n",
  "inventory/__init__.py": "__version__ = '0.2.0'\n",
  "inventory/core.py": "import os\nimport requests\n\nAPI_URL = os.environ.get('INVENTORY_API_URL', 'http://localhost:8000')\n\ndef add(a: int, b: int) -> int:\n    return a + b\n\ndef fetch(item_id: str) -> dict:\n    return requests.get(f'{API_URL}/items/{item_id}', timeout=5).json()\n",
  "tests/test_core.py": "from inventory.core import add\n\ndef test_add():\n    assert add(2, 3) == 5\n",
  ".vscode/settings.json": "{\n  \"python.defaultInterpreterPath\": \"/Users/alice/.venvs/inventory/bin/python\"\n}\n",
  ".github/workflows/ci.yml": "name: CI\non:\n  push:\n    branches: [master]\n  pull_request:\n    branches: [master]\npermissions: write-all\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - uses: actions/setup-python@v5\n        with:\n          python-version: '3.12'\n      - run: pip install -r requirements.txt pytest ruff\n      - name: Lint\n        run: ruff check .\n        continue-on-error: true\n      - name: Test\n        run: pytest -q || true\n",
  ".github/workflows/pr-check.yml": "name: PR check\non:\n  pull_request_target:\n    types: [opened, synchronize]\njobs:\n  check:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n      - run: pip install . && pytest\n        env:\n          DEPLOY_TOKEN: ${{ secrets.DEPLOY_TOKEN }}\n",
  ".github/workflows/triage.yml": "name: Triage\non:\n  issues:\n    types: [opened]\njobs:\n  label:\n    runs-on: ubuntu-latest\n    steps:\n      - run: |\n          echo \"New issue: ${{ github.event.issue.title }}\"\n          ./scripts/label.sh \"${{ github.event.issue.title }}\"\n",
  ".github/workflows/deploy.yml": "name: Deploy\non:\n  push:\n    branches: ['**']\njobs:\n  deploy:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - uses: appleboy/ssh-action@master\n        with:\n          host: ${{ secrets.HOST }}\n          key: ${{ secrets.SSH_KEY }}\n          script: cd /srv/app && git pull && systemctl restart inventory\n",
  "scripts/label.sh": "#!/bin/sh\necho labeling \"$1\"\n",
 }, []),
 ("add deploy helper settings", {"deploy_settings.py": f"GITHUB_TOKEN = \"{GH_TOKEN}\"\nTARGET = 'prod'\n"}, []),
 ("remove token file", {}, ["deploy_settings.py"]),
])

# ---------------- Scenario C: healthy
make("scenario_c", [
 ("init", {
  "README.md": "# Tasky\n\nA tiny task CLI.\n\n## Install\n\n```\npip install -e .[dev]\n```\n\n## Configure\n\nCopy `.env.example` to `.env` and set `TASKY_API_TOKEN`.\n\n## Test\n\n```\nruff check . && pytest\n```\n",
  ".gitignore": "__pycache__/\n*.py[cod]\n.venv/\n.env\n.pytest_cache/\n.ruff_cache/\ndist/\nbuild/\n*.egg-info/\n.coverage\n",
  ".env.example": "TASKY_API_TOKEN=your-token-here\nTASKY_ENV=development\n",
  "pyproject.toml": "[build-system]\nrequires = [\"setuptools>=68\"]\nbuild-backend = \"setuptools.build_meta\"\n\n[project]\nname = \"tasky\"\nversion = \"1.2.0\"\nrequires-python = \">=3.10\"\ndependencies = [\"click>=8.1,<9\"]\n\n[project.optional-dependencies]\ndev = [\"pytest>=8,<9\", \"ruff>=0.5\"]\n\n[project.scripts]\ntasky = \"tasky.cli:main\"\n\n[tool.ruff]\nline-length = 100\n\n[tool.ruff.lint]\nselect = [\"E\", \"F\", \"I\", \"B\"]\n\n[tool.pytest.ini_options]\ntestpaths = [\"tests\"]\n",
  "tasky/__init__.py": "\"\"\"Tasky.\"\"\"\n",
  "tasky/cli.py": "import os\n\nimport click\n\n\ndef get_token() -> str:\n    token = os.environ.get(\"TASKY_API_TOKEN\")\n    if not token:\n        raise click.ClickException(\"TASKY_API_TOKEN is not set\")\n    return token\n\n\n@click.command()\n@click.argument(\"title\")\ndef main(title: str) -> None:\n    click.echo(f\"added: {title}\")\n",
  "tests/test_cli.py": "from click.testing import CliRunner\n\nfrom tasky.cli import get_token, main\n\n\ndef test_add():\n    result = CliRunner().invoke(main, [\"buy milk\"])\n    assert result.exit_code == 0\n    assert \"buy milk\" in result.output\n\n\ndef test_token(monkeypatch):\n    monkeypatch.setenv(\"TASKY_API_TOKEN\", \"dummy-test-token\")\n    assert get_token() == \"dummy-test-token\"\n",
  ".github/workflows/ci.yml": "name: CI\non:\n  push:\n    branches: [main]\n  pull_request:\npermissions:\n  contents: read\njobs:\n  test:\n    runs-on: ubuntu-latest\n    strategy:\n      matrix:\n        python-version: ['3.10', '3.11', '3.12']\n    steps:\n      - uses: actions/checkout@v4\n      - uses: actions/setup-python@v5\n        with:\n          python-version: ${{ matrix.python-version }}\n      - run: pip install -e .[dev]\n      - run: ruff check .\n      - run: pytest -q\n",
  ".github/dependabot.yml": "version: 2\nupdates:\n  - package-ecosystem: pip\n    directory: /\n    schedule:\n      interval: weekly\n",
 }, []),
])
# ---------------- Scenario D: mixed subtle defects
make("scenario_d", [
 ("init", {
  "README.md": "# Web Dashboard\n\nNode frontend + Python API.\n",
  ".gitignore": "__pycache__/\n.env\n",
  "api/requirements.txt": "fastapi==0.110.0\nuvicorn==0.29.0\nsqlalchemy==2.0.29\n",
  "api/main.py": "import os\nimport subprocess\n\nimport yaml\nfrom fastapi import FastAPI\n\napp = FastAPI()\nDATABASE_URL = os.environ['DATABASE_URL']\n\n@app.post('/import')\ndef import_cfg(body: str):\n    return yaml.load(body)\n\n@app.get('/ping')\ndef ping(host: str):\n    return subprocess.check_output(f'ping -c 1 {host}', shell=True)\n",
  "api/tests/test_main.py": "from api.main import app\n\ndef test_app_exists():\n    assert True\n\ndef test_ping():\n    pass\n",
  "web/package.json": "{\n  \"name\": \"dashboard\",\n  \"private\": true,\n  \"scripts\": {\"build\": \"vite build\", \"test\": \"vitest run\"},\n  \"dependencies\": {\"react\": \"*\", \"axios\": \"latest\"},\n  \"devDependencies\": {\"vite\": \"^5.0.0\", \"vitest\": \"^1.0.0\"}\n}\n",
  "web/src/index.js": "import axios from 'axios';\nexport const api = axios.create({ baseURL: 'http://192.168.1.23:8000' });\n",
  "Dockerfile": "FROM python:latest\nWORKDIR /app\nCOPY . .\nRUN pip install -r api/requirements.txt\nCMD [\"uvicorn\", \"api.main:app\", \"--host\", \"0.0.0.0\"]\n",
  ".github/workflows/ci.yml": "name: CI\non: [push, pull_request]\njobs:\n  web:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - uses: actions/setup-node@v4\n        with:\n          node-version: 20\n      - run: cd web && npm ci && npm run build\n  api:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - uses: actions/setup-python@v5\n        with:\n          python-version: '3.12'\n      - run: pip install -r api/requirements.txt\n      - run: python -c \"import api.main\"\n      - uses: actions/upload-artifact@v3\n        with:\n          name: api\n          path: api/\n",
  ".github/workflow/release.yml": "name: Release\non:\n  push:\n    tags: ['v*']\njobs:\n  publish:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - run: docker build -t org/dash . && docker push org/dash\n",
  ".github/workflows/automerge.yml": "name: Auto merge\non: pull_request_target\npermissions:\n  contents: write\n  pull-requests: write\njobs:\n  merge:\n    runs-on: ubuntu-latest\n    steps:\n      - run: gh pr merge --auto --squash \"$PR_URL\"\n        env:\n          PR_URL: ${{ github.event.pull_request.html_url }}\n          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}\n",
 }, []),
])
# ---------------- Scenario E: healthy with alternative tooling
make("scenario_e", [
 ("init", {
  "README.rst": "Ledger\n======\n\nInstall with ``poetry install``; run ``tox``.\nSet ``LEDGER_DB_URL`` (see ``.env.sample``).\n",
  ".gitignore": "*.pyc\n__pycache__/\n.tox/\n.venv/\n.env\ndist/\n",
  ".env.sample": "LEDGER_DB_URL=postgresql://user:password@localhost:5432/ledger\n",
  "pyproject.toml": "[tool.poetry]\nname = \"ledger\"\nversion = \"2.1.0\"\ndescription = \"ledger\"\nauthors = [\"Team <team@example.org>\"]\n\n[tool.poetry.dependencies]\npython = \"^3.10\"\nsqlalchemy = \"^2.0\"\n\n[tool.poetry.group.dev.dependencies]\npytest = \"^8.0\"\nflake8 = \"^7.0\"\n\n[build-system]\nrequires = [\"poetry-core\"]\nbuild-backend = \"poetry.core.masonry.api\"\n",
  "poetry.lock": "# This file is automatically @generated by Poetry\n[[package]]\nname = \"sqlalchemy\"\nversion = \"2.0.30\"\n",
  "tox.ini": "[tox]\nenvlist = py310,py311,py312,lint\n\n[testenv]\ndeps = pytest\ncommands = pytest\n\n[testenv:lint]\ndeps = flake8\ncommands = flake8 ledger tests\n",
  ".flake8": "[flake8]\nmax-line-length = 100\n",
  ".pre-commit-config.yaml": "repos:\n  - repo: https://github.com/pycqa/flake8\n    rev: 7.0.0\n    hooks:\n      - id: flake8\n",
  "ledger/__init__.py": "",
  "ledger/db.py": "import os\n\nfrom sqlalchemy import create_engine\n\n\ndef engine():\n    return create_engine(os.environ[\"LEDGER_DB_URL\"])\n",
  "tests/test_db.py": "import unittest\nfrom unittest import mock\n\nfrom ledger import db\n\n\nclass TestEngine(unittest.TestCase):\n    def test_engine_uses_env(self):\n        with mock.patch.dict('os.environ', {'LEDGER_DB_URL': 'sqlite://'}):\n            self.assertEqual(str(db.engine().url), 'sqlite://')\n",
  ".gitlab-ci.yml": "stages: [test]\n\ntest:\n  stage: test\n  image: python:3.12-slim\n  script:\n    - pip install tox\n    - tox\n",
  ".github/workflows/labeler.yml": "name: Labeler\non: pull_request_target\npermissions:\n  contents: read\n  pull-requests: write\njobs:\n  label:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/labeler@v5\n",
  "Dockerfile": "FROM python:3.12.3-slim\nRUN useradd -m app\nWORKDIR /app\nCOPY pyproject.toml poetry.lock ./\nRUN pip install poetry==1.8.2 && poetry install --only main\nCOPY ledger ./ledger\nUSER app\nCMD [\"python\", \"-m\", \"ledger\"]\n",
  ".dockerignore": ".env\n.git\n.tox\n",
  "tests/__init__.py": "",
 }, []),
])
print(f"scenarios written to {BASE}")
