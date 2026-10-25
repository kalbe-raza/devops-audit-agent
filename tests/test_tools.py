import subprocess

import pytest

from tests.conftest import FAKE_AWS_KEY, FAKE_GH_TOKEN
from tools import TOOL_SPECS, ToolError, build_dispatch


def _status(repo):
    return subprocess.run(["git", "status", "--porcelain"], cwd=repo, capture_output=True, text=True).stdout


def test_list_files(defect_tools):
    out = defect_tools.list_files()
    assert "app.py" in out and ".github/workflows/ci.yml" in out
    assert "Default branch: main" in out
    assert "requirements.txt" in defect_tools.list_files(path=".")


def test_list_files_unknown_dir(defect_tools):
    with pytest.raises(ToolError):
        defect_tools.list_files(path="nope")


def test_read_file_numbers_and_redacts(defect_tools):
    out = defect_tools.read_file("settings.py")
    assert "1| AWS_KEY" in out and FAKE_AWS_KEY not in out
    assert "2| DEBUG = True" in out
    out = defect_tools.read_file("app.py", start_line=2, end_line=2)
    assert "2| DATA" in out and "1| import" not in out


@pytest.mark.parametrize("path", ["../etc/passwd", "/../../etc/passwd", ".git/config", "missing.py"])
def test_read_file_rejects_bad_paths(defect_tools, path):
    with pytest.raises(ToolError):
        defect_tools.read_file(path)


def test_read_file_rejects_symlink_escape(defect_repo):
    from audit_agent.repo import open_local_repository
    from tools import RepoTools
    (defect_repo / "link").symlink_to("/etc/hostname")
    tools = RepoTools(open_local_repository(str(defect_repo)))
    with pytest.raises(ToolError):
        tools.read_file("link")


def test_read_binary_file(defect_tools):
    assert "binary" in defect_tools.read_file("__pycache__/app.cpython-312.pyc")


def test_search_code(defect_tools):
    out = defect_tools.search_code(r"/home/[a-z]+", path_glob="*.py")
    assert "app.py:2:" in out
    assert "No matches" in defect_tools.search_code("zzz_not_present")
    with pytest.raises(ToolError):
        defect_tools.search_code("(unclosed")


def test_git_log_history_and_search(defect_tools):
    out = defect_tools.git_log(show_files=True)
    assert "remove token" in out and "deploy.py" in out
    out = defect_tools.git_log(search="TOKEN")
    assert "deploy.py" in out and FAKE_GH_TOKEN not in out


def test_find_tracked_artifacts(defect_tools, healthy_tools):
    out = defect_tools.find_tracked_artifacts()
    assert ".gitignore at root: ABSENT" in out
    assert "__pycache__/app.cpython-312.pyc" in out
    assert ".env" in out.split("credentials/local secrets:")[1]
    healthy = healthy_tools.find_tracked_artifacts()
    assert "credentials/local secrets: none" in healthy
    assert ".env.example" in healthy  # listed as acceptable template


def test_scan_secrets_working_tree_and_history(defect_tools):
    out = defect_tools.scan_secrets()
    assert "settings.py:1 kind=aws_access_key_id" in out
    assert ".env:1" in out
    assert "file=deploy.py kind=github_token" in out
    assert FAKE_AWS_KEY not in out and FAKE_GH_TOKEN not in out


def test_scan_secrets_healthy_only_placeholders(healthy_tools):
    out = healthy_tools.scan_secrets()
    assert "placeholder_like=yes" in out
    assert "placeholder_like=no" not in out


def test_inspect_ci_flags(defect_tools):
    out = defect_tools.inspect_ci()
    assert "does not match the default branch 'main'" in out
    assert "write-all" in out
    assert "'|| true'" in out
    assert "continue-on-error: true" in out
    assert "mutable branch ref 'main'" in out
    assert "head_commit.message" in out


def test_inspect_ci_healthy_has_no_flags(healthy_tools):
    out = healthy_tools.inspect_ci()
    assert "heuristic flags: none" in out
    assert "test command found=True" in out


def test_inspect_ci_invalid_yaml(tmp_path):
    from audit_agent.repo import open_local_repository
    from tests.conftest import make_repo
    from tools import RepoTools
    repo = make_repo(tmp_path / "bad", [("i", {".github/workflows/x.yml": "on: [push\njobs: {"}, [])])
    out = RepoTools(open_local_repository(str(repo))).inspect_ci()
    assert "YAML PARSE ERROR" in out


def test_dependency_overview(defect_tools, healthy_tools):
    out = defect_tools.dependency_overview()
    assert "UNCONSTRAINED=1" in out and "lower-bound only (>=)=1" in out
    assert "Lockfiles: none" in out
    out = healthy_tools.dependency_overview()
    assert "click>=8,<9" in out


def test_dependency_overview_detects_conflicts_and_undeclared(tmp_path):
    from audit_agent.repo import open_local_repository
    from tests.conftest import make_repo
    from tools import RepoTools
    repo = make_repo(tmp_path / "dep", [("i", {
        "requirements.txt": "requests==2.31.0\n",
        "pyproject.toml": "[project]\nname='x'\ndependencies=['requests>=2.32']\n",
        "x.py": "import requests\nimport yaml\n",
    }, [])])
    out = RepoTools(open_local_repository(str(repo))).dependency_overview()
    assert "DIFFERENT constraints" in out and "requests" in out
    assert "yaml (first import at x.py:2)" in out


def test_run_ruff(defect_tools):
    out = defect_tools.run_ruff()
    assert "issue(s)" in out


def test_run_pytest_unavailable_is_reported(defect_tools, monkeypatch):
    monkeypatch.setenv("ENABLE_DOCKER_TESTS", "false")
    out = defect_tools.run_pytest()
    assert "UNAVAILABLE" in out


def test_tools_do_not_modify_repository(defect_repo, defect_tools, monkeypatch):
    monkeypatch.setenv("ENABLE_DOCKER_TESTS", "false")
    before = _status(defect_repo)
    for spec in TOOL_SPECS:
        fn = build_dispatch(defect_tools)[spec["name"]]
        args = {"path": "app.py"} if spec["name"] == "read_file" else {}
        if spec["name"] == "search_code":
            args = {"pattern": "import"}
        fn(**args)
    assert _status(defect_repo) == before == ""


def test_every_spec_has_an_implementation(defect_tools):
    dispatch = build_dispatch(defect_tools)
    assert {s["name"] for s in TOOL_SPECS} == set(dispatch)
    required = {"list_files", "read_file", "search_code", "git_log"}
    assert required <= set(dispatch)


def test_inspect_ci_privileged_and_release_patterns(tmp_path):
    from audit_agent.repo import open_local_repository
    from tests.conftest import make_repo
    from tools import RepoTools
    repo = make_repo(tmp_path / "ci", [("i", {
        ".github/workflows/pr.yml": (
            "on: pull_request_target\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n"
            "      - run: make test\n"),
        ".github/workflows/deploy.yml": (
            "on: push\njobs:\n  deploy:\n    runs-on: ubuntu-20.04\n    steps:\n"
            "      - uses: actions/upload-artifact@v3\n      - run: twine upload dist/*\n"),
        ".github/workflow/misplaced.yml": "on: push\njobs: {}\n",
    }, [])])
    out = RepoTools(open_local_repository(str(repo))).inspect_ci()
    assert "CRITICAL PATTERN" in out
    assert "NO needs: dependency" in out
    assert "deprecated major version" in out
    assert "retired/deprecated runner 'ubuntu-20.04'" in out
    assert ".github/workflow/misplaced.yml" in out.split("NOT in .github/workflows")[1]


def test_sandbox_disabled_by_env(monkeypatch):
    from audit_agent.sandbox import docker_available
    monkeypatch.setenv("ENABLE_DOCKER_TESTS", "false")
    ok, reason = docker_available()
    assert not ok and "disabled" in reason


def test_search_code_globs(tmp_path):
    from audit_agent.repo import open_local_repository
    from tests.conftest import make_repo
    from tools import RepoTools
    repo = make_repo(tmp_path / "g", [("i", {"a.py": "needle\n", "pkg/sub/b.py": "needle\n", "c.txt": "needle\n"}, [])])
    tools = RepoTools(open_local_repository(str(repo)))
    out = tools.search_code("needle", path_glob="*.py")
    assert "a.py:1:" in out and "pkg/sub/b.py:1:" in out and "c.txt" not in out
    out = tools.search_code("needle", path_glob="pkg/**")
    assert "pkg/sub/b.py:1:" in out and "a.py:1:" not in out


def test_dependency_overview_reports_version_declarations(tmp_path):
    from audit_agent.repo import open_local_repository
    from tests.conftest import make_repo
    from tools import RepoTools
    repo = make_repo(tmp_path / "v", [("i", {
        "pyproject.toml": "[project]\nname='p'\nversion = \"1.2.0\"\n",
        "p/__init__.py": "__version__ = '1.1.0'\n",
    }, [])])
    out = RepoTools(open_local_repository(str(repo))).dependency_overview()
    assert "p/__init__.py:1 -> 1.1.0" in out and "pyproject.toml:3 -> 1.2.0" in out
