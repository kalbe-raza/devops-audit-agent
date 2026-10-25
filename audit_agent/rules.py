"""Catalogue of DevOps rules the agent reports against.

The catalogue is general DevOps knowledge (no repository-specific findings). It
gives the LLM stable rule IDs, default severities and - most importantly - the
acceptable alternatives that must NOT be reported, which keeps precision high.
"""

from __future__ import annotations

CATEGORIES = [
    "repository_hygiene", "dependency_management", "code_quality", "testing", "ci_cd",
    "security", "configuration", "collaboration", "build_release",
]
SEVERITIES = ["critical", "high", "medium", "low"]

# (rule_id, category, default severity, title, report-when / do-not-report guidance)
RULES: list[tuple[str, str, str, str, str]] = [
    ("HYG-001", "repository_hygiene", "medium", "Missing README",
     "No README at the repo root (any README.* / readme.* counts; docs-only README elsewhere does not)."),
    ("HYG-002", "repository_hygiene", "medium", "Missing or unsuitable .gitignore",
     "No .gitignore, or it lacks rules for the stack's standard artifacts (e.g. __pycache__/, *.pyc, .venv/, .env, "
     "node_modules/, dist/) AND that matters for the repo. A minimal but adequate .gitignore is fine."),
    ("HYG-003", "repository_hygiene", "medium", "Tracked generated/temporary files",
     "Committed bytecode, caches, virtualenvs, build/dist output, node_modules, logs, coverage output, OS files "
     "(.DS_Store). Group all files of one kind into ONE finding. Vendored files intentionally committed with a "
     "documented reason are not violations."),
    ("HYG-004", "repository_hygiene", "low", "Large binary/archive committed",
     "Archives, binaries or data dumps committed without need (not small test fixtures, images used by docs)."),
    ("DEP-001", "dependency_management", "high", "No dependency manifest",
     "Code imports third-party packages but no manifest (requirements*.txt, pyproject, setup.py/cfg, Pipfile, "
     "environment.yml, package.json...) declares them."),
    ("DEP-002", "dependency_management", "medium", "Weak or missing version constraints",
     "An application/deployable's runtime dependencies are unconstrained or lower-bound-only AND no lockfile or "
     "constraints file pins them. Libraries publishing ranges in pyproject are acceptable; one or two loose dev "
     "tools are low at most. Report once per manifest."),
    ("DEP-003", "dependency_management", "medium", "Inconsistent dependency specifications",
     "Same package with conflicting constraints in different files, duplicate conflicting entries, a package "
     "imported by runtime code but not declared anywhere, or CI/Docker installing from a different file than the "
     "one maintained. Verify an import is truly third-party and not provided transitively/optionally."),
    ("DEP-004", "dependency_management", "medium", "Required lockfile absent or unused",
     "Tooling that expects a lock is used without it (npm ci / yarn --frozen-lockfile / poetry install --no-root in "
     "CI without lock; Pipfile without Pipfile.lock; app package.json without any lockfile). Plain pip "
     "requirements with == pins do NOT need a lockfile."),
    ("DEP-005", "dependency_management", "medium", "Insecure dependency source",
     "Plain-http index, --trusted-host, unpinned VCS URLs on mutable branches, or --extra-index-url for private "
     "packages (dependency confusion)."),
    ("DEP-006", "dependency_management", "low", "Python version declarations inconsistent",
     "requires-python / python_requires / CI matrix / Dockerfile / .python-version disagree in a way that means "
     "the supported version is not actually tested or installable."),
    ("CQ-001", "code_quality", "low", "No linting/formatting enforcement",
     "No linter/formatter is configured (ruff, flake8, pylint, black, isort, pre-commit, eslint, ... in any config "
     "file) AND none is run in CI. Any one equivalent tool is enough; do not demand a specific tool."),
    ("CQ-002", "code_quality", "high", "Code that cannot run (syntax errors / undefined names)",
     "Syntax errors, undefined names (F821) or broken imports in tracked source - evidence from run_ruff/read_file."),
    ("CQ-003", "code_quality", "medium", "Obvious maintainability problems",
     "Bare 'except:' that silently swallows errors, leftover debugger calls (pdb.set_trace/breakpoint), wildcard "
     "imports in library code, large duplicated code, dead code paths that hide behaviour. Not style nits."),
    ("TST-001", "testing", "high", "No automated tests",
     "No test files/directories exist for non-trivial code (search tests/, test_*.py, *_test.py, *.spec.*, "
     "doctest configs, unittest usage)."),
    ("TST-002", "testing", "high", "Tests not executed in CI",
     "A CI pipeline exists and tests exist, but no CI job runs them (check tox/nox/make/npm scripts invoked by CI)."),
    ("TST-003", "testing", "high", "Failing or broken tests",
     "run_pytest shows genuine assertion failures, or tests that cannot possibly pass (e.g. import a module that "
     "does not exist). Environment-only problems (no network/service) are NOT evidence."),
    ("TST-004", "testing", "medium", "Ineffective tests",
     "Tests that assert nothing meaningful (assert True, no asserts), are all skipped/xfail unconditionally, or are "
     "not discoverable by the configured runner (wrong file names/testpaths)."),
    ("CI-001", "ci_cd", "medium", "No continuous integration",
     "No CI configuration of any provider (GitHub Actions, GitLab, Travis, CircleCI, Jenkins, Azure, pre-commit.ci "
     "...) for a project with code and tests. Never infer CI from branch protection."),
    ("CI-002", "ci_cd", "high", "Incorrect or ineffective workflow triggers",
     "Validation workflow never runs on the default branch or PRs: branch filter names a non-existent/other branch, "
     "only manual/schedule triggers, typo'd event, paths(-ignore) that exclude source, workflow file outside "
     ".github/workflows, invalid YAML."),
    ("CI-003", "ci_cd", "high", "Failures masked or quality gates ineffective",
     "Test/lint/build steps cannot fail the build: continue-on-error: true, '|| true', 'exit 0', set +e, "
     "--exit-zero, coverage gate 0, if: false/always on gating steps."),
    ("CI-004", "ci_cd", "medium", "Validation skipped or incomplete",
     "Steps that claim to validate but skip it (tests deselected, --collect-only, lint step commented out, matrix "
     "excluding the supported versions)."),
    ("CI-005", "ci_cd", "medium", "Third-party actions on mutable refs or unversioned",
     "uses: owner/action@master|main or without @ref. Version tags like @v4 are acceptable (do not report)."),
    ("CI-006", "ci_cd", "low", "Deprecated/retired CI components",
     "Deprecated action major versions that no longer run (e.g. actions/upload-artifact@v3, actions/cache@v2), "
     "retired runners (ubuntu-20.04), ::set-output, end-of-life language versions only."),
    ("SEC-001", "security", "critical", "Hardcoded credential in tracked file",
     "Real-looking secret (API key, token, password, private key, connection string with password) in source/config. "
     "Placeholders, dummy test fixtures clearly marked fake, and env-var references are NOT violations. One finding "
     "per secret location; never reproduce the value."),
    ("SEC-002", "security", "high", "Secret present in git history",
     "A credential was committed and later removed from HEAD; it remains in history and must be rotated."),
    ("SEC-003", "security", "high", "Committed credential/environment file",
     "Tracked .env, key/cert files, credentials.json, .npmrc/.pypirc with tokens, terraform state. .env.example "
     "templates with placeholders are fine. Do not double report with SEC-001 for the same secret: choose one."),
    ("SEC-004", "security", "high", "Overly broad workflow token permissions",
     "permissions: write-all, or write scopes granted to jobs that only build/test, especially on PR-triggered "
     "workflows. A missing permissions block alone is low at most."),
    ("SEC-005", "security", "critical", "Untrusted code executed with privileges (pull_request_target/workflow_run)",
     "pull_request_target or workflow_run workflow checks out the PR head and runs it (build/test/install) with "
     "secrets or write token. pull_request_target used only for labelling without checkout is acceptable."),
    ("SEC-006", "security", "high", "Script injection in workflow",
     "Untrusted ${{ github.event.* }} text (PR/issue titles, bodies, branch names, comments) interpolated directly "
     "in run: scripts. Passing via env: variables is the safe alternative."),
    ("SEC-007", "security", "high", "Secrets exposed in CI logs",
     "echo/printf of secrets, set -x around secrets, printing env with secrets, uploading secret files as artifacts."),
    ("SEC-008", "security", "medium", "Debug mode or insecure framework settings for production",
     "DEBUG=True in production settings, app.run(debug=True) in the real entrypoint, ALLOWED_HOSTS=['*'], wildcard "
     "CORS with credentials. Local-only dev scripts and tests are not violations."),
    ("SEC-009", "security", "medium", "TLS/certificate verification disabled",
     "verify=False, ssl._create_unverified_context, rejectUnauthorized: false, curl -k, pip --trusted-host in code "
     "or scripts that talk to real services."),
    ("SEC-010", "security", "high", "Unsafe execution or deserialisation of external input",
     "eval/exec, pickle.loads, yaml.load without SafeLoader, subprocess(shell=True) or SQL built by string "
     "formatting on data that can come from users/network/files. Constant inputs are not violations. Report each "
     "class (SQL injection, unsafe deserialisation, eval/exec, shell injection, template injection) separately."),
    ("CFG-001", "configuration", "medium", "Machine-specific absolute paths",
     "Hardcoded user/machine paths (/home/<user>/, /Users/<user>/, C:\\Users\\..., D:\\...) in code or config "
     "used at runtime/CI. Container-standard paths (/app, /usr/src, /tmp) are fine."),
    ("CFG-002", "configuration", "low", "Committed local/IDE/personal settings",
     "Tracked .idea/, .vscode/settings.json with personal/local values, *.local overrides, local_settings.py. "
     "Shared, intentional editor config (.editorconfig, .vscode/extensions.json) is fine."),
    ("CFG-003", "configuration", "medium", "Poor environment separation",
     "Environment-specific values (prod hosts, DB URLs, ports, debug flags) hardcoded in code instead of env vars/"
     "config files; one config used for dev and prod; production settings defaulting to development values."),
    ("CFG-004", "configuration", "low", "Required configuration undocumented",
     "Code requires environment variables that appear in no .env.example, README or config documentation."),
    ("COL-001", "collaboration", "high", "Unsafe PR automation",
     "Workflows that auto-approve or auto-merge PRs without restricting actor/update type or waiting for checks; "
     "bots triggered by comments without author association checks."),
    ("COL-002", "collaboration", "low", "Review guidance missing or broken",
     "Only where relevant (several contributors or explicit contribution invitation): CODEOWNERS referencing "
     "non-existent paths/invalid syntax, or no contribution/review guidance at all. Never infer branch protection."),
    ("BLD-001", "build_release", "medium", "No build validation",
     "A distributable artifact (package, Docker image) is defined but never built/validated in CI before release."),
    ("BLD-002", "build_release", "high", "Risky release/deployment automation",
     "Deploy/publish jobs that run without depending on tests (no needs:), run on every push/PR from any branch, "
     "deploy from pull_request events, force-push to production, or use long-lived secrets where they leak."),
    ("BLD-003", "build_release", "medium", "Unreproducible or unsafe container build",
     "Dockerfile using unpinned :latest/untagged base, copying secrets/.env into the image, COPY . without "
     ".dockerignore while secrets/artifacts are tracked, running as root in a production image."),
    ("BLD-004", "build_release", "low", "Inconsistent versioning",
     "Version declared in several places with different values (pyproject vs __init__ vs setup.py vs tags)."),
]

RULE_IDS = {r[0] for r in RULES}
RULE_CATEGORY = {r[0]: r[1] for r in RULES}
CATEGORY_PREFIX = {
    "repository_hygiene": "HYG", "dependency_management": "DEP", "code_quality": "CQ", "testing": "TST",
    "ci_cd": "CI", "security": "SEC", "configuration": "CFG", "collaboration": "COL", "build_release": "BLD",
}


def render_catalogue() -> str:
    lines = []
    current = None
    for rid, cat, sev, title, guide in RULES:
        if cat != current:
            lines.append(f"\n[{cat}]")
            current = cat
        lines.append(f"- {rid} ({sev}) {title}: {guide}")
    return "\n".join(lines).strip()
