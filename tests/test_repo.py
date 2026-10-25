import pytest

from audit_agent.repo import RepoError, clone_repository, open_local_repository, parse_github_url


@pytest.mark.parametrize("url,owner,name,ref", [
    ("https://github.com/psf/requests", "psf", "requests", None),
    ("https://github.com/psf/requests.git", "psf", "requests", None),
    ("https://github.com/psf/requests/", "psf", "requests", None),
    ("github.com/pallets/flask", "pallets", "flask", None),
    ("https://github.com/a-b/c.d_e/tree/dev", "a-b", "c.d_e", "dev"),
    ("git@github.com:owner/repo.git", "owner", "repo", None),
])
def test_parse_valid_urls(url, owner, name, ref):
    spec = parse_github_url(url)
    assert (spec.owner, spec.name, spec.ref) == (owner, name, ref)
    assert spec.canonical_url == f"https://github.com/{owner}/{name}"


@pytest.mark.parametrize("url", ["", "not a url", "https://gitlab.com/a/b", "https://github.com/onlyowner",
                                 "https://github.com/a/b/c/d", "file:///etc/passwd", "https://github.com/a/..",
                                 "https://evil.com/github.com/a/b"])
def test_parse_invalid_urls(url):
    with pytest.raises(RepoError):
        parse_github_url(url)


def test_open_local_repository(defect_repo):
    co = open_local_repository(str(defect_repo))
    assert co.default_branch == "main"
    assert co.commit_count == 3
    assert co.head_commit


def test_open_local_rejects_non_git(tmp_path):
    with pytest.raises(RepoError):
        open_local_repository(str(tmp_path))


def test_clone_nonexistent_repo_fails_cleanly(monkeypatch):
    # Uses the network; skip quietly when offline.
    import socket
    try:
        socket.create_connection(("github.com", 443), timeout=3).close()
    except OSError:
        pytest.skip("network unavailable")
    spec = parse_github_url("https://github.com/this-owner-does-not-exist-zz9/nope-zz9")
    with pytest.raises(RepoError):
        clone_repository(spec, timeout=60)
