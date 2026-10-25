from audit_agent.redact import contains_secret, detect_secrets, redact_text
from tests.conftest import FAKE_AWS_KEY, FAKE_GH_TOKEN


def test_provider_tokens_are_redacted():
    text = f"key = {FAKE_AWS_KEY}\ntoken: {FAKE_GH_TOKEN}"
    out = redact_text(text)
    assert FAKE_AWS_KEY not in out and FAKE_GH_TOKEN not in out
    assert "aws_access_key_id" in out and "github_token" in out
    assert out.count("\n") == 1  # line structure preserved


def test_assignments_and_url_credentials_are_redacted():
    out = redact_text('password = "Zx81!kqLmP0"\nDSN=postgres://admin:hunter22@db/x\nDB_PASSWORD=Zx81!kqLmP0')
    assert "Zx81!kqLmP0" not in out and "hunter22" not in out


def test_line_numbered_and_grep_prefixed_lines_are_redacted():
    assert "Zx81" not in redact_text("12| DB_PASSWORD=Zx81!kqLmP0")
    assert "Zx81" not in redact_text("config/.env:3:DB_PASSWORD=Zx81!kqLmP0")


def test_references_and_annotations_are_not_secrets():
    for line in ['token = os.environ["TOKEN"]', "TOKEN: ${{ secrets.TOKEN }}", "api_key: Optional[str] = None",
                 "secret = settings.SECRET_KEY", "def get_token(self):", "password: str"]:
        assert not contains_secret(line), line


def test_placeholder_detection():
    found = detect_secrets("API_TOKEN=your-token-here")
    assert found and found[0]["placeholder"] is True
    found = detect_secrets(f'AWS = "{FAKE_AWS_KEY}"')
    assert found and found[0]["placeholder"] is False


def test_known_secret_scrubbed_when_repeated_elsewhere():
    redact_text(f"k = {FAKE_GH_TOKEN}")
    assert FAKE_GH_TOKEN not in redact_text(f"something {FAKE_GH_TOKEN} else")


def test_agent_text_does_not_poison_known_secrets():
    redact_text("scan_secrets: config.py:2 kind=x", remember=False)
    assert "config.py:2" in redact_text("see config.py:2")


def test_common_words_are_not_scrubbed_globally():
    redact_text("LEDGER_DB_URL=postgresql://user:password@localhost:5432/ledger")
    assert redact_text("the url_password field") == "the url_password field"
