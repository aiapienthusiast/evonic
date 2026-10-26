"""Regression tests for credential redaction and the sensitive-payload gate.

Two defects motivated these tests (see ``docs/safety/label-audit.md``):

1. ``decim_safety_telemetry.command_preview`` anchored the credential keyword
   with ``\\b``, so every environment-variable style name (``PGPASSWORD``,
   ``MYSQL_PWD``, ``NPM_TOKEN``, ``DOCKER_PASSWORD``) passed through verbatim.
   The same defect existed in ``decim_safety._SECRET_PATTERN``, which is why
   those payloads were also sent to the provider instead of falling back to the
   deterministic checker.
2. ``command_preview`` truncated *before* redacting.  A cut inside a credential
   leaves a fragment no pattern can match, so the leading part of the secret was
   stored.  Credentials that need both delimiters to be recognised (PEM key
   blocks, ``scheme://user:pass@host``) leaked wholesale.

Every test uses obviously fake values; no real credential appears here.
"""

from types import SimpleNamespace

import pytest

from backend.services import decim_safety_telemetry as telemetry
from backend.tools.lib.decim_safety import _SECRET_PATTERN


# ---------------------------------------------------------------------------
# env-var style names: the key is an identifier, not a bare word
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("assignment,secret", [
    ("PGPASSWORD=pgS3cretValue", "pgS3cretValue"),
    ("MYSQL_PWD=mySqlS3cret", "mySqlS3cret"),
    ("NPM_TOKEN=npmS3cretToken", "npmS3cretToken"),
    ("DOCKER_PASSWORD=dockerS3cret", "dockerS3cret"),
    ("AWS_SECRET_ACCESS_KEY=awsS3cretKey", "awsS3cretKey"),
    ("GH_TOKEN=ghS3cretToken", "ghS3cretToken"),
    ("export PGPASSWORD='quotedS3cret'", "quotedS3cret"),
    ("REDIS_PASSWORD=\"dqS3cret\"", "dqS3cret"),
])
def test_command_preview_redacts_env_prefixed_credentials(assignment, secret):
    preview = telemetry.command_preview(f"psql --host db {assignment} -c 'select 1'")
    assert secret not in preview
    assert telemetry._REDACTED in preview


@pytest.mark.parametrize("assignment", [
    "PGPASSWORD=pgS3cretValue",
    "MYSQL_PWD=mySqlS3cret",
    "NPM_TOKEN=npmS3cretToken",
    "DOCKER_PASSWORD=dockerS3cret",
    "AWS_SECRET_ACCESS_KEY=awsS3cretKey",
])
def test_provider_gate_detects_env_prefixed_credentials(assignment):
    """A prefixed name must route the payload to the deterministic fallback."""
    assert _SECRET_PATTERN.search(assignment) is not None


@pytest.mark.parametrize("command", [
    "git fetch origin main",
    "gcloud run services describe api --region asia-southeast2",
    "ls -la /tmp/scratchpad && echo done",
])
def test_provider_gate_does_not_flag_ordinary_commands(command):
    assert _SECRET_PATTERN.search(command) is None


# ---------------------------------------------------------------------------
# redaction must happen before truncation
# ---------------------------------------------------------------------------

def test_private_key_block_cut_by_the_cap_does_not_leak_key_material():
    """A PEM block crossing the cap has no END marker after a naive cut."""
    pem = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        + "MIIEowIBAAKCAQEAfakefakefake" * 80
        + "\n-----END RSA PRIVATE KEY-----"
    )
    preview = telemetry.command_preview("cat > k.pem <<EOF\n" + pem + "\nEOF")
    assert len(preview) <= telemetry.MAX_COMMAND_PREVIEW
    assert "MIIEow" not in preview
    assert "[REDACTED PRIVATE KEY]" in preview


def test_url_credential_cut_by_the_cap_does_not_leak_the_password():
    """``scheme://user:pass@host`` needs the ``@`` to be matchable."""
    body = "a " * 470 + "git clone https://deployer:" + "P" * 300 + "@git.example.com/x.git"
    preview = telemetry.command_preview(body)
    assert len(preview) <= telemetry.MAX_COMMAND_PREVIEW
    assert "PPPP" not in preview


def test_assignment_straddling_the_cap_keeps_no_value_fragment():
    body = "a" * 960 + " PGPASSWORD=" + "V" * 200
    preview = telemetry.command_preview(body)
    assert len(preview) <= telemetry.MAX_COMMAND_PREVIEW
    assert "VVVV" not in preview


@pytest.mark.parametrize("offset", [900, 950, 970, 980, 985, 990, 1000, 1200])
def test_assignment_anywhere_near_the_cap_is_fully_redacted(offset):
    """Sweep the boundary: the value must never survive in part."""
    body = "b" * offset + " NPM_TOKEN=npmS3cretTokenValue end"
    preview = telemetry.command_preview(body)
    assert "npmS3cretTokenValue" not in preview
    assert "npmS3cret" not in preview


def test_truncation_does_not_leave_a_half_written_marker():
    """Cosmetic but cheap: the cut must not split ``[REDACTED]``."""
    body = "c" * 975 + " PGPASSWORD=x"
    preview = telemetry.command_preview(body)
    assert "REDACT" not in preview.replace(telemetry._REDACTED, "")


def test_redaction_is_idempotent():
    once = telemetry.command_preview("PGPASSWORD=x MYSQL_PWD=y")
    assert telemetry._redact(once) == once


def test_preview_never_exceeds_the_cap_after_redaction():
    body = " ".join(["PGPASSWORD=short"] * 200)
    preview = telemetry.command_preview(body)
    assert len(preview) <= telemetry.MAX_COMMAND_PREVIEW


# ---------------------------------------------------------------------------
# the stored preview, end to end
# ---------------------------------------------------------------------------

def test_record_comparison_stores_redacted_prefixed_credential(monkeypatch):
    captured = {}

    class _Cursor:
        def execute(self, sql, params=None):
            captured[sql.split()[0]] = params
            return self

        def fetchone(self):
            return (0,)

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    class _Conn:
        def execute(self, sql, params=None):
            captured["row"] = params
            return _Cursor()

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def commit(self):
            return None

    monkeypatch.setattr(telemetry, "_connect", lambda: _Conn())

    event_id = telemetry.record_comparison(
        settings=SimpleNamespace(enabled=True, mode="shadow", retention_days=30),
        code="PGPASSWORD=pgS3cretValue psql -c 'select 1'",
        tool_type="bash",
        agent_context=None,
        deterministic={"level": "safe", "score": 0, "blocked_patterns": []},
        model_decision="allow",
        decision_source="decim",
        final_level="safe",
    )
    assert event_id
    stored = [v for v in captured.get("row", ()) if isinstance(v, str)]
    joined = " ".join(stored)
    assert "pgS3cretValue" not in joined
