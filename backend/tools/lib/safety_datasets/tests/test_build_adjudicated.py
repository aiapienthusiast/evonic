"""Tests for the adjudicated real-row dataset builder."""

import json

import pytest

from backend.tools.lib.safety_datasets import build_adjudicated as builder
from backend.tools.lib.safety_datasets.scrub import (
    assert_clean,
    clean_command,
    leak_report,
    scrub_identifiers,
)


# ---------------------------------------------------------------------------
# scrubbing
# ---------------------------------------------------------------------------

def test_clean_command_redacts_env_prefixed_credentials():
    out = clean_command("PGPASSWORD=pgS3cretValue psql -h db")
    assert "pgS3cretValue" not in out
    assert "[REDACTED]" in out


def test_scrub_identifiers_removes_email_ip_and_home_owner():
    out = scrub_identifiers("cat /home/alice/x.txt mail bob@example.com host 10.1.2.3")
    assert "alice" not in out
    assert "bob@example.com" not in out
    assert "10.1.2.3" not in out
    assert "/home/[user]/x.txt" in out


def test_scrub_identifiers_keeps_hostnames_and_project_ids():
    """Target identity is label-bearing signal, so it must survive scrubbing."""
    text = "ssh app-core 'sudo cat /opt/example-app/.env' --project=example-project-000000"
    out = scrub_identifiers(text)
    assert "app-core" in out
    assert "example-project-000000" in out


def test_leak_report_lists_each_kind():
    assert leak_report("a@b.com") == ["email"]
    assert leak_report("10.0.0.1") == ["ipv4"]
    assert leak_report("/home/bob/x") == ["home_path"]
    assert leak_report("glpat-abcdefgh1234") == ["token"]
    assert leak_report("echo hello") == []


def test_assert_clean_fails_closed():
    with pytest.raises(ValueError):
        assert_clean([{"command": "echo ok"}, {"command": "mail a@b.com"}])


# ---------------------------------------------------------------------------
# build
# ---------------------------------------------------------------------------

def _export(tmp_path, events):
    path = tmp_path / "export.json"
    path.write_text(json.dumps({"events": events}))
    return path


def _labels(tmp_path, rows):
    path = tmp_path / "labels.jsonl"
    path.write_text("".join(json.dumps(r) + "\n" for r in rows))
    return path


def test_build_joins_labels_and_marks_disagreement(tmp_path):
    export = _export(tmp_path, [{
        "id": "row-1",
        "occurred_at": "2026-10-25T00:00:00Z",
        "tool_type": "bash",
        "mode": "enforce",
        "detection_command": "git push origin HEAD:main",
        "command_fingerprint": "fp1",
        "deterministic_level": "safe",
        "final_level": "safe",
        "model_decision": "allow",
        "disposition": "executed",
    }])
    labels = _labels(tmp_path, [{
        "id": "row-1",
        "level": "requires_approval",
        "rationale_code": "prod_mutation",
        "confidence": 0.9,
        "method": "hand",
        "evidence_span": "push to default branch",
    }])

    rows, stats = builder.build(export, labels)

    assert rows[0]["label"]["level"] == "requires_approval"
    assert rows[0]["disagreement"] is True
    assert rows[0]["escalation_gap"] is True
    assert stats["disagreements"] == 1
    assert stats["escalation_gap"] == 1
    assert stats["rule_vs_adjudicated"] == {"safe->requires_approval": 1}


def test_build_rejects_an_export_with_unlabelled_rows(tmp_path):
    export = _export(tmp_path, [{"id": "row-x", "detection_command": "ls"}])
    labels = _labels(tmp_path, [])
    with pytest.raises(ValueError):
        builder.build(export, labels)


def test_build_never_publishes_an_identifier(tmp_path):
    export = _export(tmp_path, [{
        "id": "row-2", "tool_type": "bash", "mode": "enforce",
        "detection_command": "mail bob@example.com; curl 10.1.2.3; cat /home/alice/.x",
        "deterministic_level": "safe", "final_level": "safe",
        "model_decision": "allow", "disposition": "executed",
    }])
    labels = _labels(tmp_path, [{
        "id": "row-2", "level": "safe", "rationale_code": "readonly_local",
        "confidence": 0.9, "method": "hand",
    }])
    rows, _ = builder.build(export, labels)
    command = rows[0]["command"]
    assert "bob@example.com" not in command
    assert "10.1.2.3" not in command
    assert "alice" not in command


# ---------------------------------------------------------------------------
# the versioned label file
# ---------------------------------------------------------------------------

def test_shipped_labels_are_unique_and_in_vocabulary():
    labels = builder.load_labels()
    assert len(labels) == 1028
    levels = {"safe", "warning", "requires_approval", "dangerous", "unknown"}
    methods = {"hand", "signature", "unusable"}
    for row in labels.values():
        assert row["level"] in levels, row
        assert row["method"] in methods, row
        assert 0.0 <= row["confidence"] <= 1.0, row


def test_shipped_labels_contain_no_command_text():
    """The label file is versioned, so it must not carry the export's payload."""
    raw = builder.LABELS_PATH.read_text()
    for marker in ("sudo", "rm -rf", "http", "@", "PGPASSWORD"):
        assert marker not in raw, marker
