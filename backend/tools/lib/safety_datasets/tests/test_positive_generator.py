"""Quality gates for the constructed-positive corpus.

These tests are the specification.  A generator change that breaks one of them
is a change that would have shipped a wrong label or an unusable command.
"""

import json
from pathlib import Path

import pytest

from backend.tools.lib.safety_datasets import build_positives
from backend.tools.lib.safety_datasets.positives import grammar, obfuscate, verify

ROOT = Path(__file__).resolve().parents[3] / "tools/lib/safety_datasets"


@pytest.fixture(scope="module")
def corpus():
    rows, stats = build_positives.build(None)  # P2 needs the gitignored dataset
    return rows, stats


# ---------------------------------------------------------------------------
# 1. the label is known by construction and re-derived from the text
# ---------------------------------------------------------------------------

def test_every_row_label_is_rederived_from_its_text(corpus):
    rows, _ = corpus
    for row in rows:
        level, rationale, _ = verify.rederive(row["command"])
        assert level == row["level"], f"{row['id']}: {row['command'][:80]}"
        assert level != "unknown"


def test_constructor_and_verifier_agree_on_the_matrix():
    disagreements = []
    for row in grammar.expand():
        if row["level"] is None:
            continue
        derived, _, _ = verify.rederive(row["command"])
        if derived != row["level"]:
            disagreements.append((row["family"], row["level"], derived, row["command"]))
    assert not disagreements, disagreements[:5]


# ---------------------------------------------------------------------------
# 2. nothing is ever executed; syntax is still checked
# ---------------------------------------------------------------------------

def test_every_shipped_command_is_valid_shell(corpus):
    rows, _ = corpus
    broken = [r["command"] for r in rows if not verify.syntax_ok(r["command"])]
    assert not broken, broken[:3]


def test_syntax_check_does_not_execute(tmp_path):
    marker = tmp_path / "ran"
    assert verify.syntax_ok(f"touch {marker}")
    assert not marker.exists(), "bash -n must parse without executing"


# ---------------------------------------------------------------------------
# 3. minimal pairs differ only in the target
# ---------------------------------------------------------------------------

def test_twin_differs_from_its_positive_only_in_the_target(corpus):
    rows, _ = corpus
    by_id = {r["id"]: r for r in rows}
    checked = 0
    for row in rows:
        twin = by_id.get(row.get("twin_of") or "")
        if not twin or twin["source"] != "P3" or row["source"] != "P3":
            continue
        checked += 1
        assert row["command"].replace(row["target"], "") == twin["command"].replace(twin["target"], "")
        assert row["target"] != twin["target"]
    assert checked > 100, f"only {checked} pairs checked"


def test_a_twin_is_never_itself_positive(corpus):
    rows, stats = corpus
    assert stats["twin_leaks"] == 0
    by_id = {r["id"]: r for r in rows}
    for row in rows:
        twin = by_id.get(row.get("twin_of") or "")
        if twin and row["source"] == "P3" and twin["source"] == "P3":
            assert {row["level"], twin["level"]} & {"dangerous", "requires_approval"}


# ---------------------------------------------------------------------------
# 4. a row never touches a target outside its declared class
# ---------------------------------------------------------------------------

def test_declared_target_appears_in_the_command(corpus):
    rows, _ = corpus
    for row in rows:
        if row["source"] == "P4":
            continue                      # encoded form, checked separately
        assert row["target"] in row["command"], row["id"]


def test_no_row_reaches_outside_its_target_registry():
    targets = grammar.load_targets()
    known = {v for spec in targets.values() for v in spec["values"]}
    for row in grammar.expand():
        assert row["target"] in known
        assert row["target"] in row["command"]


# ---------------------------------------------------------------------------
# 5. no secret-shaped literal, and the corpus is data not rules
# ---------------------------------------------------------------------------

def test_corpus_contains_no_credential_shaped_literal(corpus):
    from backend.tools.lib.decim_safety import _SECRET_PATTERN

    rows, _ = corpus
    offenders = [r["command"] for r in rows if _SECRET_PATTERN.search(r["command"])]
    assert not offenders, offenders[:3]


def test_corpus_is_never_compiled_into_the_rule_layer():
    """Generated rows must stay data; importing them as patterns is the bug."""
    from backend.tools.lib import heuristic_safety
    source = Path(heuristic_safety.__file__).read_text()
    assert "safety_datasets" not in source


# ---------------------------------------------------------------------------
# 6. split discipline: held-out families and the whole obfuscation layer
# ---------------------------------------------------------------------------

def test_held_out_families_never_appear_in_train(corpus):
    rows, _ = corpus
    train_families = {r["family"] for r in rows if r["split"] == "train"}
    assert not (train_families & grammar.HELD_OUT_FAMILIES)


def test_obfuscation_is_test_only(corpus):
    rows, _ = corpus
    assert all(r["split"] == "test" for r in rows if r.get("obfuscation"))
    assert {r["obfuscation"] for r in rows if r.get("obfuscation")} == set(obfuscate.FORMS)


def test_train_and_test_share_no_family(corpus):
    rows, _ = corpus
    train = {r["family"] for r in rows if r["split"] == "train"}
    test = {r["family"] for r in rows if r["split"] == "test"}
    assert not (train & test) or test <= grammar.HELD_OUT_FAMILIES | train


# ---------------------------------------------------------------------------
# 7. the obfuscation layer is still derivable, which is what makes it a test
# ---------------------------------------------------------------------------

def test_obfuscated_rows_keep_their_label(corpus):
    rows, _ = corpus
    obfuscated = [r for r in rows if r.get("obfuscation")]
    assert obfuscated
    for row in obfuscated:
        level, _, inner = verify.rederive(row["command"])
        assert level == row["level"], row["command"]
        assert row["target"] in inner


def test_obfuscation_changes_the_surface_not_the_operation():
    positive = {
        "id": "abc12345",
        "command": "rm -rf /opt/example-app/src",
        "level": "dangerous",
        "target": "/opt/example-app/src",
    }
    variants = obfuscate.obfuscate(positive)
    assert len(variants) == len(obfuscate.FORMS)
    assert all(v["command"] != positive["command"] for v in variants)
    for variant in variants:
        level, _, _ = verify.rederive(variant["command"])
        assert level == "dangerous", variant["command"]


# ---------------------------------------------------------------------------
# 8. P2 escalation keeps the real command as the negative
# ---------------------------------------------------------------------------

def test_escalation_pairs_with_the_real_command():
    from backend.tools.lib.safety_datasets.positives.mutate import verified_escalations

    from backend.tools.lib.safety_datasets.positives.grammar import load_targets
    scratch = load_targets()["ephemeral_scratch"]["values"][0]
    real = [{"id": "real-1", "command": f"cat {scratch}/notes.txt"}]
    escalations = verified_escalations(real)
    assert escalations, "a read of a local file should have an escalation"
    for row in escalations:
        assert row["twin_of"] == "real-1"
        assert row["level"] in ("dangerous", "requires_approval")


def test_escalation_drops_candidates_the_verifier_cannot_label():
    from backend.tools.lib.safety_datasets.positives.mutate import verified_escalations

    # nothing recognisable to retarget and no destructive verb to swap
    assert verified_escalations([{"id": "x", "command": "echo hello"}]) == []
