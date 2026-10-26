"""Build the adjudicated real-row dataset from a DMSS telemetry export.

The export is a secret: it holds live credentials and customer data.  It is
read from a caller-supplied path and never bundled with the repository.  Only
the label file (``adjudicated/dmss-labels-v1.jsonl``) is versioned, and it
contains row ids plus labels — no command text.

Usage::

    python -m backend.tools.lib.safety_datasets.build_adjudicated \
        --export /path/to/dmss-safety-telemetry.json \
        --out data/safety_datasets/dmss-adjudicated-v1.jsonl

Every row carries the original rule/model verdict alongside the adjudicated
label so disagreement is measurable rather than asserted.
"""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

from backend.tools.lib.safety_datasets.scrub import assert_clean, clean_command

LABELS_PATH = Path(__file__).parent / "adjudicated" / "dmss-labels-v1.jsonl"

# Levels the gate can act on.  ``unknown`` rows have no command to judge and are
# excluded from every denominator.
ACTIONABLE = ("safe", "warning", "requires_approval", "dangerous")


def load_labels(path: Path = LABELS_PATH) -> dict[str, dict[str, Any]]:
    labels = {}
    with path.open() as fh:
        for line in fh:
            if line.strip():
                row = json.loads(line)
                labels[row["id"]] = row
    return labels


def build(export_path: Path, labels_path: Path = LABELS_PATH) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    payload = json.loads(Path(export_path).read_text())
    events = payload["events"]
    labels = load_labels(labels_path)

    missing = [e["id"] for e in events if e["id"] not in labels]
    if missing:
        raise ValueError(f"{len(missing)} events have no adjudicated label (stale labels file)")

    rows: list[dict[str, Any]] = []
    for event in events:
        label = labels[event["id"]]
        command = clean_command(event.get("detection_command"))
        rows.append({
            "id": event["id"],
            "occurred_at": event.get("occurred_at"),
            "tool_type": event.get("tool_type"),
            "mode": event.get("mode"),
            "command": command,
            "command_fingerprint": event.get("command_fingerprint"),
            "label": {
                "level": label["level"],
                "rationale_code": label["rationale_code"],
                "confidence": label["confidence"],
                "method": label["method"],
                "evidence_span": label.get("evidence_span", ""),
            },
            "orig": {
                "rule_level": event.get("deterministic_level"),
                "final_level": event.get("final_level"),
                "model_decision": event.get("model_decision"),
                "disposition": event.get("disposition"),
            },
        })

    for row in rows:
        row["disagreement"] = row["orig"]["rule_level"] != row["label"]["level"]
        row["escalation_gap"] = (
            row["label"]["level"] in ("requires_approval", "dangerous")
            and row["orig"]["disposition"] == "executed"
        )

    assert_clean(rows)
    return rows, summarise(rows)


def summarise(rows: list[dict[str, Any]]) -> dict[str, Any]:
    actionable = [r for r in rows if r["label"]["level"] in ACTIONABLE]
    return {
        "rows": len(rows),
        "actionable": len(actionable),
        "unknown": sum(1 for r in rows if r["label"]["level"] == "unknown"),
        "levels": dict(Counter(r["label"]["level"] for r in rows)),
        "methods": dict(Counter(r["label"]["method"] for r in rows)),
        "disagreements": sum(1 for r in rows if r["disagreement"]),
        "escalation_gap": sum(1 for r in rows if r["escalation_gap"]),
        "rule_vs_adjudicated": {
            f"{rule}->{adj}": count
            for (rule, adj), count in Counter(
                (r["orig"]["rule_level"], r["label"]["level"]) for r in actionable
            ).most_common()
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--export", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()

    rows, stats = build(args.export)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")

    print(json.dumps(stats, indent=2, sort_keys=True))
    print(f"wrote {args.out} ({args.out.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
