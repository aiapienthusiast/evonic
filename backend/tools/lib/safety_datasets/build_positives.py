"""Build the constructed-positive corpus.

Sources, in the order the plan specifies:

P3  matrix expansion of versioned family files (coverage by construction)
P2  counterfactual escalation of real adjudicated commands (authentic surface)
P4  obfuscation of the positives above, held out of training entirely
P6  minimal-pair twins, attached to every positive

A row ships only when the constructor and the verifier agree.  Rows that cannot
be re-derived from their text are dropped and counted, never guessed.

Usage::

    python -m backend.tools.lib.safety_datasets.build_positives \
        --dataset data/safety_datasets/dmss-adjudicated-v1.jsonl \
        --out data/safety_datasets/dmss-positives-v1.jsonl

Nothing here executes a command; the only shell interaction is ``bash -n``,
which parses without running.
"""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

from backend.tools.lib.safety_datasets.positives import grammar, obfuscate, verify
from backend.tools.lib.safety_datasets.positives.mutate import verified_escalations


def _finalise(row: dict[str, Any], *, drop: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Verify one row; return it with a text-derived label, or drop it."""
    if not verify.syntax_ok(row["command"]):
        drop.append({"reason": "syntax", "row": row})
        return None
    level, rationale, _ = verify.rederive(row["command"])
    if level == "unknown":
        drop.append({"reason": "no_target_or_operation", "row": row})
        return None
    if row.get("level") is None:          # twin: text is the only source
        row["level"] = level
        row["rationale_code"] = rationale
    elif level != row["level"]:
        drop.append({"reason": f"constructor_verifier_disagree:{row['level']}!={level}", "row": row})
        return None
    row["split"] = grammar.split_of(row["family"], row.get("obfuscation"))
    return row


def build(dataset_path: Path | None = None) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    drop: list[dict[str, Any]] = []

    expanded = grammar.expand()
    rows: list[dict[str, Any]] = []
    for row in expanded:
        final = _finalise(row, drop=drop)
        if final:
            rows.append(final)

    # A twin that still re-derives as positive means the pairing is wrong: the
    # minimal pair would teach nothing. Keep the positive, drop the twin, and
    # count it — the test suite asserts this never happens.
    by_id = {r["id"]: r for r in rows}
    leaking = {r["id"] for r in rows
               if r.get("twin_of") and r["id"] in by_id
               and r["level"] in ("dangerous", "requires_approval")
               and by_id[r["twin_of"]]["level"] in ("dangerous", "requires_approval")}
    leaking = {i for i in leaking if by_id[i]["level"] is not None}
    if leaking:
        drop.extend({"reason": "twin_still_positive", "row": by_id[i]} for i in leaking)
        rows = [r for r in rows if r["id"] not in leaking]

    # P4: obfuscate the surviving positives, held out of train
    obfuscated: list[dict[str, Any]] = []
    for row in rows:
        if row["level"] not in ("dangerous", "requires_approval"):
            continue
        # Every fifth positive is enough to measure semantic reading; spending
        # all of them would leave nothing in the training split.
        if int(row["id"][:8], 16) % 5:
            continue
        for variant in obfuscate.obfuscate(row):
            final = _finalise(variant, drop=drop)
            if final:
                obfuscated.append(final)

    # P2: counterfactual escalation of real commands
    real_rows: list[dict[str, Any]] = []
    if dataset_path and Path(dataset_path).exists():
        real = [json.loads(line) for line in Path(dataset_path).read_text().splitlines() if line.strip()]
        bases = [r for r in real if r["label"]["level"] in ("safe", "warning")]
        for candidate in verified_escalations(bases):
            if not verify.syntax_ok(candidate["command"]):
                drop.append({"reason": "syntax", "row": candidate})
                continue
            candidate["split"] = "train"
            real_rows.append(candidate)

    rows.extend(obfuscated)
    rows.extend(real_rows)
    return rows, summarise(rows, drop)


def summarise(rows: list[dict[str, Any]], drop: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "rows": len(rows),
        "dropped": len(drop),
        "drop_reasons": dict(Counter(d["reason"] for d in drop).most_common()),
        "levels": dict(Counter(r["level"] for r in rows)),
        "sources": dict(Counter(r["source"] for r in rows)),
        "split": dict(Counter(r["split"] for r in rows)),
        "twin_leaks": sum(1 for d in drop if d["reason"] == "twin_still_positive"),
        "families": dict(Counter(r["family"] for r in rows).most_common()),
        "obfuscation": dict(Counter(r["obfuscation"] for r in rows if r.get("obfuscation"))),
        "with_twin": sum(1 for r in rows if r.get("twin_of")),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=None,
                        help="adjudicated real rows; enables the P2 source")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    rows, stats = build(args.dataset)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")

    print(json.dumps(stats, indent=2, sort_keys=True))
    print(f"wrote {args.out} ({args.out.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
