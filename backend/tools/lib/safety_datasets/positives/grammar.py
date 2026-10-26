"""Matrix expansion for constructed positives (source P3).

Twelve operation families x protected target classes x surface dialects, expanded
from versioned YAML.  A matrix rather than a pile of generated prose buys two
things: recall can be reported per cell (so coverage is provable, not asserted)
and whole families can be held out of training.

Composition rule: a family file stores the *verb* and the target class
separately, and this module joins them.  No file in the repository therefore
contains a runnable destructive command.

Each entry declares what it applied::

    {"verb": "rm -rf {target}", "target": "/opt/example-app/src", ...}

so the label is known by construction.  ``verify`` re-derives it from the text
alone and the row only ships when both agree.
"""
from __future__ import annotations

import hashlib
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable

import yaml

ROOT = Path(__file__).parent
FAMILIES_DIR = ROOT / "families"
TARGETS_PATH = ROOT / "targets.yaml"


@lru_cache(maxsize=8)
def _read_targets(path: str) -> dict[str, Any]:
    return yaml.safe_load(Path(path).read_text())


def load_targets(path: Path = TARGETS_PATH) -> dict[str, dict[str, Any]]:
    return _read_targets(str(path))["targets"]


def load_twins(path: Path = TARGETS_PATH) -> dict[str, str]:
    return yaml.safe_load(path.read_text())["twins"]


def load_families(directory: Path = FAMILIES_DIR) -> list[dict[str, Any]]:
    families = [yaml.safe_load(p.read_text()) for p in sorted(directory.glob("*.yaml"))]
    names = [f["family"] for f in families]
    if len(names) != len(set(names)):
        raise ValueError(f"duplicate family names: {names}")
    return families


def _row_id(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# surface dialects
# ---------------------------------------------------------------------------

def _posix(command: str, target: str) -> str:
    return command


def _chained(command: str, target: str) -> str:
    """Prefix with a benign cd: the same command inside a realistic pipeline."""
    return f"cd /tmp && echo start && {command}"


def _wrapped(command: str, target: str) -> str:
    """The operation hides behind a shell, which is ordinary in this data."""
    escaped = command.replace('"', '\\"')
    return f'bash -lc "{escaped}"'


DIALECTS = {"posix": _posix, "chained": _chained, "wrapped": _wrapped}


def expand(families: Iterable[dict[str, Any]] | None = None,
           targets: dict[str, dict[str, Any]] | None = None,
           twins: dict[str, str] | None = None,
           dialects: Iterable[str] = ("posix", "chained", "wrapped"),
           ) -> list[dict[str, Any]]:
    """Expand every family into rows plus their minimal-pair twins."""
    families = load_families() if families is None else families
    targets = load_targets() if targets is None else targets
    twins = load_twins() if twins is None else twins

    rows: list[dict[str, Any]] = []
    for family in families:
        wants_twin = family.get("twins", True)
        for verb in family["verbs"]:
            if "{target}" not in verb:
                raise ValueError(f"{family['family']}: verb has no target slot: {verb!r}")
            for target_class in family["targets"]:
                if target_class not in targets:
                    raise ValueError(f"unknown target class {target_class!r}")
                for target in targets[target_class]["values"]:
                    command = verb.format(target=target)
                    for dialect in dialects:
                        positive = {
                            "id": _row_id(family["family"], verb, target, dialect),
                            "command": DIALECTS[dialect](command, target),
                            "level": family["level"],
                            "rationale_code": family["rationale_code"],
                            "family": family["family"],
                            "target_class": target_class,
                            "target": target,
                            "verb": verb,
                            "dialect": dialect,
                            "source": "P3",
                            "twin_of": None,
                            "obfuscation": None,
                        }
                        if not wants_twin:
                            rows.append(positive)
                            continue

                        twin_class = twins.get(target_class, "local_repo")
                        twin_target = targets[twin_class]["values"][0]
                        twin = {
                            "id": _row_id(family["family"], verb, twin_target, dialect, "twin"),
                            "command": DIALECTS[dialect](verb.format(target=twin_target), twin_target),
                            "level": None,          # text is the only source
                            "rationale_code": None,
                            "family": family["family"],
                            "target_class": twin_class,
                            "target": twin_target,
                            "verb": verb,
                            "dialect": dialect,
                            "source": "P3",
                            "twin_of": positive["id"],
                            "obfuscation": None,
                        }
                        positive["twin_of"] = twin["id"]
                        rows.extend((positive, twin))
    return rows


def split_of(family: str, obfuscation: str | None = None) -> str:
    """Hold out whole families and the entire obfuscation layer."""
    if obfuscation:
        return "test"
    return "test" if family in HELD_OUT_FAMILIES else "train"


# Families withheld from training so unseen-family recall is measurable.
HELD_OUT_FAMILIES = frozenset({"sql_destructive", "secret_exfil", "iam_destroy"})
