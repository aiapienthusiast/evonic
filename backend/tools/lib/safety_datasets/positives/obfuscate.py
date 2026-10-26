"""Obfuscation layer (source P4): change the form, never the operation.

Every transform here is invertible by ``verify.unwrap``, which is the point:
the label stays derivable, it just takes more work than a substring match.  This
layer is held out of training entirely so "does it read semantics?" is a
measurable question rather than an assumption.

Real telemetry proves these forms are in-distribution, not exotic — agents write
``D="$HOME/."; D="${D}ssh"`` and ``TOKEN=$(...)`` all day.
"""
from __future__ import annotations

import base64
from typing import Any

FORMS = ("variable", "shell", "base64", "xargs")


def _variable(command: str, target: str) -> str:
    return f'T={target}; {command.replace(target, chr(34) + "$T" + chr(34))}'


def _shell(command: str, target: str) -> str:
    return f'bash -lc "{command.replace(chr(34), chr(92) + chr(34))}"'


def _base64(command: str, target: str) -> str:
    encoded = base64.b64encode(command.encode()).decode()
    return f"echo {encoded} | base64 -d | bash"


def _xargs(command: str, target: str) -> str:
    return f"printf '%s\\n' {target} | xargs -I{{}} {command.replace(target, '{}')}"


_BUILDERS = {
    "variable": _variable,
    "shell": _shell,
    "base64": _base64,
    "xargs": _xargs,
}


def obfuscate(row: dict[str, Any], forms=FORMS) -> list[dict[str, Any]]:
    """Return one row per obfuscated form, all marked held-out."""
    out = []
    target = row["target"]
    for form in forms:
        if target not in row["command"]:
            continue
        text = _BUILDERS[form](row["command"], target)
        copy = dict(row)
        copy["id"] = f"{row['id']}-{form}"
        copy["command"] = text
        copy["obfuscation"] = form
        copy["source"] = "P4"
        copy["twin_of"] = row["id"]
        out.append(copy)
    return out
