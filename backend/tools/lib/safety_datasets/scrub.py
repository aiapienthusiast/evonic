"""Redaction and leak scanning for derived safety datasets.

Two layers, deliberately separate:

``redact``
    Removes credential-shaped material using the same patterns the telemetry
    writer uses, so a derived dataset can never re-publish a secret that the
    live preview would have caught.
``scrub_identifiers``
    Removes personal and network identifiers that are irrelevant to the safety
    label (emails, IP addresses, home directory owners).  Hostnames and project
    identifiers are **kept**: "which target is this" is exactly the signal the
    label depends on.

``leak_scan`` fails closed.  A build that cannot prove the output is clean does
not produce output.
"""
from __future__ import annotations

import re

from backend.services.decim_safety_telemetry import _redact as redact_credentials

_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6 = re.compile(r"\b(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}\b", re.I)
_HOME = re.compile(r"(/home/|/Users/)([A-Za-z0-9._-]+)")
_TOKEN_LIKE = re.compile(
    r"\b(?:glpat-[A-Za-z0-9_-]{8,}|ghp_[A-Za-z0-9]{8,}|sk-[A-Za-z0-9]{8,}|"
    r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,})\b"
)

_PLACEHOLDER = {
    "email": "[EMAIL]",
    "ip": "[IP]",
    "home": r"\1[user]",
    "token": "[TOKEN]",
}


def scrub_identifiers(text: str) -> str:
    """Remove personal and network identifiers that the label does not need."""
    if not text:
        return ""
    text = _TOKEN_LIKE.sub(_PLACEHOLDER["token"], text)
    text = _EMAIL.sub(_PLACEHOLDER["email"], text)
    text = _IPV4.sub(_PLACEHOLDER["ip"], text)
    text = _IPV6.sub(_PLACEHOLDER["ip"], text)
    text = _HOME.sub(_PLACEHOLDER["home"], text)
    return text


def clean_command(text: str | None) -> str:
    """Credential-redact, then identifier-scrub, then credential-redact again.

    The second credential pass is belt and braces: identifier scrubbing rewrites
    substrings (``user@host`` becomes ``[EMAIL]``) and could in principle splice
    a new assignment-looking fragment together.
    """
    if not text:
        return ""
    return redact_credentials(scrub_identifiers(redact_credentials(text)))


def leak_report(text: str) -> list[str]:
    """Return the kinds of identifier still present in *text* (empty == clean)."""
    found = []
    if _EMAIL.search(text):
        found.append("email")
    if _IPV4.search(text):
        found.append("ipv4")
    if _TOKEN_LIKE.search(text):
        found.append("token")
    if _HOME.search(text):
        found.append("home_path")
    return found


def assert_clean(rows: list[dict], *, field: str = "command") -> None:
    """Fail closed: raise if any row still carries an identifier."""
    dirty = [(i, leak_report(r.get(field) or "")) for i, r in enumerate(rows)]
    dirty = [(i, kinds) for i, kinds in dirty if kinds]
    if dirty:
        sample = ", ".join(f"row {i}: {kinds}" for i, kinds in dirty[:5])
        raise ValueError(f"leak scan failed on {len(dirty)} rows ({sample})")
