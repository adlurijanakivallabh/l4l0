"""Cross-engagement pattern memory ("My additions" — adapted from Claude Bug
Bounty's ``pattern_db``, narrowed).

Advisory-only, read at decision time (e.g. Build Order 4's tech-aware
tool/wordlist picker, or Phase-3 class-priority ranking): "this vuln class
was confirmed before against a similar tech stack" is a hunt-priority hint
for a *future* engagement, never a verdict-maker, and never itself a path
to ``write_finding``.

Memory-poisoning guard (OWASP Agentic Security Initiative — a hostile
target must not be able to plant a false "this technique works here" fact
that biases a later, unrelated engagement): the only intended writer is
``_ValidatorSeam.write()`` in ``scan/orchestrator.py``, reached strictly
*after* ``run_oracle`` already confirmed the violation. Nothing here is
ever populated from raw LLM narrative, an unconfirmed candidate, or
unbounded target-controlled content — only the already-oracle-confirmed
``vuln_class``/``oracle_used``/``severity`` plus a fingerprinted
``technology`` string (itself a recon fact, not response body content).

Storage is one JSON object per line (JSONL), schema-validated on read —
a corrupt or unreadable file degrades to "no advisory data", exactly like
every other optional-signal reader in this codebase (fail-open, never a
scan-breaking error).
"""

from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass
from pathlib import Path

_MAX_FIELD = 200
_MAX_RECORDS = 5_000  # hard cap; oldest records drop first on trim
_DEFAULT_PATH = Path(__file__).resolve().parents[3] / "data" / "pattern_db.jsonl"
_lock = threading.Lock()  # ponytail: process-wide lock, not cross-process safe;
# fine for a single GUI process — this is advisory data, never security-critical.


@dataclass(frozen=True)
class Pattern:
    """One past confirmed-finding correlation. Never itself a Finding."""

    vuln_class: str
    technology: str
    oracle_used: str
    severity: str
    timestamp: float


def _validate(raw: object) -> Pattern | None:
    if not isinstance(raw, dict):
        return None
    vuln_class = raw.get("vuln_class")
    technology = raw.get("technology")
    oracle_used = raw.get("oracle_used")
    severity = raw.get("severity")
    timestamp = raw.get("timestamp")
    if not isinstance(vuln_class, str) or not vuln_class:
        return None
    if not isinstance(technology, str) or not isinstance(oracle_used, str):
        return None
    if not isinstance(severity, str):
        return None
    if not isinstance(timestamp, (int, float)) or isinstance(timestamp, bool):
        return None
    return Pattern(
        vuln_class=vuln_class[:_MAX_FIELD],
        technology=technology[:_MAX_FIELD],
        oracle_used=oracle_used[:_MAX_FIELD],
        severity=severity[:_MAX_FIELD],
        timestamp=float(timestamp),
    )


def _trim_if_needed(path: Path) -> None:
    lines = path.read_text(encoding="utf-8").splitlines()
    if len(lines) <= _MAX_RECORDS:
        return
    path.write_text("\n".join(lines[-_MAX_RECORDS:]) + "\n", encoding="utf-8")


def record_confirmed_pattern(
    vuln_class: str,
    technology: str,
    oracle_used: str,
    severity: str,
    *,
    path: str | Path | None = None,
) -> None:
    """Append one advisory record. Intended caller: ``_ValidatorSeam.write()``,
    strictly after ``run_oracle`` already confirmed the finding — never from LLM
    narrative, never from an unconfirmed candidate. Fails open on any I/O error;
    advisory memory must never break a scan. A blank ``technology`` is skipped —
    there is nothing to correlate a future engagement against.
    """
    if not technology:
        return
    destination = Path(path) if path is not None else _DEFAULT_PATH
    record = {
        "vuln_class": vuln_class[:_MAX_FIELD],
        "technology": technology[:_MAX_FIELD],
        "oracle_used": oracle_used[:_MAX_FIELD],
        "severity": severity[:_MAX_FIELD],
        "timestamp": time.time(),
    }
    try:
        with _lock:
            destination.parent.mkdir(parents=True, exist_ok=True)
            with destination.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, sort_keys=True) + "\n")
            _trim_if_needed(destination)
    except OSError:
        pass


def load_patterns(*, path: str | Path | None = None) -> list[Pattern]:
    """Read all valid records. Corrupt/unreadable lines or files are skipped."""
    source = Path(path) if path is not None else _DEFAULT_PATH
    if not source.exists():
        return []
    patterns: list[Pattern] = []
    try:
        with source.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    raw = json.loads(line)
                except json.JSONDecodeError:
                    continue
                validated = _validate(raw)
                if validated is not None:
                    patterns.append(validated)
    except OSError:
        return []
    return patterns


def patterns_for_technology(
    technology: str, *, limit: int = 5, path: str | Path | None = None
) -> list[Pattern]:
    """Advisory lookup: past confirmed vuln classes for a similar tech stack.

    Free-form technology strings (e.g. "WordPress, PHP" vs "wordpress") get a
    case-insensitive substring match either direction. Most-recent first,
    bounded to ``limit``.
    """
    if not technology or limit <= 0:
        return []
    needle = technology.lower()
    matches = [
        pattern
        for pattern in load_patterns(path=path)
        if needle in pattern.technology.lower() or pattern.technology.lower() in needle
    ]
    matches.sort(key=lambda pattern: pattern.timestamp, reverse=True)
    return matches[:limit]
