"""Render a run's durable ``events.jsonl`` into a plaintext, per-agent-
attributed narrative log.

Every event ``ScanRunner._emit`` durably persists already carries a real
``agent_id`` (or is unambiguously operator/system-scoped: ``finding``/
``chain`` are graph-level, not per-agent; ``steering`` is the operator's own
text) — but the only durable record of a run today is the raw JSON stream
itself. Nothing renders it as something a human can actually read top to
bottom and know which agent did what. This module closes that gap with a
pure rendering layer over already-captured data: it invents no new fact
about a run, it only re-presents facts events.jsonl already recorded.

**Timing: rendered once, at scan completion — not incrementally per event.**
This mirrors ``trace.json``'s own precedent exactly (see ``scan.py``'s
``_write_trace_file``/``_trace_summary``): a small, whole-file, *derived*
artifact written once after the run's own real-time data (there, Tracer
spans; here, events.jsonl) is already fully captured, using
``atomic_write_verified`` like every other whole-file run-directory artifact,
rather than an append-only per-line writer like ``events.jsonl``/
``journal.jsonl`` use. The tradeoff is the same one the project already
accepted for trace.json: a scan that crashes before reaching this point
has no narrative.log yet, only the still-durable events.jsonl a future
render can replay — never a lost fact, only a not-yet-rendered one. An
append-per-event alternative was considered and rejected: it would require
touching ScanRunner._emit's own locked hot path (already shared by every
concurrently spawned child in a spawn_agents fan-out) for a purely-cosmetic
artifact, when a cheap, correct, one-shot render of already-durable data
does the same job with a smaller, more isolated diff.

**Sanitization.** ``core.redaction.redact`` (the project's one universal
secret-masking entry point — see its own module docstring) is reused as-is
for secret-shaped substrings. No existing helper anywhere in the codebase
strips control characters or embedded newlines from arbitrary agent-
controlled free text, though — ``core.redaction`` only recognizes secret
*shapes*, and ``report/html.py``'s own ``html.escape``-based ``_e()`` is an
HTML-injection defense meaningless for a plaintext file. A minimal one
(``_sanitize_line``, five lines of stdlib ``re``) is added here rather than
reused from elsewhere, because there is nowhere to reuse it from. It closes
two real risks specific to a plaintext, one-line-per-event log: an
attacker-controlled response body or header captured verbatim into a tool
observation could otherwise embed its own ``\\n[agent-1] ...``-shaped text
and forge what reads as a second, differently-attributed narrative line
inside what is actually a single event; and a raw control/ANSI byte could
corrupt a terminal a human later ``cat``s/``less``s this file in.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from ..core.atomic_io import atomic_write_verified
from ..core.logging import get_logger
from ..core.redaction import redact
from ..paths import EVENTS_FILENAME, NARRATIVE_LOG_FILENAME

_log = get_logger("lalo.narrative")

_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")

# One narrative line stays scannable rather than becoming its own multi-KB
# blob - an observation is already capped well below this by
# agent/loop.py's own _MAX_EMITTED_OBSERVATION_CHARS (2000) before it ever
# reaches events.jsonl, but this line-level cap is what actually keeps a
# *rendered* line skimmable regardless of what any given payload contains.
_MAX_LINE_CHARS = 300

# Categories with no real per-agent author (see this module's own docstring)
# get an explicit, honest placeholder instead of a fabricated agent_id.
_SYSTEM_CATEGORIES = frozenset({"finding", "chain"})


def _sanitize_line(text: str) -> str:
    """Collapse embedded newlines/control characters and mask secret-shaped
    substrings — see this module's own docstring for why both are needed."""
    collapsed = text.replace("\r\n", "\n").replace("\r", "\n").replace("\n", " | ")
    collapsed = _CONTROL_CHARS_RE.sub("", collapsed)
    return redact(collapsed).strip()


def _compact_args(args: dict[str, Any]) -> str:
    """``{"method": "GET", "url": "..."}`` -> ``"GET ..."`` (the common,
    HTTP-shaped tool-call case this project's own tools overwhelmingly use);
    any other shape falls back to plain, sorted ``key=value`` pairs."""
    if "method" in args and "url" in args:
        rest = {k: v for k, v in args.items() if k not in ("method", "url")}
        extra = " ".join(f"{k}={v}" for k, v in sorted(rest.items(), key=str))
        return f"{args['method']} {args['url']}" + (f" {extra}" if extra else "")
    return " ".join(f"{k}={v}" for k, v in sorted(args.items(), key=str))


def _generic_detail(payload: dict[str, Any], *, skip: frozenset[str]) -> str:
    return " ".join(f"{k}={v}" for k, v in sorted(payload.items(), key=str) if k not in skip)


def render_narrative_line(category: str, payload: dict[str, Any]) -> str:
    """One human-readable, agent-attributed line for a single durably-emitted
    ``(category, payload)`` event pair — the exact shape every line of
    ``events.jsonl`` stores under its own ``"category"``/``"payload"`` keys.

    Never raises on an unrecognized category or a missing expected field —
    an events.jsonl written by a future version of this codebase with a new
    event shape falls back to a plain, generic rendering rather than
    breaking every other line's narrative.
    """
    agent_id = (
        "system" if category in _SYSTEM_CATEGORIES else str(payload.get("agent_id", "system"))
    )
    if category == "steering":
        agent_id = "operator"
    event = str(payload.get("event", category))
    skip = frozenset({"agent_id", "event"})

    if category == "log" and event == "tool_call" and isinstance(payload.get("args"), dict):
        detail = f"{payload.get('tool', '?')} {_compact_args(payload['args'])}"
    elif category == "log" and event == "tool_result":
        detail = (
            f"{payload.get('tool', '?')} ok={payload.get('ok')} {payload.get('observation', '')}"
        )
    elif category == "agent":
        detail = (
            f"{payload.get('name', '?')} status={payload.get('status', '?')} "
            f"task={payload.get('task', '')}"
        )
    elif category == "finding":
        detail = (
            f"{payload.get('finding_id', '?')} {payload.get('title', '')} "
            f"severity={payload.get('severity')} confidence={payload.get('confidence')} "
            f"verdict={payload.get('verdict')}"
        )
    elif category == "chain":
        detail = "nodes=" + ",".join(str(n) for n in payload.get("node_ids", []))
    elif category == "steering":
        detail = str(payload.get("text", ""))
    else:
        detail = _generic_detail(payload, skip=skip)

    line = _sanitize_line(f"[{agent_id}] {event}: {detail}".strip())
    if len(line) > _MAX_LINE_CHARS:
        line = line[: _MAX_LINE_CHARS - 1] + "…"
    return line


def _events_path(run_dir: Path) -> Path:
    return run_dir / EVENTS_FILENAME


def _narrative_path(run_dir: Path) -> Path:
    return run_dir / NARRATIVE_LOG_FILENAME


def _iter_events(run_dir: Path) -> Iterator[tuple[str, dict[str, Any]]]:
    """Yield every valid ``(category, payload)`` pair from ``run_dir``'s
    durable ``events.jsonl``, in original emission order - a missing file or
    a torn final line from a crash mid-write are never fatal, mirroring
    ``DurableJournal``/``load_run_events``'s own already-established
    crash-tolerant reload behavior elsewhere in this codebase. Factored out
    of :func:`render_narrative` so :func:`write_per_agent_narrative_logs`
    doesn't have to duplicate the same parse loop."""
    path = _events_path(run_dir)
    if not path.exists():
        return
    lines = path.read_text(encoding="utf-8").splitlines()
    last_index = len(lines) - 1
    for i, raw_line in enumerate(lines):
        raw_line = raw_line.strip()
        if not raw_line:
            continue
        try:
            record = json.loads(raw_line)
        except (json.JSONDecodeError, ValueError):
            # A crash mid-write can only ever torn the LAST line - skip that
            # one without comment (mirrors DurableJournal._load's identical
            # reasoning). Any OTHER line failing to parse is real
            # corruption, not a crash artifact, and dropping it silently
            # would make this run's narrative log read as a complete record
            # when a tool_call/tool_result/finding line is actually missing.
            if i != last_index:
                _log.warning("events.jsonl line %d unparseable, dropping: %s", i, path)
            continue
        if not isinstance(record, dict):
            if i != last_index:
                _log.warning("events.jsonl line %d not a JSON object, dropping: %s", i, path)
            continue
        category, payload = record.get("category"), record.get("payload")
        if isinstance(category, str) and isinstance(payload, dict):
            yield category, payload
        elif i != last_index:
            _log.warning("events.jsonl line %d has an unexpected shape, dropping: %s", i, path)


def render_narrative(run_dir: Path) -> str:
    """Replay ``run_dir``'s durable ``events.jsonl`` into a full plaintext
    narrative — one attributed line per event, in original emission order.
    """
    lines = [
        render_narrative_line(category, payload) for category, payload in _iter_events(run_dir)
    ]
    return "\n".join(lines) + ("\n" if lines else "")


def write_narrative_log(run_dir: Path) -> Path:
    """Render and durably write ``run_dir / "narrative.log"``, replacing any
    prior version — called once, at scan completion (see
    ``ScanRunner._run_inside``), after ``events.jsonl`` already holds every
    event this run will ever emit.

    Routed through :func:`atomic_write_verified` like every other whole-file
    derived run-directory artifact (``trace.json``, the graph, every report
    format) — this file is fully regenerable from ``events.jsonl`` at any
    time, so a plain whole-file replace-and-verify is the right shape here,
    unlike ``events.jsonl``/``journal.jsonl`` themselves.
    """
    path = _narrative_path(run_dir)
    atomic_write_verified(path, render_narrative(run_dir).encode("utf-8"))
    return path


def _narrative_path_for_agent(run_dir: Path, agent_id: str) -> Path:
    return run_dir / f"narrative-{agent_id}.log"


def write_per_agent_narrative_logs(run_dir: Path) -> dict[str, Path]:
    """Additive to :func:`write_narrative_log`'s combined file, never a
    replacement: one ``narrative-<agent_id>.log`` per agent that actually
    participated, filenamed only from the already-safe, system-generated
    ``agent_id`` (never the agent-chosen name/task free text). System/
    operator-scoped events (``finding``/``chain``/``steering`` - see this
    module's own docstring) have no real per-agent author and are excluded
    entirely, never spuriously creating a "system"/"operator" file. Skips
    generating any file at all for a single-agent run - identical content
    to the combined file, a pointless duplicate.
    """
    lines_by_agent: dict[str, list[str]] = {}
    for category, payload in _iter_events(run_dir):
        agent_id = payload.get("agent_id")
        if not isinstance(agent_id, str):
            continue  # system/operator-scoped events have no per-agent home
        lines_by_agent.setdefault(agent_id, []).append(render_narrative_line(category, payload))

    if len(lines_by_agent) < 2:
        return {}

    written: dict[str, Path] = {}
    for agent_id, lines in lines_by_agent.items():
        out_path = _narrative_path_for_agent(run_dir, agent_id)
        atomic_write_verified(out_path, ("\n".join(lines) + "\n").encode("utf-8"))
        written[agent_id] = out_path
    return written
