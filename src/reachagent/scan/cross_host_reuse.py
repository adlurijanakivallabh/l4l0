"""Cross-host credential reuse (v3 plan V4).

A genuine gap confirmed against every reference project researched this session
(Shannon/Strix/CAI/PentAGI/PentestGPT/hexstrike-ai/claude-bug-bounty) — none of
them tries a credential captured on one in-scope host against another in-scope
host in the same engagement, even though credential/password reuse across
services is a real, common finding class.

Reuses existing, already-tested machinery rather than inventing a parallel path:

  * ``identity.login.detect_login_forms``/``submit_login`` — the exact same
    login-discovery and submission mechanism ``run_default_credentials``
    already uses on the primary host, pointed at a DIFFERENT host's base URL.
  * ``StructuralEvidence(check_type=DEFAULT_CREDENTIALS, ...)`` — the judged
    evidence shape is identical to a default-credential login ("did this
    attempt yield a real, session-backed authentication"); only the finding's
    reported ``vuln_class`` differs, honestly labeling WHERE the credential
    came from.
  * The oracle/write path (``seam.run``/``seam.write``) — unchanged; a
    confirmed reuse is judged and gated exactly like every other finding.

Extraction is deliberately narrow: only a high-confidence JSON-shaped
``"username": "...", "password": "..."`` pair (this project's own real eval
targets — VAmPI/crAPI/Juice Shop — are all JSON APIs) pulled from a body
projection an earlier CONFIRMED finding's own evidence already captured
(``Finding.metadata["evidence_metadata"]`` — Stage E1 work). An HTML-table- or
CSV-shaped credential dump is a fuzzier, lower-confidence extraction
deliberately left out rather than guessed at.
"""

from __future__ import annotations

import json
import logging
import re
from typing import TYPE_CHECKING, Any

import httpx

if TYPE_CHECKING:
    from reachagent.execution.firer import RequestFirer
    from reachagent.graph.store import ReachabilityGraph
    from reachagent.scan.orchestrator import ScanEvent

_log = logging.getLogger(__name__)

__all__ = ["extract_credential_pairs", "run_cross_host_credential_reuse"]

_USER_RE = re.compile(r'"(?:username|user|email)"\s*:\s*"([^"\n]{1,80})"', re.IGNORECASE)
_PASS_RE = re.compile(r'"(?:password|passwd|pwd)"\s*:\s*"([^"\n]{1,80})"', re.IGNORECASE)
_MAX_PAIRS = 3
_MAX_HOSTS = 5


def extract_credential_pairs(body_text: str) -> list[tuple[str, str]]:
    """Bounded, best-effort ``(username, password)`` extraction from an
    already-captured response body projection. Never raises; returns ``[]``
    on anything that doesn't look like a clean JSON credential dump.
    """
    if not body_text:
        return []
    users = _USER_RE.findall(body_text)
    passwords = _PASS_RE.findall(body_text)
    if not users or not passwords:
        return []
    pairs: list[tuple[str, str]] = []
    for username, password in zip(users, passwords, strict=False):
        if username and password and (username, password) not in pairs:
            pairs.append((username, password))
        if len(pairs) >= _MAX_PAIRS:
            break
    return pairs


def _collect_candidate_pairs(graph: ReachabilityGraph) -> list[tuple[str, str]]:
    """Every credential pair extractable from any CONFIRMED finding's own
    captured evidence, deduplicated, bounded to ``_MAX_PAIRS`` overall.
    """
    pairs: list[tuple[str, str]] = []
    for _fid, finding in graph.findings():
        raw = finding.metadata.get("evidence_metadata", "")
        if not raw:
            continue
        try:
            metadata = json.loads(raw)
        except (TypeError, ValueError):
            continue
        if not isinstance(metadata, dict):
            continue
        for key in ("body_projection", "baseline_body_projection", "probe_body_projection"):
            for pair in extract_credential_pairs(str(metadata.get(key, "") or "")):
                if pair not in pairs:
                    pairs.append(pair)
                if len(pairs) >= _MAX_PAIRS:
                    return pairs
    return pairs


def run_cross_host_credential_reuse(
    *,
    graph: ReachabilityGraph,
    firer: RequestFirer,
    base_url: str,
    identity: str,
    seam: Any,
    events: list[ScanEvent],
) -> list[str]:
    """Try every extracted credential pair against every OTHER in-scope host's
    login form, once each, bounded and scope-gated through ``firer``
    (unchanged — this fires no request ``ScopeGuard`` would not already
    allow). Returns the ids of any newly-confirmed findings.
    """
    from reachagent.identity.login import LoginError, detect_login_forms, submit_login
    from reachagent.oracles import OracleMechanism
    from reachagent.oracles.structural import StructuralCheckType, StructuralEvidence
    from reachagent.scan.orchestrator import ScanEvent as _ScanEvent

    def _emit(kind: str, message: str) -> None:
        events.append(_ScanEvent(phase="payloads", kind=kind, message=message))

    found: list[str] = []
    pairs = _collect_candidate_pairs(graph)
    if not pairs:
        return found

    try:
        parsed_base = httpx.URL(base_url)
    except Exception:  # noqa: BLE001 — a malformed base_url must not abort the scan
        return found
    own_host = (parsed_base.host or "").lower()
    scheme = parsed_base.scheme or "https"

    other_hosts = sorted(
        {
            candidate
            for _nid, host in graph.hosts()
            if (candidate := (host.hostname or host.address or "").strip().lower())
            and candidate != own_host
        }
    )
    if not other_hosts:
        return found

    _emit(
        "step",
        f"credential_reuse: trying {len(pairs)} captured pair(s) against {len(other_hosts)} "
        "other in-scope host(s)",
    )
    for host in other_hosts[:_MAX_HOSTS]:
        other_base = f"{scheme}://{host}"
        try:
            forms = detect_login_forms(firer, other_base, identity, graph)
        except Exception as exc:  # noqa: BLE001 — one host's discovery failure is not fatal
            _log.debug("credential_reuse: login discovery failed for %s (%s)", host, exc)
            continue
        if not forms:
            continue
        form = forms[0]  # bounded: first discovered login surface only
        for username, password in pairs:
            try:
                captured = submit_login(firer, identity, form, username, password)
            except LoginError:
                continue
            except Exception as exc:  # noqa: BLE001 — one attempt errors, others still try
                _log.debug("credential_reuse: attempt errored for %s (%s)", host, exc)
                continue
            evidence = StructuralEvidence(
                check_type=StructuralCheckType.DEFAULT_CREDENTIALS,
                probe_status=200,
                session_captured=bool(captured.token or captured.cookies),
                evidence_ref=f"orchestrator/credential_reuse/{form.url}",
            )
            verdict = seam.run(OracleMechanism.STRUCTURAL, evidence)
            if verdict.is_violation:
                nid = seam.write("credential_reuse", seam.last, severity="high")
                if nid:
                    found.append(nid)
                    _emit("finding", f"credential_reuse confirmed on {host} via {form.url}")
                break  # one confirmed pair is enough for this host
    return found
