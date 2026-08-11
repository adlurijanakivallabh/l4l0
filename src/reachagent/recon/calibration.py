"""Wildcard/catch-all calibration helper — deferred FP-filtering item (D5).

This is the calibration-baseline helper logged as deferred in
``docs/audits/recon-gap-audit.md`` (and the (b) item from the comprehensive
reference audit, D5 WAF item — technique inspiration from claude-bug-bounty's
``waf_response_analyzer.py``, MIT, paraphrased not copied). It fires a few
random read-only GET paths at a target and decides whether the target serves a
*catch-all* — the same body for any arbitrary path. When it does, content
discovery (gobuster/ffuf/feroxbuster/dirb) path facts are UNTRUSTWORTHY: the
target would return a 200 "exists" for every word, so asserting ``/admin``
exists from a catch-all 200 is a false fact (§6 honesty standard, same as the
corpus semantic-validity guard).

# DECISION BLOCK (D1-D4) — encoded here, mirroring the TLS Option 1/2 style
#
# D1. Where it lives + probe shape.
#     :class:`CalibrationRunner` fires ``probe_count`` (default 3) random,
#     distinct, read-only GET paths (``/reachagent-cal-<uuid4-hex>/nonexistent``)
#     against ``base_url`` through :class:`~reachagent.execution.firer.RequestFirer`
#     — so scope, read-only-first, and audit all hold (no new transport, no new
#     probe mechanism). Returns a :class:`CalibrationResult`. Wildcard is
#     deterministic: all probes 2xx AND identical body length AND identical body
#     hash → the target returns a stable catch-all for arbitrary paths. Any
#     probe 404 / non-2xx / differing size → wildcard False (the target
#     distinguishes real from missing, so content discovery is trustworthy).
#
# D2. Flag vs suppress — SUPPRESS, honestly recorded.
#     When a catch-all is detected, a content-discovery tool's path facts are
#     untrustworthy (the same body for any path ⇒ asserting ``/admin`` exists
#     from a 200-catch-all is a false fact). So wildcard=True ⇒ the content-
#     discovery wrapper emits NO Endpoint facts for that run; each suppressed
#     path is audited ``refused_wildcard_catchall``; and the calibration fact
#     itself IS recorded as a Host ``technology`` attribute
#     ``wildcard_shape:200/size:<n>`` (or ``wildcard_shape:none`` when checked
#     and no catch-all). This is flag-AND-suppress: the Host says catch-all, the
#     suppressed Endpoint facts are not asserted. A real path whose size happens
#     to match the catch-all body is the accepted tradeoff — recorded here, not
#     silently.
#
# D3. Wiring — minimal.
#     Each content-discovery wrapper (gobuster/ffuf/feroxbuster/dirb) gains an
#     optional ``calibration`` on ``parse`` (param) AND a per-instance
#     ``calibration`` field the scan entrypoint sets before ingest. base.py is
#     untouched (its ``parse`` contract is overridden by ~20 wrappers; adding a
#     param there breaks every override under mypy strict and would fail the
#     porcelain gate). ``scan_target`` runs :class:`CalibrationRunner` once per
#     target (live mode only — calibration *fires* probes, so dry-run stays
#     zero-fired) and hands the result to the four content wrappers. When
#     calibration is None or wildcard False, wrapper behavior is unchanged.
#
# D4. No oracle, no Finding, no new node/edge type.
#     Calibration is a recon-tier fact (Host ``technology`` attribute + audit
#     entries). Six oracle families held; nothing here writes a ``can_call``, a
#     candidate, or a ``Finding``.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass

from reachagent.execution.firer import RequestFirer


@dataclass(frozen=True)
class CalibrationResult:
    """What the calibration probes observed, plus the catch-all verdict.

    ``statuses`` / ``sizes`` / ``body_hashes`` / ``content_types`` are one entry
    per probe (order preserved). A probe that errored (transport exhausted) is
    recorded as ``status 0`` / ``size 0`` / empty hash — which can never satisfy
    the wildcard condition, so an infra hiccup is conservative (no suppression
    on uncertainty), not a false positive.
    """

    statuses: tuple[int, ...]
    sizes: tuple[int, ...]
    body_hashes: tuple[str, ...]
    content_types: tuple[str, ...]
    wildcard: bool = False

    @property
    def shape_label(self) -> str:
        """The Host ``wildcard_shape`` attribute value for this result.

        ``200/size:<n>`` when a stable catch-all was detected (n = the shared
        body length), else ``none`` (checked, no catch-all). Per D2 both states
        are recorded so the calibration fact is honest either way.
        """
        if self.wildcard and self.sizes:
            return f"200/size:{self.sizes[0]}"
        return "none"


class CalibrationRunner:
    """Fire read-only calibration probes through the firer and judge catch-all.

    Purely a prober: RequestFirer in, :class:`CalibrationResult` out. It never
    touches the graph, never writes a finding — the Host ``wildcard_shape`` fact
    is recorded by the content-discovery wrapper that consumes the result (D2).
    """

    def __init__(self, firer: RequestFirer, base_url: str, identity: str = "calibration") -> None:
        self._firer = firer
        self._base_url = base_url.rstrip("/")
        self._identity = identity

    def run(self, probe_count: int = 3) -> CalibrationResult:
        """Fire ``probe_count`` distinct read-only GET paths and judge catch-all.

        Each probe is a fresh random path so no two probes collide and a proxy
        cache cannot serve a stale same-body answer for a "known" path. A probe
        that raises (transport error after the firer's bounded retries) is
        recorded as an errored probe (status 0) — conservative, never a wildcard.
        """
        statuses: list[int] = []
        sizes: list[int] = []
        body_hashes: list[str] = []
        content_types: list[str] = []
        for _ in range(probe_count):
            probe_path = f"/reachagent-cal-{uuid.uuid4().hex}/nonexistent"
            try:
                result = self._firer.fire(
                    self._identity, "GET", self._base_url + probe_path, state_changing=False
                )
            except Exception:  # noqa: BLE001 — infra hiccup is a conservative non-wildcard
                statuses.append(0)
                sizes.append(0)
                body_hashes.append("")
                content_types.append("")
                continue
            statuses.append(result.status_code)
            sizes.append(len(result.body))
            body_hashes.append(hashlib.sha256(result.body).hexdigest())
            content_types.append(str(result.headers.get("content-type", "")))

        wildcard = (
            len(statuses) == probe_count
            and all(200 <= s < 300 for s in statuses)
            and len(set(sizes)) == 1
            and len(set(body_hashes)) == 1
        )
        return CalibrationResult(
            statuses=tuple(statuses),
            sizes=tuple(sizes),
            body_hashes=tuple(body_hashes),
            content_types=tuple(content_types),
            wildcard=wildcard,
        )
