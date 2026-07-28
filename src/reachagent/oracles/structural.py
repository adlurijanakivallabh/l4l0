"""Structural oracle — file upload bypass, path traversal, JWT forgery (§7, Phase 3).

The sixth and final §7 oracle family. Confirms structural input-handling
violations deterministically:

  * **FILE_UPLOAD_BYPASS** — a file that should be rejected by the server's
    extension/content-type allowlist was accepted (2xx). Baseline: a legitimately
    allowed file is accepted (confirms the endpoint works). Probe: a disguised
    file (wrong extension, double extension, mismatched content-type). Probe
    accepted → bypass confirmed.

  * **PATH_TRAVERSAL** — a known sentinel string (e.g. ``root:x:0:0``) appears
    verbatim in the response body, proving the server read a file outside the
    intended directory.

  * **JWT_FORGERY** — a forged token (none-algorithm, weak-secret, key-confusion)
    was accepted (2xx) when it should have been refused (401/403). Baseline: a
    valid token is accepted. Probe: the forged token.

  * **CLICKJACKING** — a framable response: the page ships no *effective*
    framing defense. ``X-Frame-Options`` counts only when its value is ``DENY``,
    ``SAMEORIGIN`` or ``ALLOW-FROM <uri>`` (browsers ignore any other value, so
    junk like ``ALLOWALL`` is no defense). A CSP ``frame-ancestors`` directive
    counts only when its source list is non-empty and not solely ``*`` — a bare
    ``frame-ancestors *`` permits all framing and is no defense. Either effective
    defense present → not framable. Both absent → violation. Client-side
    structural class (§5/§7, v1.5).

  * **CORS_MISCONFIG** — an origin-reflected ``Access-Control-Allow-Origin``
    combined with ``Access-Control-Allow-Credentials: true``, letting a
    cross-origin attacker read authenticated responses. A bare ``ACAO: *`` is
    NOT exploitable with credentials (browsers reject the pair), so it is never
    a violation. Client-side structural class (§5/§7, v1.5).

All paths are deterministic: no LLM, no heuristics. Same evidence in,
same verdict out, every time.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from reachagent.graph.nodes import FindingStatus
from reachagent.oracles import OracleMechanism
from reachagent.oracles.base import Oracle, OracleVerdict


class StructuralCheckType(StrEnum):
    """Which structural check this evidence covers."""

    FILE_UPLOAD_BYPASS = "file_upload_bypass"
    PATH_TRAVERSAL = "path_traversal"
    JWT_FORGERY = "jwt_forgery"
    CLICKJACKING = "clickjacking"
    CORS_MISCONFIG = "cors_misconfig"


@dataclass(frozen=True)
class StructuralEvidence:
    """Evidence for the structural oracle.

    ``check_type`` selects the decision branch.

    FILE_UPLOAD_BYPASS:
      ``baseline_status``: response to a legitimately allowed file (must be 2xx
      for the probe to mean anything — same guard as the differential oracle's
      baseline-GRANTED requirement).
      ``probe_status``: response to the disguised/disallowed file. 2xx = bypass.

    PATH_TRAVERSAL:
      ``sentinel``: known string that proves out-of-scope file access (e.g.
      ``root:x:0:0``). ``response_body``: the server's response. Sentinel present
      verbatim → traversal confirmed.

    JWT_FORGERY:
      ``baseline_status``: response to a valid token (must be 2xx).
      ``probe_status``: response to the forged token. 2xx = forgery accepted.

    CLICKJACKING:
      ``x_frame_options``: the response's ``X-Frame-Options`` header value —
      effective only when it is ``DENY``, ``SAMEORIGIN`` or ``ALLOW-FROM <uri>``
      (case-insensitive); any other value is ignored by browsers. ``csp``: the
      raw ``Content-Security-Policy`` header value — its ``frame-ancestors``
      directive is effective only when its source list is non-empty and not
      solely ``*``. Both defenses absent/ineffective → framable → violation.

    CORS_MISCONFIG:
      ``acao``: the ``Access-Control-Allow-Origin`` value the server returned.
      ``acac``: the ``Access-Control-Allow-Credentials`` value returned
      (credentials on iff it lower-cases to ``true``). ``probe_origin``: the
      attacker ``Origin`` we sent — reflection is present when ``acao`` equals it.
      Origin-reflected ACAO with credentials on → violation; ``ACAO: *`` with
      credentials is not exploitable → denied.

    ``evidence_ref``: short, secret-free provenance handle (§13).
    """

    check_type: StructuralCheckType
    baseline_status: int = 0
    probe_status: int = 0
    sentinel: str = ""
    response_body: str = ""
    x_frame_options: str = ""
    csp: str = ""
    acao: str = ""
    acac: str = ""
    probe_origin: str = ""
    evidence_ref: str = ""


def _xfo_is_effective(xfo: str) -> bool:
    """Whether an ``X-Frame-Options`` value actually blocks framing.

    Browsers honour only ``DENY``, ``SAMEORIGIN`` and ``ALLOW-FROM <uri>``; any
    other value (empty, ``ALLOWALL``, garbage) is ignored and leaves the page
    framable. Matched case-insensitively.
    """
    value = xfo.strip().lower()
    return value in ("deny", "sameorigin") or value.startswith("allow-from ")


def _csp_frame_ancestors_is_effective(csp: str) -> bool:
    """Whether the CSP ``frame-ancestors`` directive actually restricts framing.

    Effective only when the directive is present with a non-empty source list
    that is not solely ``*`` — a bare ``frame-ancestors *`` permits all framing
    and is no defense. Pure string parse, no network.
    """
    lowered = csp.lower()
    marker = "frame-ancestors"
    idx = lowered.find(marker)
    if idx == -1:
        return False
    # Source list runs from after the directive name to the next ';'.
    rest = csp[idx + len(marker) :]
    rest = rest.split(";", 1)[0]
    sources = rest.split()
    if not sources:
        return False
    return sources != ["*"]


def decide(evidence: StructuralEvidence) -> FindingStatus:
    """Map structural evidence to one verdict — the whole decision (§7).

    Pure and total: every valid input returns exactly one FindingStatus.
    No LLM anywhere in the path.
    """
    if evidence.check_type is StructuralCheckType.FILE_UPLOAD_BYPASS:
        # Baseline must be accepted to confirm the endpoint is functional.
        if not (200 <= evidence.baseline_status < 300):
            return FindingStatus.INCONCLUSIVE
        # Probe accepted when it should have been rejected → bypass.
        if 200 <= evidence.probe_status < 300:
            return FindingStatus.CONFIRMED_VIOLATION
        # Probe correctly rejected.
        if evidence.probe_status in range(400, 500):
            return FindingStatus.CONFIRMED_DENIED
        return FindingStatus.INCONCLUSIVE

    if evidence.check_type is StructuralCheckType.PATH_TRAVERSAL:
        if evidence.sentinel and evidence.sentinel in evidence.response_body:
            return FindingStatus.CONFIRMED_VIOLATION
        return FindingStatus.INCONCLUSIVE

    if evidence.check_type is StructuralCheckType.JWT_FORGERY:
        if not (200 <= evidence.baseline_status < 300):
            return FindingStatus.INCONCLUSIVE
        if 200 <= evidence.probe_status < 300:
            return FindingStatus.CONFIRMED_VIOLATION
        if evidence.probe_status in range(400, 500):
            return FindingStatus.CONFIRMED_DENIED
        return FindingStatus.INCONCLUSIVE

    if evidence.check_type is StructuralCheckType.CLICKJACKING:
        # A framing defense is effective only when XFO is DENY/SAMEORIGIN/
        # ALLOW-FROM, OR the CSP frame-ancestors source list is non-empty and
        # not solely '*'. Violation only when BOTH are ineffective.
        defended = _xfo_is_effective(evidence.x_frame_options) or _csp_frame_ancestors_is_effective(
            evidence.csp
        )
        if defended:
            return FindingStatus.CONFIRMED_DENIED
        return FindingStatus.CONFIRMED_VIOLATION

    if evidence.check_type is StructuralCheckType.CORS_MISCONFIG:
        acao = evidence.acao.strip()
        # No ACAO returned at all → CORS is off, nothing to judge.
        if not acao:
            return FindingStatus.INCONCLUSIVE
        credentials_on = evidence.acac.strip().lower() == "true"
        origin_reflected = bool(evidence.probe_origin) and acao == evidence.probe_origin
        wildcard = acao == "*"
        # Origin-reflected ACAO with credentials → attacker reads authed data.
        if origin_reflected and credentials_on:
            return FindingStatus.CONFIRMED_VIOLATION
        # ACAO: * with credentials is rejected by browsers → not exploitable.
        # Reflection without credentials, or any other shape → denied.
        if wildcard or origin_reflected or credentials_on:
            return FindingStatus.CONFIRMED_DENIED
        return FindingStatus.INCONCLUSIVE

    return FindingStatus.INCONCLUSIVE


class StructuralOracle(Oracle):
    """Confirms structural input-handling violations — sixth §7 family."""

    mechanism = OracleMechanism.STRUCTURAL

    def run(self, evidence: object) -> OracleVerdict:
        """Return the deterministic verdict for ``evidence``.

        ``evidence`` must be :class:`StructuralEvidence`. Raises ``TypeError``
        on wrong type — a mis-wired caller is a bug, not an inconclusive result.
        """
        if not isinstance(evidence, StructuralEvidence):
            raise TypeError(
                f"StructuralOracle needs StructuralEvidence, got {type(evidence).__name__}"
            )
        status = decide(evidence)
        return OracleVerdict(
            mechanism=self.mechanism,
            status=status,
            evidence_ref=evidence.evidence_ref,
        )
