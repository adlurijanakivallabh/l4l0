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

  * **UNION_EXTRACTION** — a known extraction-only sentinel (a seeded user email,
    bcrypt prefix, or sqlite schema artifact) appears verbatim in a successful
    response body. Product-search content alone cannot satisfy this check.

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

  * **OPEN_REDIRECT** — a redirect-shaped query parameter (``redirect``,
    ``next``, ``returnUrl``, ...) was echoed verbatim into the ``Location``
    header of a 3xx response, sending the browser to an attacker-controlled
    host. Read-only GET; the firer never follows the redirect (§10 — the
    destination is never actually visited).

  * **WEB_CACHE_POISONING** — an unkeyed request header (e.g. ``X-Forwarded-
    Host``) is reflected into a cacheable response, and a second, independent
    GET to the exact same cache-busted URL — sent with no special headers —
    still carries the injected marker. The marker can only have reached the
    second request through a shared cache serving the first response back to
    it; that is the confirmed poisoning. A marker reflected only in the
    poisoning probe's own response (not the clean re-read) proves per-request
    reflection with no cache involved — not exploitable, denied. Every probe
    URL carries a run-unique cache-buster, so a real poisoned cache entry is
    never created at a URL another visitor could ever request (§10 spirit —
    no collateral impact on live traffic). Client-side structural class
    (§5/§7, v1.16).

  * **CSRF_MISSING_PROTECTION** — a *structural precondition* for CSRF, not a
    confirmed exploit. Confirming a real CSRF would require firing a forged
    cross-origin state-change, which violates read-only-first (§10); we do not
    do that. Instead we read a normal probe's ``Set-Cookie`` and confirm the
    session cookie is sent cross-site (``SameSite=None``) with no anti-CSRF
    token mechanism in play — the deterministic precondition that leaves the
    app open to forgery. A token present, or ``SameSite=Lax``/``Strict``, means
    the precondition does not hold → denied. An absent ``SameSite`` attribute is
    inconclusive: modern browsers default to ``Lax`` (which blocks top-level
    cross-site POST), so flagging its absence would overclaim. Partial
    client-side structural class (§5/§7, v1.5) — read-only-first preserved
    because no forged state-change is fired.

All paths are deterministic: no LLM, no heuristics. Same evidence in,
same verdict out, every time.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import StrEnum

from reachagent.graph.nodes import FindingStatus
from reachagent.oracles import OracleMechanism
from reachagent.oracles.base import Oracle, OracleVerdict, decision_reason
from reachagent.oracles.evidence import (
    EvidenceMetadata,
    validate_evidence_metadata,
    validate_evidence_ref,
    validate_status_code,
)


class StructuralCheckType(StrEnum):
    """Which structural check this evidence covers."""

    FILE_UPLOAD_BYPASS = "file_upload_bypass"
    PATH_TRAVERSAL = "path_traversal"
    UNION_EXTRACTION = "union_extraction"
    JWT_FORGERY = "jwt_forgery"
    CLICKJACKING = "clickjacking"
    CORS_MISCONFIG = "cors_misconfig"
    OPEN_REDIRECT = "open_redirect"
    CSRF_MISSING_PROTECTION = "csrf_missing_protection"
    WEB_CACHE_POISONING = "web_cache_poisoning"
    # SSRF_RESPONSE (Task 24) — non-blind SSRF: a cloud-metadata / internal
    # endpoint the server fetched, confirmed by a known metadata response marker
    # (sentinel) in the body. Same sentinel-in-body shape as UNION_EXTRACTION —
    # one new check type inside the existing STRUCTURAL family (§7-authorized
    # "new evidence type inside an existing family" pattern; six families held).
    SSRF_RESPONSE = "ssrf_response"
    # SUBDOMAIN_TAKEOVER — a Host's DNS CNAME points at a third-party service
    # that no longer claims it; a GET to the CNAME target returns one of that
    # service's own well-known "unclaimed" markers. Same sentinel-in-body shape
    # as PATH_TRAVERSAL/UNION_EXTRACTION/SSRF_RESPONSE — one more evidence type
    # inside the existing STRUCTURAL family, six families held.
    SUBDOMAIN_TAKEOVER = "subdomain_takeover"


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
      in a successful response → traversal confirmed.

    UNION_EXTRACTION:
      ``union_sentinel``: known user or schema artifact that cannot occur in a
      benign product-search response. ``response_body``: the server's response.
      Sentinel present in a successful response → extraction confirmed.

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

    OPEN_REDIRECT:
      ``probe_status``: the redirect probe's response status. ``sentinel``: the
      exact attacker-controlled URL injected as the redirect parameter's value.
      ``location``: the response's ``Location`` header value. A 3xx status with
      the sentinel present verbatim in ``location`` → violation.

    CSRF_MISSING_PROTECTION:
      ``set_cookie``: the raw ``Set-Cookie`` header value from a normal read
      probe. ``csrf_token_present``: whether the app exposes an anti-CSRF token
      mechanism (the detector determines this). A ``SameSite=None`` session
      cookie with no token mechanism → the structural precondition for CSRF
      holds → violation. This confirms a *precondition*, NOT a confirmed CSRF
      exploit: no forged cross-origin state-change is fired, so read-only-first
      (§10) is preserved.

    WEB_CACHE_POISONING:
      ``probe_status``: the poisoning probe's response status (must be 2xx).
      ``sentinel``: the run-unique marker injected into an unkeyed header.
      ``response_body``: the poisoning probe's own response body. ``reread_
      response_body``: a second, independent GET to the same cache-busted URL,
      sent with no special headers. Marker in both → a shared cache served the
      first response to the second, unrelated request → violation. Marker in
      ``response_body`` only → per-request reflection, no cache involved →
      denied.

    SUBDOMAIN_TAKEOVER:
      ``probe_status``: the CNAME target's response status (must be 2xx —
      most "unclaimed service" pages themselves render successfully; a 4xx/5xx
      proves nothing about claim state). ``sentinel``: one service's known
      "unclaimed" body marker (e.g. an S3 ``NoSuchBucket`` error page, a
      GitHub Pages "there isn't a GitHub Pages site here" message).
      ``response_body``: the CNAME target's response body. Sentinel present in
      a successful response → the service genuinely reports itself unclaimed
      → violation.

    ``evidence_ref``: short, secret-free provenance handle (§13).
    """

    check_type: StructuralCheckType
    baseline_status: int = 0
    probe_status: int = 0
    sentinel: str = ""
    union_sentinel: str = ""
    response_body: str = ""
    reread_response_body: str = ""
    x_frame_options: str = ""
    csp: str = ""
    acao: str = ""
    acac: str = ""
    probe_origin: str = ""
    location: str = ""
    set_cookie: str = ""
    csrf_token_present: bool = False
    evidence_ref: str = ""
    metadata: EvidenceMetadata = field(default_factory=EvidenceMetadata)


def _validate_evidence(evidence: StructuralEvidence) -> None:
    validate_evidence_ref(evidence.evidence_ref)
    validate_evidence_metadata(evidence.metadata)
    for name, value in (
        ("baseline_status", evidence.baseline_status),
        ("probe_status", evidence.probe_status),
    ):
        validate_status_code(value, field=name)
    for name in (
        "sentinel",
        "union_sentinel",
        "response_body",
        "reread_response_body",
        "x_frame_options",
        "csp",
        "acao",
        "acac",
        "probe_origin",
        "location",
        "set_cookie",
    ):
        value = getattr(evidence, name)
        if not isinstance(value, str):
            raise TypeError(f"{name} must be a string")
        limit = 1_000_000 if name in ("response_body", "reread_response_body") else 16_384
        if len(value) > limit:
            raise ValueError(f"{name} exceeds its evidence size limit")
        if any(ord(char) < 32 and char not in "\t\n\r" for char in value):
            raise ValueError(f"{name} contains a control character")
    if not isinstance(evidence.csrf_token_present, bool):
        raise TypeError("csrf_token_present must be a boolean")


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


def _cookie_samesite(set_cookie: str) -> str:
    """Parse the ``SameSite`` attribute of the FIRST cookie in a Set-Cookie value.

    Returns the value lower-cased (``"none"``/``"lax"``/``"strict"``), or ``""``
    when the attribute is absent. Case-insensitive; tolerates whitespace around
    ``=``. Only the leading cookie's attributes are read — splitting on ``,`` is
    unsafe for cookies (expires dates contain commas), so we split on ``;`` and
    never cross into a second cookie.
    """
    first = set_cookie.split(";")
    for attr in first:
        name, sep, value = attr.partition("=")
        if not sep:
            continue
        if name.strip().lower() == "samesite":
            return value.strip().lower()
    return ""


def decide(evidence: StructuralEvidence) -> FindingStatus:
    """Map structural evidence to one verdict — the whole decision (§7).

    Pure and total: every valid input returns exactly one FindingStatus.
    No LLM anywhere in the path.
    """
    _validate_evidence(evidence)
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
        if (
            200 <= evidence.probe_status < 300
            and evidence.sentinel
            and evidence.sentinel in evidence.response_body
        ):
            return FindingStatus.CONFIRMED_VIOLATION
        return FindingStatus.INCONCLUSIVE

    if evidence.check_type is StructuralCheckType.UNION_EXTRACTION:
        if (
            200 <= evidence.probe_status < 300
            and evidence.union_sentinel
            and evidence.union_sentinel in evidence.response_body
        ):
            return FindingStatus.CONFIRMED_VIOLATION
        return FindingStatus.INCONCLUSIVE

    if evidence.check_type is StructuralCheckType.SSRF_RESPONSE:
        # Non-blind SSRF: the server fetched a cloud-metadata / internal endpoint
        # and echoed a known metadata response marker. Sentinel-in-body, same
        # shape as UNION_EXTRACTION: 2xx + sentinel present → confirmed; anything
        # else (no marker, non-2xx) → inconclusive. A 4xx/5xx is not "safe" here —
        # the endpoint may be reachable but error, or the SSRF may land on a
        # non-metadata host — so only the sentinel confirms.
        if (
            200 <= evidence.probe_status < 300
            and evidence.sentinel
            and evidence.sentinel in evidence.response_body
        ):
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

    if evidence.check_type is StructuralCheckType.OPEN_REDIRECT:
        if not (300 <= evidence.probe_status < 400):
            return FindingStatus.INCONCLUSIVE
        if evidence.sentinel and evidence.sentinel in evidence.location:
            return FindingStatus.CONFIRMED_VIOLATION
        # A redirect fired but not to the attacker-controlled target — the
        # server validated/rewrote the destination.
        if evidence.location:
            return FindingStatus.CONFIRMED_DENIED
        return FindingStatus.INCONCLUSIVE

    if evidence.check_type is StructuralCheckType.WEB_CACHE_POISONING:
        if not (200 <= evidence.probe_status < 300) or not evidence.sentinel:
            return FindingStatus.INCONCLUSIVE
        reflected = evidence.sentinel in evidence.response_body
        replayed = evidence.sentinel in evidence.reread_response_body
        # Marker survived into an independent, header-free re-read of the same
        # cache-busted URL — only a shared cache could have carried it there.
        if reflected and replayed:
            return FindingStatus.CONFIRMED_VIOLATION
        # Reflected in the poisoning probe's own response but gone on re-read —
        # per-request reflection, no cache serving it back. Not exploitable.
        if reflected:
            return FindingStatus.CONFIRMED_DENIED
        return FindingStatus.INCONCLUSIVE

    if evidence.check_type is StructuralCheckType.SUBDOMAIN_TAKEOVER:
        if (
            200 <= evidence.probe_status < 300
            and evidence.sentinel
            and evidence.sentinel in evidence.response_body
        ):
            return FindingStatus.CONFIRMED_VIOLATION
        return FindingStatus.INCONCLUSIVE

    if evidence.check_type is StructuralCheckType.CSRF_MISSING_PROTECTION:
        samesite = _cookie_samesite(evidence.set_cookie)
        # SameSite=None ships the session cookie cross-site; with no token
        # mechanism the structural precondition for CSRF holds (precondition,
        # not a confirmed exploit — no forged state-change is fired, §10).
        if samesite == "none" and not evidence.csrf_token_present:
            return FindingStatus.CONFIRMED_VIOLATION
        # A token, or SameSite=Lax/Strict, means the precondition does not hold.
        if evidence.csrf_token_present or samesite in ("lax", "strict"):
            return FindingStatus.CONFIRMED_DENIED
        # Absent SameSite → browsers default to Lax → flagging it would overclaim.
        return FindingStatus.INCONCLUSIVE

    return FindingStatus.INCONCLUSIVE


def _reason(evidence: StructuralEvidence, status: FindingStatus) -> str:
    if status is not FindingStatus.INCONCLUSIVE:
        return decision_reason(OracleMechanism.STRUCTURAL, status)
    detail = {
        StructuralCheckType.FILE_UPLOAD_BYPASS: "baseline_or_probe_not_decisive",
        StructuralCheckType.PATH_TRAVERSAL: "sentinel_not_observed",
        StructuralCheckType.UNION_EXTRACTION: "union_sentinel_not_observed",
        StructuralCheckType.SSRF_RESPONSE: "internal_response_marker_not_observed",
        StructuralCheckType.JWT_FORGERY: "baseline_or_forged_token_not_decisive",
        StructuralCheckType.CLICKJACKING: "header_evidence_missing",
        StructuralCheckType.CORS_MISCONFIG: "credentialed_origin_reflection_absent",
        StructuralCheckType.OPEN_REDIRECT: "redirect_target_not_attacker_controlled",
        StructuralCheckType.CSRF_MISSING_PROTECTION: "same_site_or_token_control_unknown",
        StructuralCheckType.WEB_CACHE_POISONING: "marker_not_replayed_from_cache",
        StructuralCheckType.SUBDOMAIN_TAKEOVER: "unclaimed_service_marker_not_observed",
    }.get(evidence.check_type, "unknown_structural_check")
    return decision_reason(OracleMechanism.STRUCTURAL, status, detail)


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
        metadata = validate_evidence_metadata(evidence.metadata)
        if not metadata.headers:
            headers = tuple(
                (name, value)
                for name, value in (
                    ("x-frame-options", evidence.x_frame_options),
                    ("content-security-policy", evidence.csp),
                    ("access-control-allow-origin", evidence.acao),
                    ("access-control-allow-credentials", evidence.acac),
                    ("location", evidence.location),
                )
                if value
            )
            if headers:
                metadata = replace(metadata, headers=headers).validated()
        return OracleVerdict(
            mechanism=self.mechanism,
            status=status,
            evidence_ref=evidence.evidence_ref,
            reason=_reason(evidence, status),
            evidence_metadata=metadata,
        )
