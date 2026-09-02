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

  * **PROTOTYPE_POLLUTION** (v2 W9) — a page loaded with an injected
    ``__proto__``-shaped query parameter, then evaluated in-page: a brand-new
    ``{}`` object literal carries a property it was never given. A fresh POJO
    can never have an arbitrary own or inherited property unless the page's
    own client-side merge logic actually polluted ``Object.prototype`` — one
    in-page JS observation is unambiguous, no baseline/differential needed.
    Client-side structural class (§5/§7, v2).

All paths were deterministic: no LLM, no heuristics. Same evidence in,
same verdict out, every time.

v3 architecture decision: the fixed ``decide(evidence)`` if/elif decision
chain (and the check-specific helpers it alone used —
``_validate_evidence``, ``_xfo_is_effective``, ``_csp_frame_ancestors_is_
effective``, ``_cookie_samesite``, ``_reason``) has been REMOVED. Live
confirmation for every check type above now goes through LLM judgment
(``reachagent.oracles.llm_judgment.judge``), wired directly into
``tools/validator.py::run_oracle`` and ``detection/oracle_gateway.py::
registry_runner``. ``StructuralOracle`` is kept only as an inert shim so
``reachagent.oracles.registry`` can still register
``OracleMechanism.STRUCTURAL`` — its ``run()`` no longer decides anything.

The dataclasses in this module (``StructuralCheckType``, ``StructuralEvidence``)
remain in active use as the evidence-shape vocabulary: every structural
detector still builds a ``StructuralEvidence`` of the appropriate
``StructuralCheckType`` and hands it to LLM judgment for confirmation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from reachagent.oracles import OracleMechanism
from reachagent.oracles.base import Oracle, OracleVerdict
from reachagent.oracles.evidence import EvidenceMetadata

# v2 Phase 6 Stage E1: a bounded, real evidence snippet for the GUI/report to show
# instead of only an opaque evidence_ref handle — window of context either side of
# the matched sentinel (the actual proof a human would want to see), or the response
# body's own start when no sentinel exists for this check type. _validate_projection
# (oracles/evidence.py) already caps length and scrubs raw secret values; this just
# picks WHICH bounded slice to hand it, mirroring the existing header auto-fill below.
_BODY_PROJECTION_CONTEXT_CHARS = 200


def _body_projection(evidence: StructuralEvidence) -> str:
    body = evidence.response_body
    if not body:
        return ""
    sentinel = evidence.sentinel or evidence.union_sentinel
    if sentinel:
        index = body.find(sentinel)
        if index != -1:
            start = max(0, index - _BODY_PROJECTION_CONTEXT_CHARS)
            end = min(len(body), index + len(sentinel) + _BODY_PROJECTION_CONTEXT_CHARS)
            return ("…" if start > 0 else "") + body[start:end] + ("…" if end < len(body) else "")
    return body[: _BODY_PROJECTION_CONTEXT_CHARS * 2]


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
    # INFO_DISCLOSURE — a response body contains a known framework/language
    # stack-trace or debug-page marker (e.g. a Java JSP exception trace, a
    # Python traceback, a Django/Spring/PHP debug page), proving the app
    # leaked implementation detail in an error response. Same sentinel-in-body
    # shape as the checks above — the fixed marker table lives with the
    # detector (`reachagent.info_disclosure.detector`), not here; this oracle
    # only reconfirms a specific, already-identified marker is verbatim
    # present, exactly like every other sentinel-in-body check.
    INFO_DISCLOSURE = "info_disclosure"
    # DEFAULT_CREDENTIALS — a well-known username/password pair authenticated
    # successfully against a discovered login form. Same accept-or-reject
    # shape as JWT_FORGERY (a credential either produced a real session or it
    # didn't) — the detector (`reachagent.default_creds.detector`) determines
    # `session_captured` from the login attempt's actual response (real
    # token/cookies present, not just a 2xx status); this oracle only
    # reconfirms that determination deterministically.
    DEFAULT_CREDENTIALS = "default_credentials"
    # RATE_LIMIT_ABSENT — a small, bounded burst of login attempts (never a
    # real brute force) never triggered any defensive signal (a 429 status,
    # or a known lockout/throttle body marker). Same "was a specific
    # defensive mechanism present or absent" shape as CLICKJACKING/CORS —
    # the detector runs the bounded burst and determines
    # `lockout_signal_observed`; this oracle only reconfirms the completeness
    # + presence/absence logic deterministically.
    RATE_LIMIT_ABSENT = "rate_limit_absent"
    # CLOUD_BUCKET_EXPOSURE — a generated cloud-storage bucket name (S3/GCS/
    # Azure naming convention derived from the target) turns out to both
    # exist AND be publicly listable without authentication. Same
    # sentinel-in-body shape as SUBDOMAIN_TAKEOVER/PATH_TRAVERSAL: a known
    # "this is a real, listable bucket" marker (e.g. S3/GCS's
    # ``<ListBucketResult``, Azure's ``<EnumerationResults``) present in a
    # 2xx response confirms exposure. A "no such bucket" response is simply
    # not applicable (try the next candidate name); a 403/AccessDenied means
    # the bucket exists but is properly secured — denied, not a finding.
    CLOUD_BUCKET_EXPOSURE = "cloud_bucket_exposure"
    # KNOWN_VULNERABLE_VERSION — a fingerprinted Host.technology/detected_version
    # (e.g. "Apache Tomcat/7.0.92") has at least one known CVE per a live NVD
    # lookup (reachagent.cve_intel.nvd_client — a threat-intel enrichment of a
    # deterministic fact, never a scanner import per CLAUDE.md §9). Same
    # sentinel-in-response shape as PATH_TRAVERSAL/SUBDOMAIN_TAKEOVER, but with
    # NO status-code gate: unlike a traversal payload, a version banner is just
    # as real on a 403/404/500 error page as on a 2xx. This oracle confirms only
    # that the exact version string is genuinely present in the CURRENT live
    # response, not stale graph data from an earlier recon pass — the CVE match
    # itself is an already-established external-database fact, decided before
    # the oracle ever runs (same role as DEFAULT_CREDENTIALS's login attempt).
    KNOWN_VULNERABLE_VERSION = "known_vulnerable_version"
    # PROTOTYPE_POLLUTION (v2 W9) — a fresh, in-page object literal (`{}`) carries a
    # property it was never given. A brand-new POJO can NEVER have an arbitrary own or
    # inherited property unless Object.prototype itself was polluted by the page's own
    # client-side merge logic processing our injected `__proto__`-shaped query parameter —
    # so this single in-page JS observation is unambiguous, no baseline/differential
    # needed (unlike most other checks here). Client-side structural class (§5/§7).
    PROTOTYPE_POLLUTION = "prototype_pollution"


_MAX_BODY_CHARS = 1_000_000


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

    INFO_DISCLOSURE:
      ``sentinel``: the specific known stack-trace/debug-page marker the
      detector already identified as a candidate match. ``response_body``:
      the probed response body. ``probe_status``: the probe's status code —
      unrestricted (a leak can appear on a 200, 404, or 500 alike; the marker
      itself, not the status, is the evidence). Sentinel present verbatim →
      violation.

    DEFAULT_CREDENTIALS:
      ``session_captured``: whether the login attempt actually returned real
      session material (a token or cookies) — the detector's own login
      submission determined this, not a status-code guess. ``probe_status``:
      the login response's status. A captured session on a non-error status
      → violation; no session material → the credential pair failed.

    CLOUD_BUCKET_EXPOSURE:
      ``probe_status``: the guessed bucket URL's response status (must be
      2xx — a listable bucket renders its listing successfully; a 4xx
      proves nothing about listability). ``sentinel``: the provider's own
      "this is a real listing" body marker. ``response_body``: the probed
      response body. Sentinel present in a successful response → the
      bucket is genuinely publicly listable → violation.

    RATE_LIMIT_ABSENT:
      ``attempts_planned``/``attempts_completed``: the bounded burst size and
      how many attempts actually got a real HTTP response (a partial burst —
      network failures, a safety-gate refusal — carries no trustworthy
      signal). ``lockout_signal_observed``: whether ANY attempt in the burst
      showed a 429 status or a known lockout/throttle body marker — the
      detector's own determination. A complete burst with no lockout signal
      → violation (no rate limiting); a lockout signal observed → denied
      (rate limiting works); an incomplete burst → inconclusive.

    KNOWN_VULNERABLE_VERSION:
      ``sentinel``: the fingerprinted version string (e.g.
      ``Apache Tomcat/7.0.92``). ``response_body``: the live re-probe's
      searchable text (headers and body both concatenated in by the
      detector — a version banner may live in either). ``probe_status``:
      the live re-probe's status, carried for evidence only — NOT gated on,
      since a version banner is just as real on an error page as a 2xx.
      Sentinel present anywhere in the live response → the fingerprint is
      current, not stale → violation (the CVE match itself was already
      established, before this oracle ever ran, by a live NVD lookup).

    PROTOTYPE_POLLUTION:
      ``probe_status``: the page load's HTTP status (must be 2xx — a non-2xx
      error page proves nothing about whether the app's client-side merge
      logic ever ran). ``polluted``: whether a fresh ``{}`` literal evaluated
      in that same page load carries the injected marker property. A decisive
      2xx load with the marker present → violation; a decisive 2xx load with
      no marker → confirmed not polluted via this vector; a non-2xx load →
      inconclusive (the page never meaningfully executed).

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
    session_captured: bool = False
    attempts_planned: int = 0
    attempts_completed: int = 0
    lockout_signal_observed: bool = False
    polluted: bool = False
    evidence_ref: str = ""
    metadata: EvidenceMetadata = field(default_factory=EvidenceMetadata)

    def __post_init__(self) -> None:
        # A live target's response body has no upper bound a detector
        # controls — cap it here, at construction (the one place every
        # in-process driver AND the MCP boundary both route through),
        # so an oversized body degrades to a truncated, still-decidable
        # value instead of raising out of _validate_evidence and aborting
        # whatever driver is mid-check. Caught live: crAPI's
        # cache_poisoning driver hit an oversized response_body and took
        # the entire remaining scan down with it (frozen dataclass, so
        # object.__setattr__ is required here).
        for name in ("response_body", "reread_response_body"):
            value = getattr(self, name)
            if isinstance(value, str) and len(value) > _MAX_BODY_CHARS:
                object.__setattr__(self, name, value[:_MAX_BODY_CHARS])


class StructuralOracle(Oracle):
    """Inert v3 shim — kept only so ``oracles.registry`` can still register
    ``OracleMechanism.STRUCTURAL`` (and so ``get_oracle(STRUCTURAL)`` keeps
    validating as a known mechanism for callers like
    ``recon/tools/signal_gated.py``, which only checks that the lookup does
    not raise and never calls ``.run()``).

    The fixed ``decide()`` chain that used to back this class is gone; no
    caller on the live confirmation path invokes ``run()`` any more
    (``tools/validator.py::run_oracle`` goes straight to
    ``oracles.llm_judgment.judge`` instead), so this raises rather than
    pretend to decide anything.
    """

    mechanism = OracleMechanism.STRUCTURAL

    def run(self, evidence: object) -> OracleVerdict:
        """No longer decides a verdict — see the class docstring.

        The type guard below predates ``decide()`` and is independent of it
        (a mis-wired caller passing the wrong evidence type is still a bug,
        not a removed-feature question), so it is kept. Before v3, ``run()``
        also auto-filled ``evidence_metadata`` (a ``headers`` tuple from the
        header-shaped evidence fields, and a ``body_projection`` snippet via
        the ``_body_projection`` helper above) ahead of calling the
        now-removed ``decide()``. That auto-fill logic was independent of
        ``decide()`` too and is not dead by necessity — it is preserved
        verbatim in this task's report for a human to relocate (e.g. into
        ``oracles/llm_judgment.py``'s own verdict construction) rather than
        silently lost.
        """
        if not isinstance(evidence, StructuralEvidence):
            raise TypeError(
                f"StructuralOracle needs StructuralEvidence, got {type(evidence).__name__}"
            )
        raise NotImplementedError(
            "StructuralOracle.run() was removed in v3 — confirmation now goes "
            "through reachagent.oracles.llm_judgment.judge"
        )
