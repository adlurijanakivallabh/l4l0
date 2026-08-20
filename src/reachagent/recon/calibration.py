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
import socket
import uuid
from collections.abc import Callable
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


# ---------------------------------------------------------------------------
# DNS wildcard pre-check — the subdomain analog of the HTTP calibration above.
#
# Same catch-all FP class, but for subdomain enumeration: a zone with a wildcard
# A record answers ANY random label with the same IP, so a discovered
# "subdomain" may be the catch-all, not a real host. Technique inspiration from
# claude-bug-bounty's recon_engine.sh DNS wildcard pre-check (MIT, paraphrased).
#
# # DECISION BLOCK (D1-D4) — DNS analog, mirroring the HTTP block above
#
# D1. Probe shape.
#     :class:`DnsWildcardProber` resolves N=3 random distinct labels
#     ``<uuid4-hex>.<host>`` at the target's host via an INJECTED resolver
#     callable (default stdlib ``socket.gethostbyname`` — ponytail: no dnspython;
#     tests inject a fake resolver, so hermetic). Deterministic wildcard = >=2 of
#     3 labels resolve AND all resolved to the SAME IP (the wildcard IP). Any
#     label NXDOMAIN / socket error, or differing IPs → wildcard False.
#     Conservative on resolver failure: any error → that label is not resolved;
#     fewer than 2 resolved → no wildcard. Probes the given host directly —
#     multi-level registrable-domain extraction (public-suffix list) is deferred,
#     documented here, not this commit: a target that IS a subdomain checks
#     wildcard at its own level, still a useful honest fact.
#
# D2. Flag + suppress, honestly recorded.
#     When dns_wildcard=True, a subdomain-enumeration hostname (subfinder/amass/
#     theHarvester output) that RESOLVES to the wildcard IP is untrustworthy —
#     the domain answers every random label with that IP, so the "subdomain" may
#     be the catch-all, not a real host. So: wrappers suppress Host facts whose
#     resolved IP == wildcard IP, each audited ``refused_wildcard_dns``; the
#     wildcard fact IS recorded as a Host ``technology`` attribute
#     ``dns_wildcard:<ip>`` on the root target Host (or ``dns_wildcard:none``
#     when checked clean). Resolving each discovered hostname to compare costs
#     one read-only DNS query per hostname — bounded by tool output, acceptable.
#     A hostname that FAILS to resolve is KEPT (conservative — don't over-suppress
#     on uncertainty); only an exact wildcard-IP match suppresses. A real host
#     behind the catch-all IP is the accepted tradeoff, recorded here, not silent.
#
# D3. Wiring — minimal, mirror the HTTP calibration helper exactly.
#     subfinder/amass/theHarvester gain an optional ``dns_wildcard_ip`` field
#     (per-instance, set by ``scan_target`` before ingest — base.py untouched,
#     same mypy-strict reason as the HTTP block). Each wrapper resolves a
#     discovered hostname via an injected ``resolve`` callable (defaulting to
#     ``socket.gethostbyname``) and suppresses on an exact wildcard-IP match.
#     ``scan_target`` runs :class:`DnsWildcardProber` once per domain-shaped
#     target, live mode only (DNS probes fire — dry-run stays zero-probe), hands
#     the wildcard IP to the three subdomain wrappers, and records the
#     ``dns_wildcard`` fact on the root target Host. When None or no wildcard →
#     behavior unchanged.
#
# D4. No oracle, no Finding, no new node/edge type.
#     DNS wildcard is a recon-tier fact (Host ``technology`` attribute + audit
#     entries). Six oracle families held; nothing writes a ``can_call``, a
#     candidate, or a ``Finding``.
# ---------------------------------------------------------------------------


def _default_dns_resolve(hostname: str) -> str | None:
    """Resolve a hostname to one IPv4 address via stdlib, or ``None`` on failure.

    ``socket.gethostbyname`` raises ``socket.gaierror`` on NXDOMAIN and
    ``OSError`` on transient network trouble — both map to ``None`` (treated as
    "not resolved"), which is the conservative, non-suppressing answer (D2).
    """
    try:
        return socket.gethostbyname(hostname)
    except (socket.gaierror, OSError):
        return None


@dataclass(frozen=True)
class DnsWildcardResult:
    """What the DNS probes observed plus the catch-all verdict.

    ``ips`` is one entry per probe label (``None`` = that label did not resolve).
    ``wildcard`` is True only when >=2 labels resolved to the SAME IP.
    """

    wildcard: bool
    wildcard_ip: str | None = None
    ips: tuple[str | None, ...] = ()

    @property
    def shape_label(self) -> str:
        """The Host ``dns_wildcard`` attribute value: ``dns_wildcard:<ip>`` or ``none`` (D2)."""
        if self.wildcard and self.wildcard_ip:
            return f"dns_wildcard:{self.wildcard_ip}"
        return "dns_wildcard:none"


class DnsWildcardProber:
    """Resolve random labels under a host and judge whether the zone is a wildcard.

    Purely a prober: injected resolver in, :class:`DnsWildcardResult` out. It
    never touches the graph — the Host ``dns_wildcard`` fact is recorded by the
    scan entrypoint on the root target Host (D2).
    """

    def __init__(
        self,
        host: str,
        resolve: Callable[[str], str | None] = _default_dns_resolve,
    ) -> None:
        self._host = host.rstrip(".")
        self._resolve = resolve

    def run(self, probe_count: int = 3) -> DnsWildcardResult:
        """Resolve ``probe_count`` distinct random labels and judge wildcard.

        Each label is a fresh random label so no two probes collide and a caching
        resolver cannot serve a cached answer for a "known" label. A label whose
        resolver call raises (or returns ``None``) counts as not resolved —
        conservative, never a wildcard.
        """
        ips: list[str | None] = []
        for _ in range(probe_count):
            label = f"{uuid.uuid4().hex}.{self._host}"
            try:
                ips.append(self._resolve(label))
            except Exception:  # noqa: BLE001 — resolver hiccup is a conservative non-wildcard
                ips.append(None)
        resolved = [ip for ip in ips if ip is not None]
        wildcard = len(resolved) >= 2 and len(set(resolved)) == 1
        return DnsWildcardResult(
            wildcard=wildcard,
            wildcard_ip=resolved[0] if wildcard else None,
            ips=tuple(ips),
        )
