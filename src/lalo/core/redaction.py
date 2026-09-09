"""The single shared secret-redaction module — used universally.

Two mechanisms in one instance, informed by a reference project's own
architecture-comparison notes on its redaction engine: it has both an
exact-match layer (its own configured credentials, by literal string) and a
pattern-based layer, built via a shared singleton — but the comparison explicitly
flags that engine as *inconsistently applied* (wired into one write path, not
universally). This module fixes that gap: every subsystem that renders text to a
human, a log, a report, or the graph imports these helpers instead of
maintaining its own regex set, so there is exactly one place redaction can drift
and exactly one place everything must route through.

- Pattern-based: catches secrets *discovered on the target* (an unknown API key
  shape, a leaked JWT) that were never configured anywhere.
- Exact-match: catches the operator's *own* configured credentials verbatim (an
  LLM provider key, a login password) even when they don't match any known shape.

Design: fail-closed and conservative. Over-redacting a high-entropy-but-harmless
token is fine; leaking a real secret is not.
"""

from __future__ import annotations

import hashlib
import math
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

REDACTION_PLACEHOLDER = "«REDACTED»"


def _fingerprinted_placeholder(secret: str) -> str:
    """A redaction placeholder that hides ``secret``'s content but stays
    distinguishable from a DIFFERENT secret's own placeholder.

    A single fixed literal for every redacted value (the plain
    ``REDACTION_PLACEHOLDER``) collapses two materially different findings
    whose target URLs differ only in an embedded secret/token (e.g. an
    IDOR proven against two different victims' password-reset links) into
    one dedup identity, silently merging what should be two separately-
    reported findings. The digest is a one-way fingerprint (sha256,
    truncated) - it reveals nothing recoverable about the original value
    beyond confirming a candidate an attacker already holds, exactly like
    the plain placeholder already would for any dedup-identity scheme.

    ONLY call this on a value already known to be high-entropy by
    construction (a structured token shape, or the entropy heuristic) -
    never on a value that could plausibly be short and dictionary-
    guessable (an operator's own login password, a generic key=value
    match of unknown entropy): fingerprinting one of those would let an
    attacker holding the delivered report brute-force a small candidate
    space and confirm a guess against the digest, which the plain,
    non-fingerprinted placeholder never allows.
    """
    digest = hashlib.sha256(secret.encode("utf-8", "surrogateescape")).hexdigest()[:8]
    return f"«REDACTED:{digest}»"


# Structured, algorithmically-generated token shapes: cryptographically
# high-entropy by construction, so fingerprinting them (see
# `_fingerprinted_placeholder`) creates no realistic dictionary/brute-force
# exposure.
_STRUCTURED_TOKEN_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\b"),  # JWT
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),  # AWS access key id
    re.compile(r"\bASIA[0-9A-Z]{16}\b"),  # AWS temp access key id
    re.compile(r"\bghp_[A-Za-z0-9]{30,}\b"),  # GitHub PAT
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),  # GitHub fine-grained PAT
    re.compile(r"\bgh[oprsu]_[A-Za-z0-9]{20,}\b"),  # GitHub oauth/refresh/server tokens
    re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"),  # Anthropic key (before generic sk-)
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),  # OpenAI-style secret key
    re.compile(r"\bsk_live_[0-9A-Za-z]{16,}\b"),  # Stripe live secret
    re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),  # Google API key
    re.compile(r"\bya29\.[0-9A-Za-z_-]{20,}\b"),  # Google OAuth access token
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),  # Slack token
)

# Never fingerprinted, see `_fingerprinted_placeholder`: the PEM header
# matches only the constant header LINE, never the actual key material (no
# entropy to distinguish - every RSA key shares the identical header text),
# and the generic key=value/JSON forms below have a VALUE that could be
# anything, including a short, dictionary-guessable secret (a weak login
# password under password=...).
_UNFINGERPRINTED_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),  # PEM private key
    # key=value / key: value forms for obviously sensitive keys
    re.compile(
        r"(?i)\b(?:bearer|authorization|token|api[_-]?key|secret|client[_-]?secret"
        r"|password|passwd|pwd)\b\s*[=:]\s*\S+"
    ),
    # JSON-style "key": "value" forms for sensitive keys
    re.compile(
        r'(?i)"(?:password|passwd|pwd|secret|token|access_token|refresh_token'
        r'|api[_-]?key|client_secret|authorization)"\s*:\s*"[^"]+"'
    ),
)

# The full set, for looks_secret_shaped's "does this look like any kind of
# secret" check - fingerprinting policy only matters at substitution time.
_TOKEN_PATTERNS: tuple[re.Pattern[str], ...] = (
    _STRUCTURED_TOKEN_PATTERNS + _UNFINGERPRINTED_PATTERNS
)

# Query/param/form keys whose *values* are redacted by name.
_SENSITIVE_KEYS: frozenset[str] = frozenset(
    {
        "password",
        "passwd",
        "pwd",
        "secret",
        "token",
        "access_token",
        "refresh_token",
        "id_token",
        "api_key",
        "apikey",
        "key",
        "authorization",
        "auth",
        "session",
        "sessionid",
        "sid",
        "code",
        "client_secret",
        "otp",
        "signature",
        "sig",
    }
)

# Fixed, pre-approved user-facing messages — mapped from an error code, never
# built from a raw exception string.
_ERROR_MESSAGES: dict[str, str] = {
    "config_error": "Configuration is invalid or incomplete.",
    "provider_error": "A model provider call failed.",
    "provider_refusal": "The model provider declined this request.",
    "provider_unavailable": "The model provider is currently unavailable.",
    "all_providers_failed": "All configured model providers failed.",
    "scope_error": "A scope check failed.",
    "scope_violation": "Target is outside the declared engagement scope.",
    "target_unreachable": (
        "The target failed its reachability preflight; confirm it is up, or turn "
        "off fail_on_unreachable_targets to proceed anyway."
    ),
    "container_error": "The runtime container failed.",
    "spawn_depth_exceeded": (
        "A spawned agent hit the depth ceiling; raise spawn_max_depth if deeper "
        "nesting is expected for this mission."
    ),
    "login_failed": (
        "Login did not produce a usable session; check the identity's "
        "credentials, or turn off fail_on_broken_login to proceed anyway."
    ),
    "session_not_mirrored": (
        "No graph node exists for this session; re-run login for this identity."
    ),
    "jwt_malformed": "The JWT string was not well-formed; capture a fresh token from the target.",
    "totp_secret_invalid": (
        "The TOTP secret is not valid base32; check the seed configured for this identity."
    ),
    "resume_config_mismatch": "This scan's saved state doesn't match the current config.",
    "cost_limit_exceeded": (
        "The run's spend crossed the configured cost ceiling; raise or clear the limit to continue."
    ),
    "unknown": "An unexpected error occurred.",
}

_ENTROPY_CHARSET = re.compile(r"[A-Za-z0-9+/=_\-]+")
_HIGH_ENTROPY_TOKEN = re.compile(r"[A-Za-z0-9+/=_\-]{20,}")


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    length = len(value)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def looks_secret_shaped(value: str) -> bool:
    """Heuristic: does ``value`` look like a credential/token/secret?

    True for known token shapes (JWT, cloud keys, provider keys, ``bearer=...``)
    and for long, high-entropy, whitespace-free base64/hex-ish blobs.
    """
    candidate = value.strip()
    if len(candidate) < 16:
        return False
    for pattern in _TOKEN_PATTERNS:
        if pattern.search(candidate):
            return True
    return bool(
        len(candidate) >= 20
        and " " not in candidate
        and _ENTROPY_CHARSET.fullmatch(candidate) is not None
        and _shannon_entropy(candidate) >= 3.5
    )


class SecretRedactor:
    """Combines pattern-based detection with exact-match of registered secrets.

    One instance is the shared, universal entry point (see the module-level
    ``redact`` convenience below) — every subsystem routes through it rather than
    building its own partial coverage, which is precisely the gap a reference
    redaction engine's own comparison notes flagged (a single shared replacer
    that several call sites simply never wired themselves into).
    """

    def __init__(self) -> None:
        self._exact_secrets: set[str] = set()

    def register_secret(self, value: str) -> None:
        """Register an operator-configured credential for exact-match redaction.

        Catches secrets that don't match any known *shape* (a provider key with
        an unusual format, a login password) as long as they're at least 6 chars
        — short enough values are skipped to avoid redacting common words.
        """
        value = value.strip()
        if len(value) >= 6:
            self._exact_secrets.add(value)

    def redact(self, text: str) -> str:
        if not text:
            return text
        out = text
        # Longest first: if one registered secret is a substring of another
        # (e.g. a key and a truncated/rotated variant of it), redacting the
        # shorter one first would consume part of the longer one's own match,
        # leaking its remainder in plaintext. Set iteration order is otherwise
        # unspecified, so this isn't just a tidiness choice — without it the
        # leak is real but silently order-dependent (seen on most, not all,
        # hash seeds).
        for secret in sorted(self._exact_secrets, key=len, reverse=True):
            if secret in out:
                # Not fingerprinted: an operator-registered secret (e.g. a
                # login password) could plausibly be short/dictionary-
                # guessable - see _fingerprinted_placeholder's own warning.
                out = out.replace(secret, REDACTION_PLACEHOLDER)
        for pattern in _STRUCTURED_TOKEN_PATTERNS:
            out = pattern.sub(lambda m: _fingerprinted_placeholder(m.group(0)), out)
        for pattern in _UNFINGERPRINTED_PATTERNS:
            out = pattern.sub(REDACTION_PLACEHOLDER, out)

        def _maybe_redact(match: re.Match[str]) -> str:
            token = match.group(0)
            # The entropy heuristic itself already requires >=20 chars from
            # a base64/hex-ish charset at shannon_entropy>=3.5 - by
            # construction not dictionary-guessable, safe to fingerprint.
            return _fingerprinted_placeholder(token) if looks_secret_shaped(token) else token

        return _HIGH_ENTROPY_TOKEN.sub(_maybe_redact, out)


# The shared, universal instance. Register operator secrets onto this one object
# (e.g. from config loading) so every call site's `redact()` benefits immediately.
_SHARED = SecretRedactor()

# True (the default) preserves every existing call site's behavior exactly.
# An explicit, informed operator choice — not a project-wide "secrets don't
# matter" stance — to disable it entirely: some engagements want captured
# credentials to appear verbatim in the delivered report/logs (e.g. a
# personal/lab run where the operator IS the only reader and redaction just
# means re-deriving a value they already have from the raw evidence blob);
# others (a client-facing report that gets stored/shared more widely than a
# raw scan log ever would) want it kept on. `set_redaction_enabled` is the
# one process-wide switch every current caller of `redact()` already routes
# through (`core/logging.py`'s formatter, every `findings/tool.py` field) -
# `ScanRunner` sets it once per run from `ScanConfig.redact_findings`.
_ENABLED = True


def set_redaction_enabled(enabled: bool) -> None:
    """Turn redaction on/off process-wide for every existing `redact()` caller."""
    global _ENABLED
    _ENABLED = enabled


def shared_redactor() -> SecretRedactor:
    """Return the one shared redactor instance — register secrets onto this."""
    return _SHARED


def redact(text: str) -> str:
    """Redact ``text`` through the shared instance, unless disabled via
    :func:`set_redaction_enabled` - the universal entry point."""
    if not _ENABLED:
        return text
    return _SHARED.redact(text)


def safe_target_url(url: str) -> str:
    """Return a URL safe to log/display: no userinfo, no fragment, sensitive
    query values redacted by key, and the assembled result run through the
    same pattern/entropy redaction every other field goes through.

    The path is deliberately NOT exempted: an audit found a token embedded
    in the path (``/verify/eyJhbGciOi...``, ``/reset/<token>``) or a query
    value under a key outside the exact-match ``_SENSITIVE_KEYS`` set
    (``resetkey``, ``access-token`` with a dash) reached every downstream
    consumer of this "already redacted" value in cleartext - the dedup key,
    the graph node, the adversarial reviewer's own context, and the
    delivered report - despite this function's own callers documenting it
    as fully sanitized. Redacting the whole assembled URL (not just the
    path) also catches a query value under an unlisted key that the
    per-key pass above didn't recognize.
    """
    try:
        parts = urlsplit(url)
        port = parts.port  # lazily parsed/validated; raises ValueError on a non-numeric port
    except ValueError:
        return REDACTION_PLACEHOLDER
    host = parts.hostname or ""
    netloc = f"{host}:{port}" if port else host  # userinfo dropped
    query = urlencode(
        [
            (key, REDACTION_PLACEHOLDER if key.lower() in _SENSITIVE_KEYS else value)
            for key, value in parse_qsl(parts.query, keep_blank_values=True)
        ]
    )
    return redact(urlunsplit((parts.scheme, netloc, parts.path, query, "")))


def safe_error_from_code(code: str) -> str:
    """Map a stable error code to a fixed, pre-approved message.

    Never returns raw exception text — the whole point is that nothing derived
    from an untrusted source can leak through an error string.
    """
    return _ERROR_MESSAGES.get(code, _ERROR_MESSAGES["unknown"])


def normalize_semantic_label(label: str) -> str:
    """Normalize a free-text label into a stable, safe slug (``[a-z0-9_]+``)."""
    slug = re.sub(r"[^a-z0-9]+", "_", label.strip().lower()).strip("_")
    return slug or "unlabeled"
