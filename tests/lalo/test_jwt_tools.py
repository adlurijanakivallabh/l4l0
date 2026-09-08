"""Tests for the pure JWT decode/tamper helpers."""

from __future__ import annotations

import base64
import hashlib
import hmac as hmac_module
import json

import pytest

from lalo.core.errors import JwtMalformedError
from lalo.identity.jwt_tools import jwt_alg_none, jwt_crack_secret, jwt_decode, jwt_with_claim


def _b64url(obj: object) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode("utf-8")).rstrip(b"=").decode("ascii")


def _make_token(
    header: dict[str, object], payload: dict[str, object], signature: str = "sig"
) -> str:
    return f"{_b64url(header)}.{_b64url(payload)}.{signature}"


def test_jwt_decode_round_trips_header_and_payload() -> None:
    token = _make_token({"alg": "HS256", "typ": "JWT"}, {"sub": "user-1", "role": "user"})
    decoded = jwt_decode(token)
    assert decoded.header == {"alg": "HS256", "typ": "JWT"}
    assert decoded.payload == {"sub": "user-1", "role": "user"}
    assert decoded.signature == "sig"


def test_jwt_decode_rejects_wrong_segment_count() -> None:
    with pytest.raises(JwtMalformedError):
        jwt_decode("only.two")


def test_jwt_decode_rejects_invalid_base64() -> None:
    with pytest.raises(JwtMalformedError):
        jwt_decode("not-base64!!!.also-not-base64!!!.sig")


def test_jwt_decode_rejects_non_object_json() -> None:
    header_list = base64.urlsafe_b64encode(b"[1,2,3]").rstrip(b"=").decode("ascii")
    payload = _b64url({"sub": "x"})
    with pytest.raises(JwtMalformedError):
        jwt_decode(f"{header_list}.{payload}.sig")


def test_jwt_alg_none_sets_alg_and_drops_signature() -> None:
    token = _make_token({"alg": "HS256"}, {"sub": "user-1"}, signature="real-signature")
    tampered = jwt_alg_none(token)
    assert tampered.endswith(".")  # no signature segment
    header_b64, payload_b64, sig = tampered.split(".")
    assert sig == ""
    header = json.loads(base64.urlsafe_b64decode(header_b64 + "=="))
    payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "=="))
    assert header["alg"] == "none"
    assert payload == {"sub": "user-1"}


def test_jwt_with_claim_substitutes_one_claim_and_keeps_signature() -> None:
    token = _make_token({"alg": "HS256"}, {"sub": "user-1", "role": "user"}, signature="orig-sig")
    tampered = jwt_with_claim(token, "role", "admin")
    decoded = jwt_decode(tampered)
    assert decoded.payload == {"sub": "user-1", "role": "admin"}
    assert decoded.header == {"alg": "HS256"}
    assert decoded.signature == "orig-sig"


def _make_signed_token(secret: str, *, algorithm: str = "HS256") -> str:
    hash_fn = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}[algorithm]
    header_b = _b64url({"alg": algorithm, "typ": "JWT"})
    payload_b = _b64url({"sub": "admin"})
    signing_input = f"{header_b}.{payload_b}".encode("ascii")
    sig = (
        base64.urlsafe_b64encode(hmac_module.new(secret.encode(), signing_input, hash_fn).digest())
        .rstrip(b"=")
        .decode("ascii")
    )
    return f"{header_b}.{payload_b}.{sig}"


def test_jwt_crack_secret_finds_the_matching_secret_among_candidates() -> None:
    token = _make_signed_token("vampi-secret")
    found = jwt_crack_secret(token, ["wrong1", "wrong2", "vampi-secret", "wrong3"])
    assert found == "vampi-secret"


def test_jwt_crack_secret_returns_none_when_no_candidate_matches() -> None:
    token = _make_signed_token("the-real-secret")
    assert jwt_crack_secret(token, ["a", "b", "c"]) is None


def test_jwt_crack_secret_supports_hs384_and_hs512() -> None:
    for algorithm in ("HS384", "HS512"):
        token = _make_signed_token("another-secret", algorithm=algorithm)
        found = jwt_crack_secret(token, ["wrong", "another-secret"], algorithm=algorithm)
        assert found == "another-secret"


def test_jwt_crack_secret_rejects_a_malformed_token() -> None:
    with pytest.raises(JwtMalformedError):
        jwt_crack_secret("not.a.valid.jwt", ["secret"])


def test_jwt_crack_secret_rejects_too_many_candidates() -> None:
    token = _make_signed_token("irrelevant")
    with pytest.raises(ValueError, match="too many candidates"):
        jwt_crack_secret(token, (str(i) for i in range(5001)))
