"""Tests for the pure RFC 6238 TOTP helper, verified against the RFC's own
published (SHA1, 8-digit) test vectors -- Appendix B."""

from __future__ import annotations

import base64

import pytest

from lalo.core.errors import TotpSecretError
from lalo.identity.totp import generate_totp

# The RFC's own 20-byte ASCII seed, base32-encoded the way a real secret
# (from an enrollment QR code) would be distributed.
_RFC_SECRET_B32 = base64.b32encode(b"12345678901234567890").decode("ascii")


@pytest.mark.parametrize(
    ("unix_time", "expected"),
    [
        (59, "94287082"),
        (1111111109, "07081804"),
        (1111111111, "14050471"),
        (1234567890, "89005924"),
        (2000000000, "69279037"),
    ],
)
def test_generate_totp_matches_the_rfc_6238_test_vectors(unix_time: int, expected: str) -> None:
    assert generate_totp(_RFC_SECRET_B32, digits=8, now=float(unix_time)) == expected


def test_generate_totp_defaults_to_six_digits() -> None:
    code = generate_totp(_RFC_SECRET_B32, now=59.0)
    assert len(code) == 6
    # the same 8-digit RFC vector's last 6 digits, since dynamic truncation
    # and the modulus are computed identically, just against a smaller mod.
    assert code == "94287082"[-6:]


def test_generate_totp_is_stable_within_the_same_time_step() -> None:
    # Window 33 spans [990, 1020); window 34 starts at 1020.
    a = generate_totp(_RFC_SECRET_B32, now=990.0)
    b = generate_totp(_RFC_SECRET_B32, now=1019.0)
    c = generate_totp(_RFC_SECRET_B32, now=1020.0)
    assert a == b
    assert a != c


def test_generate_totp_tolerates_missing_padding() -> None:
    # The RFC's own 20-byte seed encodes to exactly 32 base32 chars with no
    # padding at all (20 is a multiple of 5) -- pick a length that actually
    # needs padding to exercise the restore-padding path at all.
    padded_secret = base64.b32encode(b"a secret of odd length").decode("ascii")
    assert padded_secret.endswith("=")  # sanity: this length really does need padding
    unpadded_secret = padded_secret.rstrip("=")
    assert generate_totp(unpadded_secret, now=59.0) == generate_totp(padded_secret, now=59.0)


def test_generate_totp_rejects_invalid_base32() -> None:
    with pytest.raises(TotpSecretError):
        generate_totp("not-valid-base32!!!", now=59.0)
