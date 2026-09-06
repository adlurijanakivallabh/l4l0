"""RFC 6238 TOTP generation — a pure, zero-I/O helper, mirroring
:mod:`lalo.identity.jwt_tools`'s own shape: these are decode/generate
primitives only, never a detector, and never a place that decides anything
is vulnerable. Closes a real, narrow gap this project otherwise had no
equivalent of at all — a target's login flow requiring a second factor had
no way to be automated through :func:`~lalo.identity.login.login`, unlike
every other credential shape :class:`~lalo.identity.login.LoginScheme`
already covers.

Deliberately stdlib-only (``hmac``/``hashlib``/``struct``/``base64``): the
algorithm is nine lines once the RFC is read, and pulling in a dependency
(e.g. ``pyotp``) for that would be exactly the kind of avoidable addition
this project's own conventions argue against.
"""

from __future__ import annotations

import base64
import binascii
import hmac
import struct
import time

from ..core.errors import TotpSecretError

_DEFAULT_DIGITS = 6
_DEFAULT_TIME_STEP_S = 30
_DEFAULT_DIGEST = "sha1"


def generate_totp(
    secret_base32: str,
    *,
    digits: int = _DEFAULT_DIGITS,
    time_step: int = _DEFAULT_TIME_STEP_S,
    digest: str = _DEFAULT_DIGEST,
    now: float | None = None,
) -> str:
    """The current RFC 6238 TOTP code for ``secret_base32``.

    ``now`` defaults to the real wall-clock time; pass an explicit value for
    reproducible tests. Padding on ``secret_base32`` is restored if missing
    (a secret copied from a real enrollment QR code routinely omits the
    trailing ``=`` characters) rather than rejecting an otherwise-valid
    secret over a formatting nicety.
    """
    padded = secret_base32.strip().upper()
    padded += "=" * (-len(padded) % 8)
    try:
        key = base64.b32decode(padded)
    except (binascii.Error, ValueError) as exc:
        raise TotpSecretError(f"invalid base32 TOTP secret: {exc}") from exc
    effective_now = now if now is not None else time.time()
    counter = int(effective_now // time_step)
    counter_bytes = struct.pack(">Q", counter)
    mac = hmac.new(key, counter_bytes, digest).digest()
    offset = mac[-1] & 0x0F
    truncated = struct.unpack(">I", mac[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(truncated % (10**digits)).zfill(digits)
