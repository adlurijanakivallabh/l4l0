"""Identity and session management (plan §10, §15 Phase 1).

Isolated session/token store per test identity; credentials never hardcoded
(environment-based or a local secrets store, §10, §13). Best results require
multiple identities across the real role hierarchy — this is a grey-box tool
(§16).
"""

from __future__ import annotations

from reachagent.identity.store import (
    Credential,
    IdentityConfigError,
    IdentityStore,
    TokenStore,
    UnknownIdentityError,
)

__all__ = [
    "Credential",
    "IdentityConfigError",
    "IdentityStore",
    "TokenStore",
    "UnknownIdentityError",
]
