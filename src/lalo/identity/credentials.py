"""Per-identity credential store — no shared state between identities.

Reference reads for this phase confirmed the gap this closes by contrast: a
reference API-testing skill's own worked example (`SKILL.md`, read in full)
authenticates two tenants by embedding raw tokens directly in the mission
instruction string (``"Tenant A token: <tokenA> ... Tenant B token:
<tokenB>..."``); a reference exploitation prompt (`exploit-auth.txt`, 347
lines, read in full) shows its attack-pattern examples doing the same —
`curl -X POST -d '{"password":"CrackedPassword123"}'`, a raw literal the
model itself composed. Both hand the LLM the actual secret as plain text in
its own context window, with no isolated store standing between "credential
exists" and "credential is in the model's token stream." A companion prompt
fragment from the second reference (`_credentials-in-findings.txt`, read in
full) does the opposite for *submitted findings* — the model writes literal
``$username``/``$password`` placeholders in place of the values it was
configured with, and per that file's own text ("nothing expands them
afterwards") they stay placeholders permanently, precisely so the real
credentials never appear anywhere in the deliverable at all, not even for a
human to fill in later.

This module generalizes that placeholder idea to the point of use, not just
the point of reporting: every :class:`Identity` registers its own credential
with L4L0's shared redactor the moment it is created (see
:mod:`lalo.core.redaction`, Phase 0), so any place a raw secret ends up in a
log line or captured observation gets scrubbed universally — and the
identity/login layer is designed so tools address an identity by its
symbolic id, never by asking the agent to type the secret itself.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from ..core.redaction import shared_redactor


class CredentialKind(StrEnum):
    PASSWORD = "password"  # noqa: S105 - an enum tag naming a kind, not a literal secret
    BEARER_TOKEN = "bearer_token"  # noqa: S105 - same
    API_KEY = "api_key"
    COOKIE = "cookie"


@dataclass(frozen=True)
class Credential:
    kind: CredentialKind
    value: str


@dataclass(frozen=True)
class Identity:
    id: str
    username: str
    credential: Credential


@dataclass(frozen=True)
class EmailAccount:
    """An IMAP mailbox an agent can read to complete a target's magic-link/OTP
    login flow.

    Deliberately NOT a `Credential`/`CredentialKind` pairing threaded through
    `Identity`: nothing here authenticates to the engagement target itself
    (it authenticates to a mailbox), so folding it into the target-login
    credential model would blur two genuinely different secrets under one
    shape. Kept on its own map (`ScanConfig.email_accounts`, the same
    independent-map convention `identities`/`login_schemes` already use) and
    consumed only by :func:`~lalo.identity.email_tool.build_email_fetch_tool`.

    Only `password` is registered with the shared redactor -- matching
    `Identity`/`Credential`'s own precedent of registering the secret value
    but never the identifying label next to it (`identity.username` is never
    registered either). `address` is this account's username-equivalent and
    `imap_host`/`imap_port` are connection parameters, not secrets.
    """

    address: str
    password: str  # noqa: S105 - a dataclass field name, not a literal secret
    imap_host: str
    imap_port: int = 993

    def __post_init__(self) -> None:
        # Registered at construction -- the same guarantee IdentityStore.add()
        # gives Credential.value, applied here since this shape has no
        # equivalent "add to a store" call of its own to hang the
        # registration off of.
        shared_redactor().register_secret(self.password)


class IdentityStore:
    """Holds each identity independently — no global "current user" state."""

    def __init__(self) -> None:
        self._identities: dict[str, Identity] = {}

    def add(self, identity: Identity) -> None:
        if identity.id in self._identities:
            raise ValueError(f"identity id already registered: {identity.id}")
        self._identities[identity.id] = identity
        shared_redactor().register_secret(identity.credential.value)

    def get(self, identity_id: str) -> Identity:
        return self._identities[identity_id]

    def ids(self) -> list[str]:
        return list(self._identities)
