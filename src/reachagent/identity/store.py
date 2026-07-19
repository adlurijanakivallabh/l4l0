"""Identity and isolated per-identity session/token management (plan §10).

Each test identity gets its own :class:`TokenStore`; no store shares mutable
state with another, so one identity's token can never surface under another
(the cross-identity bleed §10 warns about). Credentials are loaded from the
environment or a local secrets file, never hardcoded (§10, §13).

The graph's :class:`~reachagent.graph.nodes.Session` node carries only a
``token_ref`` — a stable handle — not the token value. The value lives solely in
the owning identity's isolated store, so secrets never enter the graph.
"""

from __future__ import annotations

import os
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import TypeVar

import yaml

from reachagent.graph.nodes import AuthState, Identity, Provenance, Session

_T = TypeVar("_T")

# Env schema (§10, §13):
#   REACHAGENT_IDENTITIES="user_a,user_b,admin"
#   REACHAGENT_IDENTITY_<NAME>_USERNAME / _PASSWORD / _ROLE  (required)
#   REACHAGENT_IDENTITY_<NAME>_AUTH_STATE                    (optional)
_ENV_LIST = "REACHAGENT_IDENTITIES"
_ENV_PREFIX = "REACHAGENT_IDENTITY_"


class IdentityConfigError(RuntimeError):
    """Raised when identity credentials are missing or malformed (§10).

    Existence of this error is the enforcement of "never hardcoded": there is no
    default credential to fall back on, so a misconfigured run fails loudly
    rather than silently using a baked-in secret.
    """


class UnknownIdentityError(KeyError):
    """Raised when an operation names an identity that was never seeded."""


@dataclass(frozen=True)
class Credential:
    """A test identity's login secret (§10).

    ``password`` is excluded from ``repr`` so it is never echoed in logs, tracebacks,
    or test output (safety_guardrails).
    """

    identity: str
    username: str
    password: str = field(repr=False)
    role: str
    auth_state: AuthState = AuthState.USER

    @classmethod
    def from_mapping(cls, identity: str, data: Mapping[str, str]) -> Credential:
        """Build one credential from a name→field mapping (env or file row)."""
        try:
            username = data["username"]
            password = data["password"]
            role = data["role"]
        except KeyError as exc:
            raise IdentityConfigError(
                f"identity {identity!r} missing required field {exc.args[0]!r}"
            ) from exc
        auth_state = _auth_state_for(role, data.get("auth_state"))
        return cls(
            identity=identity,
            username=username,
            password=password,
            role=role,
            auth_state=auth_state,
        )


def _auth_state_for(role: str, explicit: str | None) -> AuthState:
    """Resolve auth state: explicit if given, else derived from role."""
    if explicit is not None:
        try:
            return AuthState(explicit)
        except ValueError as exc:
            raise IdentityConfigError(f"invalid auth_state {explicit!r}") from exc
    return AuthState.ADMIN if role.lower() == "admin" else AuthState.USER


class TokenStore:
    """Isolated token store for exactly one identity (§10).

    A distinct instance per identity with no shared backing state — the property
    that makes cross-identity token bleed impossible by construction rather than
    by discipline.
    """

    def __init__(self, identity: str) -> None:
        self._identity = identity
        self._token: str | None = None

    @property
    def identity(self) -> str:
        return self._identity

    @property
    def has_token(self) -> bool:
        return self._token is not None

    def set_token(self, token: str) -> None:
        self._token = token

    def get_token(self) -> str | None:
        return self._token

    def clear(self) -> None:
        self._token = None

    def __repr__(self) -> str:  # never echo the token value
        return f"TokenStore(identity={self._identity!r}, has_token={self.has_token})"


class IdentityStore:
    """Holds seeded and derived test identities and their isolated sessions (§10).

    Derived identities/sessions are those spawned by the Chain Solver via a
    ``derived_credential`` edge (§8); the Coordinator treats them as first-class
    and weights them heaviest in the §4 scoring rule.
    """

    def __init__(self) -> None:
        self._credentials: dict[str, Credential] = {}
        self._identities: dict[str, Identity] = {}
        self._token_stores: dict[str, TokenStore] = {}
        self._sessions: dict[str, Session] = {}

    # -- seeding -----------------------------------------------------------

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> IdentityStore:
        """Seed identities from environment variables (§10, §13 schema above)."""
        env = os.environ if environ is None else environ
        names_raw = env.get(_ENV_LIST)
        if not names_raw:
            raise IdentityConfigError(
                f"{_ENV_LIST} is unset — no identities to seed (never hardcoded, §10)"
            )
        store = cls()
        for name in (n.strip() for n in names_raw.split(",") if n.strip()):
            key = f"{_ENV_PREFIX}{name.upper()}_"
            data = {
                field_name: env[full]
                for field_name in ("username", "password", "role", "auth_state")
                if (full := f"{key}{field_name.upper()}") in env
            }
            store.add(Credential.from_mapping(name, data), provenance=Provenance.SEEDED)
        if not store._credentials:
            raise IdentityConfigError(f"{_ENV_LIST} listed no usable identities")
        return store

    @classmethod
    def from_secrets_file(cls, path: str | Path) -> IdentityStore:
        """Seed identities from a local YAML secrets file (§10, §13)."""
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        if not isinstance(raw, Mapping) or "identities" not in raw:
            raise IdentityConfigError("secrets file must have a top-level 'identities' list")
        store = cls()
        for row in raw["identities"]:
            name = row.get("name")
            if not name:
                raise IdentityConfigError("each identity entry needs a 'name'")
            store.add(Credential.from_mapping(name, row), provenance=Provenance.SEEDED)
        if not store._credentials:
            raise IdentityConfigError("secrets file listed no identities")
        return store

    def add(
        self, credential: Credential, *, provenance: Provenance = Provenance.SEEDED
    ) -> Identity:
        """Register a credential, its Identity node, and its isolated TokenStore."""
        name = credential.identity
        self._credentials[name] = credential
        identity = Identity(
            role=credential.role,
            auth_state=credential.auth_state,
            provenance=provenance,
        )
        self._identities[name] = identity
        # One dedicated store per identity — the isolation boundary (§10).
        self._token_stores[name] = TokenStore(name)
        return identity

    # -- access ------------------------------------------------------------

    def names(self) -> list[str]:
        return list(self._credentials)

    def __iter__(self) -> Iterator[str]:
        return iter(self._credentials)

    def __contains__(self, identity: str) -> bool:
        return identity in self._credentials

    def credential(self, identity: str) -> Credential:
        return self._require(self._credentials, identity)

    def identity(self, identity: str) -> Identity:
        return self._require(self._identities, identity)

    def token_store(self, identity: str) -> TokenStore:
        """Return the isolated token store for one identity (§10)."""
        return self._require(self._token_stores, identity)

    # -- sessions ----------------------------------------------------------

    def open_session(self, identity: str, token: str, *, live: bool = True) -> Session:
        """Store ``token`` in the identity's isolated store and bind a Session.

        The returned :class:`Session` carries only a ``token_ref`` — the value
        stays in the isolated store, never on the graph node (§6, §10).
        """
        store = self.token_store(identity)
        store.set_token(token)
        session = Session(
            token_ref=self._token_ref(identity),
            identity_ref=identity,
            live=live,
        )
        self._sessions[identity] = session
        return session

    def session(self, identity: str) -> Session | None:
        return self._sessions.get(identity)

    def resolve_token(self, session: Session) -> str | None:
        """Resolve a Session's ``token_ref`` back to its value via the owning store.

        A ref only ever resolves within its own identity's isolated store, so a
        Session for one identity can never yield another's token (§10).
        """
        return self.token_store(session.identity_ref).get_token()

    @staticmethod
    def _token_ref(identity: str) -> str:
        return f"token:{identity}"

    @staticmethod
    def _require(mapping: dict[str, _T], identity: str) -> _T:
        try:
            return mapping[identity]
        except KeyError as exc:
            raise UnknownIdentityError(identity) from exc
