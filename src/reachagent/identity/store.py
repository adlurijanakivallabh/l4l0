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
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TypeVar

import yaml

from reachagent.graph.nodes import AuthState, Identity, Provenance, Session

_T = TypeVar("_T")
_DEFAULT_TOKEN_SCHEME = "Bearer"  # noqa: S105 - HTTP auth scheme, not a credential

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
class SessionMaterial:
    """Private authentication material held by one identity's token store.

    The object is deliberately safe to represent: its ``repr`` never contains
    token, cookie, or refresh values.  Runtime callers use ``TokenStore`` to
    obtain request headers; graph, audit, and model-facing code only receives a
    session reference and the non-sensitive expiry/kind metadata.
    """

    kind: str = "bearer"
    token: str | None = field(default=None, repr=False)
    cookies: tuple[tuple[str, str], ...] = field(default=(), repr=False)
    expires_at: datetime | None = None
    refresh_token: str | None = field(default=None, repr=False)
    refresh_url: str | None = None
    token_type: str = _DEFAULT_TOKEN_SCHEME

    def __post_init__(self) -> None:
        if self.kind not in {"bearer", "cookie", "mixed"}:
            raise ValueError("session kind must be bearer, cookie, or mixed")
        object.__setattr__(
            self, "cookies", tuple(sorted((str(k), str(v)) for k, v in self.cookies))
        )

    @property
    def expired(self) -> bool:
        return self.expires_at is not None and self.expires_at <= datetime.now(UTC)

    def headers(self) -> dict[str, str]:
        """Build headers for the owning identity without mutating shared state."""
        out: dict[str, str] = {}
        if self.token:
            scheme = self.token_type.strip() or "Bearer"
            out["Authorization"] = f"{scheme} {self.token}"
        if self.cookies:
            out["Cookie"] = "; ".join(f"{name}={value}" for name, value in self.cookies)
        return out

    def safe_dict(self) -> dict[str, object]:
        """Non-secret metadata suitable for graph/audit/UI state."""
        return {
            "kind": self.kind,
            "has_token": bool(self.token),
            "cookie_names": [name for name, _ in self.cookies],
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "has_refresh": bool(self.refresh_token),
        }


RefreshCallback = Callable[[str], SessionMaterial | None]


def _coerce_expiry(value: datetime | str | None) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo is not None else value.replace(tzinfo=UTC)
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


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
        self._material: SessionMaterial | None = None
        self._refresh_callback: RefreshCallback | None = None

    @property
    def identity(self) -> str:
        return self._identity

    @property
    def has_token(self) -> bool:
        material = self._material
        return material is not None and bool(material.token or material.cookies)

    def set_token(
        self,
        token: str,
        *,
        kind: str = "bearer",
        expires_at: datetime | str | None = None,
        refresh_token: str | None = None,
        refresh_url: str | None = None,
        token_type: str = _DEFAULT_TOKEN_SCHEME,
    ) -> None:
        """Store one bearer/cookie token while retaining the old convenience API."""
        self.set_material(
            SessionMaterial(
                kind=kind,
                token=token if kind in {"bearer", "mixed"} else None,
                expires_at=_coerce_expiry(expires_at),
                refresh_token=refresh_token,
                refresh_url=refresh_url,
                token_type=token_type,
            )
        )

    def set_material(self, material: SessionMaterial) -> None:
        """Replace this identity's complete private session material."""
        self._material = material

    def merge_cookies(self, cookies: Mapping[str, str]) -> None:
        """Merge browser cookies into this identity without dropping a bearer token."""
        current = self._material
        if current is None:
            self._material = SessionMaterial(kind="cookie", cookies=tuple(cookies.items()))
            return
        merged = dict(current.cookies)
        merged.update({str(k): str(v) for k, v in cookies.items()})
        kind = "mixed" if current.token else "cookie"
        self._material = SessionMaterial(
            kind=kind,
            token=current.token,
            cookies=tuple(merged.items()),
            expires_at=current.expires_at,
            refresh_token=current.refresh_token,
            refresh_url=current.refresh_url,
            token_type=current.token_type,
        )

    def set_refresh_callback(self, callback: RefreshCallback | None) -> None:
        """Install an in-memory refresh function; never persist the callback."""
        self._refresh_callback = callback

    def get_token(self) -> str | None:
        material = self._live_material()
        return material.token if material is not None else None

    def get_material(self) -> SessionMaterial | None:
        """Return private material for runtime callers (never graph/UI callers)."""
        return self._live_material()

    def headers(self) -> dict[str, str]:
        material = self._live_material()
        return material.headers() if material is not None else {}

    @property
    def expires_at(self) -> datetime | None:
        return self._material.expires_at if self._material is not None else None

    @property
    def kind(self) -> str | None:
        return self._material.kind if self._material is not None else None

    def refresh_if_needed(self) -> bool:
        """Refresh expired bearer material when a callback was supplied.

        A missing/failed callback fails closed by clearing the material.  This
        prevents an expired token from silently being reused on later requests.
        """
        material = self._material
        if material is None or not material.expired:
            return bool(material)
        if not material.refresh_token or self._refresh_callback is None:
            self.clear()
            return False
        try:
            refreshed = self._refresh_callback(material.refresh_token)
        except Exception:  # noqa: BLE001 - refresh failure is a closed session
            refreshed = None
        if refreshed is None:
            self.clear()
            return False
        self.set_material(refreshed)
        return True

    def _live_material(self) -> SessionMaterial | None:
        if self._material is None:
            return None
        if self._material.expired and not self.refresh_if_needed():
            return None
        return self._material

    def clear(self) -> None:
        self._material = None
        self._refresh_callback = None

    def safe_summary(self) -> dict[str, object]:
        material = self._material
        return (
            material.safe_dict()
            if material is not None
            else {
                "kind": None,
                "has_token": False,
                "cookie_names": [],
                "expires_at": None,
                "has_refresh": False,
            }
        )

    def redact(self, value: str) -> str:
        """Replace this identity's private material in a model-facing string."""
        text = str(value)
        material = self._material
        if material is None:
            return text
        for secret in (material.token, material.refresh_token, *(v for _, v in material.cookies)):
            if secret:
                text = text.replace(secret, "<redacted>")
        return text

    def __repr__(self) -> str:  # never echo the token value
        kind = self._material.kind if self._material is not None else None
        return f"TokenStore(identity={self._identity!r}, has_token={self.has_token}, kind={kind!r})"


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

    def open_session(
        self,
        identity: str,
        token: str = "",
        *,
        kind: str = "bearer",
        cookies: Mapping[str, str] | None = None,
        expires_at: datetime | str | None = None,
        refresh_token: str | None = None,
        refresh_url: str | None = None,
        token_type: str = _DEFAULT_TOKEN_SCHEME,
        refresh_callback: RefreshCallback | None = None,
        live: bool = True,
    ) -> Session:
        """Store private session material and bind a secret-free graph Session.

        The returned :class:`Session` carries only a ``token_ref`` — the value
        stays in the isolated store, never on the graph node (§6, §10).
        """
        store = self.token_store(identity)
        material = SessionMaterial(
            kind=kind,
            token=token or None if kind in {"bearer", "mixed"} else None,
            cookies=tuple((str(k), str(v)) for k, v in (cookies or {}).items()),
            expires_at=_coerce_expiry(expires_at),
            refresh_token=refresh_token,
            refresh_url=refresh_url,
            token_type=token_type,
        )
        store.set_material(material)
        store.set_refresh_callback(refresh_callback)
        session = Session(
            token_ref=self._token_ref(identity),
            identity_ref=identity,
            auth_kind=material.kind,
            expires_at=material.expires_at.isoformat() if material.expires_at else None,
            live=live,
        )
        self._sessions[identity] = session
        return session

    def ensure_session(self, identity: str, *, live: bool = True) -> Session | None:
        """Create a graph-safe Session for already-captured private material."""
        existing = self._sessions.get(identity)
        if existing is not None:
            return existing
        material = self.token_store(identity).get_material()
        if material is None:
            return None
        session = Session(
            token_ref=self._token_ref(identity),
            identity_ref=identity,
            auth_kind=material.kind,
            expires_at=material.expires_at.isoformat() if material.expires_at else None,
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

    def auth_headers(self, identity: str) -> dict[str, str]:
        """Return the selected identity's live headers for a runtime request."""
        store = self.token_store(identity)
        headers = store.headers()
        session = self._sessions.get(identity)
        if session is not None:
            session.live = bool(headers)
            material = store.get_material()
            if material is not None:
                session.auth_kind = material.kind
                session.expires_at = (
                    material.expires_at.isoformat() if material.expires_at else None
                )
        return headers

    def redact(self, identity: str, value: str) -> str:
        """Redact private material for one identity from a model-facing value."""
        return self.token_store(identity).redact(value)

    @staticmethod
    def _token_ref(identity: str) -> str:
        return f"token:{identity}"

    @staticmethod
    def _require(mapping: dict[str, _T], identity: str) -> _T:
        try:
            return mapping[identity]
        except KeyError as exc:
            raise UnknownIdentityError(identity) from exc
