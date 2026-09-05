"""Per-identity credential store with graph-mirrored sessions."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..graph.store import ReachGraph


@dataclass
class SessionMaterial:
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)

    def is_usable(self) -> bool:
        return bool(self.headers or self.cookies)

    def cookie_header(self) -> str:
        return "; ".join(f"{k}={v}" for k, v in self.cookies.items())


class TokenStore:
    """Holds one identity's auth material. No shared state between identities."""

    def __init__(self, name: str, role: str | None = None) -> None:
        self.name = name
        self.role = role
        self._material = SessionMaterial()

    @property
    def material(self) -> SessionMaterial:
        return self._material

    def _set(self, material: SessionMaterial) -> None:
        # private: usable material may only be set via IdentityStore.ensure_session,
        # which mirrors the session onto the graph.
        self._material = material

    def apply(self, headers: dict[str, str] | None = None) -> dict[str, str]:
        merged = dict(headers or {})
        merged.update(self._material.headers)
        if self._material.cookies:
            merged["Cookie"] = self._material.cookie_header()
        return merged


class IdentityStore:
    """Manages identities and guarantees session -> graph mirroring."""

    def __init__(self, graph: ReachGraph) -> None:
        self._graph = graph
        self._stores: dict[str, TokenStore] = {}

    def register(self, name: str, role: str | None = None) -> TokenStore:
        store = TokenStore(name, role)
        self._stores[name] = store
        self._graph.add_identity(name, role)
        return store

    def ensure_session(
        self, name: str, material: SessionMaterial, *, label: str = "primary"
    ) -> SessionMaterial:
        """Set an identity's usable material AND mirror the session onto the graph.

        This is the ONLY path that installs usable session material, so no code
        path can hold a usable session without a corresponding graph session node.
        """
        store = self._stores.get(name) or self.register(name)
        store._set(material)
        self._graph.add_session(name, label)
        return material

    def store(self, name: str) -> TokenStore | None:
        return self._stores.get(name)

    def identities(self) -> list[str]:
        return list(self._stores)
