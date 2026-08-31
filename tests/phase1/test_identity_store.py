"""Identity/session management (plan §10; docs/phase1-tasks.md Task 2).

Asserts the DoD invariants:
  1. ≥2 VAmPI identities across the role hierarchy seed from env / local secrets
     store — never hardcoded (a missing config fails loudly, no baked-in default);
  2. each identity has an isolated token store with no cross-identity bleed.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from reachagent.graph.nodes import AuthState, Provenance
from reachagent.identity import (
    Credential,
    IdentityConfigError,
    IdentityStore,
)

# A VAmPI-shaped env: two peer users + an admin, spanning the role hierarchy.
VAMPI_ENV = {
    "REACHAGENT_IDENTITIES": "user_a,user_b,admin",
    "REACHAGENT_IDENTITY_USER_A_USERNAME": "alice",
    "REACHAGENT_IDENTITY_USER_A_PASSWORD": "alice-secret",
    "REACHAGENT_IDENTITY_USER_A_ROLE": "user",
    "REACHAGENT_IDENTITY_USER_B_USERNAME": "bob",
    "REACHAGENT_IDENTITY_USER_B_PASSWORD": "bob-secret",
    "REACHAGENT_IDENTITY_USER_B_ROLE": "user",
    "REACHAGENT_IDENTITY_ADMIN_USERNAME": "root",
    "REACHAGENT_IDENTITY_ADMIN_PASSWORD": "root-secret",
    "REACHAGENT_IDENTITY_ADMIN_ROLE": "admin",
}


@pytest.fixture
def store() -> IdentityStore:
    return IdentityStore.from_env(VAMPI_ENV)


def test_seeds_at_least_two_identities_across_role_hierarchy(store: IdentityStore) -> None:
    assert set(store.names()) == {"user_a", "user_b", "admin"}
    assert len(store.names()) >= 2
    # Role hierarchy is represented: regular users and an admin.
    assert store.identity("user_a").auth_state is AuthState.USER
    assert store.identity("admin").auth_state is AuthState.ADMIN
    # Seeded identities are marked as such (not derived by the Chain Solver).
    assert all(store.identity(n).provenance is Provenance.SEEDED for n in store)


def test_never_hardcoded_missing_env_fails_loudly() -> None:
    # No identity list in the environment => hard error, never a default secret.
    with pytest.raises(IdentityConfigError):
        IdentityStore.from_env({})


def test_missing_required_field_fails_loudly() -> None:
    partial = {
        "REACHAGENT_IDENTITIES": "user_a",
        "REACHAGENT_IDENTITY_USER_A_USERNAME": "alice",
        # no password, no role
    }
    with pytest.raises(IdentityConfigError):
        IdentityStore.from_env(partial)


def test_no_cross_identity_token_bleed(store: IdentityStore) -> None:
    # Each identity opens its own session with its own token.
    store.open_session("user_a", "token-A")
    store.open_session("user_b", "token-B")
    store.open_session("admin", "token-ADMIN")

    # Each isolated store holds only its own token.
    assert store.token_store("user_a").get_token() == "token-A"
    assert store.token_store("user_b").get_token() == "token-B"
    assert store.token_store("admin").get_token() == "token-ADMIN"

    # The stores are distinct objects — no shared backing state.
    stores = [store.token_store(n) for n in ("user_a", "user_b", "admin")]
    assert len({id(s) for s in stores}) == 3

    # Rotating one identity's token leaves the others untouched.
    store.token_store("user_a").set_token("token-A2")
    assert store.token_store("user_b").get_token() == "token-B"
    assert store.token_store("admin").get_token() == "token-ADMIN"

    # Clearing one identity does not clear any other.
    store.token_store("user_a").clear()
    assert not store.token_store("user_a").has_token
    assert store.token_store("user_b").has_token
    assert store.token_store("admin").has_token


def test_session_ref_resolves_only_within_owning_identity(store: IdentityStore) -> None:
    session_a = store.open_session("user_a", "token-A")
    session_b = store.open_session("user_b", "token-B")

    # A Session carries a ref, not the secret itself (§6, §10).
    assert "token-A" not in session_a.token_ref
    assert session_a.identity_ref == "user_a"

    # A ref resolves to its own identity's token, never another's.
    assert store.resolve_token(session_a) == "token-A"
    assert store.resolve_token(session_b) == "token-B"


def test_credential_password_never_in_repr() -> None:
    cred = Credential(
        identity="user_a",
        username="alice",
        password="super-secret",
        role="user",
    )
    assert "super-secret" not in repr(cred)


def test_token_store_repr_excludes_token_value() -> None:
    ts = IdentityStore.from_env(VAMPI_ENV).token_store("user_a")
    ts.set_token("super-secret-token")
    assert "super-secret-token" not in repr(ts)


def test_seeds_from_local_secrets_file(tmp_path: Path) -> None:
    secrets = tmp_path / "identities.yaml"
    secrets.write_text(
        "identities:\n"
        "  - name: user_a\n"
        "    username: alice\n"
        "    password: alice-secret\n"
        "    role: user\n"
        "  - name: admin\n"
        "    username: root\n"
        "    password: root-secret\n"
        "    role: admin\n",
        encoding="utf-8",
    )
    store = IdentityStore.from_secrets_file(secrets)
    assert set(store.names()) == {"user_a", "admin"}
    assert store.identity("admin").auth_state is AuthState.ADMIN
    assert store.credential("user_a").username == "alice"


def test_seeds_from_inline_identities_list() -> None:
    store = IdentityStore.from_identities_list(
        [{"username": "alice", "password": "alice-secret", "role": "admin"}]
    )
    assert store.names() == ["alice"]
    assert store.identity("alice").auth_state is AuthState.ADMIN
    assert store.credential("alice").password == "alice-secret"


def test_inline_identities_role_defaults_to_user() -> None:
    store = IdentityStore.from_identities_list([{"username": "bob", "password": "x"}])
    assert store.identity("bob").auth_state is AuthState.USER


def test_inline_identities_empty_list_raises() -> None:
    with pytest.raises(IdentityConfigError):
        IdentityStore.from_identities_list([])
