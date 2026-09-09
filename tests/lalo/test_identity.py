"""Tests for the per-identity credential store and the role matrix."""

from __future__ import annotations

import pytest

from lalo.core.redaction import REDACTION_PLACEHOLDER, redact
from lalo.identity import (
    Credential,
    CredentialKind,
    EmailAccount,
    Identity,
    IdentityStore,
    build_role_matrix,
)


def _identity(id_: str, password: str) -> Identity:
    return Identity(id=id_, username=id_, credential=Credential(CredentialKind.PASSWORD, password))


def test_identity_store_holds_identities_independently() -> None:
    store = IdentityStore()
    store.add(_identity("alice", "alice-pass-123456"))
    store.add(_identity("bob", "bob-pass-654321"))
    assert set(store.ids()) == {"alice", "bob"}
    assert store.get("alice").username == "alice"
    assert store.get("bob").username == "bob"


def test_identity_store_rejects_duplicate_ids() -> None:
    store = IdentityStore()
    store.add(_identity("alice", "alice-pass-123456"))
    with pytest.raises(ValueError, match="alice"):
        store.add(_identity("alice", "different-pass-999"))


def test_adding_an_identity_registers_its_credential_for_universal_redaction() -> None:
    store = IdentityStore()
    store.add(_identity("alice", "SuperSecretPass123456"))
    leaked_line = "login attempt used password=SuperSecretPass123456"
    assert REDACTION_PLACEHOLDER in redact(leaked_line)
    assert "SuperSecretPass123456" not in redact(leaked_line)


def test_constructing_an_email_account_registers_its_password_for_universal_redaction() -> None:
    EmailAccount(
        address="victim@example.com",
        password="MailboxSecretPass123456",
        imap_host="imap.example.com",
    )
    leaked_line = "imap login used password=MailboxSecretPass123456"
    assert REDACTION_PLACEHOLDER in redact(leaked_line)
    assert "MailboxSecretPass123456" not in redact(leaked_line)


def test_build_role_matrix_is_the_identity_major_cartesian_product() -> None:
    matrix = build_role_matrix(["alice", "bob"], ["/a", "/b"])
    assert [(e.identity_id, e.endpoint_id) for e in matrix] == [
        ("alice", "/a"),
        ("alice", "/b"),
        ("bob", "/a"),
        ("bob", "/b"),
    ]
