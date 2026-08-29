"""Phase 5 payload context, mutation, and compatibility gates."""

from __future__ import annotations

import os
from unittest.mock import Mock, patch

import pytest

from reachagent.graph.nodes import SinkType
from reachagent.oracles import OracleMechanism
from reachagent.payloads.encoding import (
    MAX_MUTATIONS_PER_PARENT,
    MutationCompatibilityError,
    expand_payload_mutations,
    validate_mutation,
    variant_value,
)
from reachagent.payloads.library import PayloadContext, PayloadEntry, PayloadLibrary
from reachagent.recon.payload_tuning import (
    MutationRequest,
    PayloadAttemptContext,
    propose_payload_choice,
)
from reachagent.tools.payload_chain import _maybe_reorder_payloads


def _entry(
    ref: str = "sqli/error-based/quote-break",
    *,
    sink: SinkType | None = SinkType.SQL,
    oracle: OracleMechanism = OracleMechanism.DIFFERENTIAL,
    context: str = "generic",
    **metadata: str | None,
) -> PayloadEntry:
    return PayloadEntry(
        vuln_class="sqli",
        context=context,
        inferred_sink_type=sink,
        oracle_type=oracle,
        payload_ref=ref,
        graph_edge_on_success="enables",
        **metadata,
    )


def test_context_dimensions_filter_without_cross_sink_fallback() -> None:
    library = PayloadLibrary(
        [
            _entry(content_type="application/json", method="POST", location="json"),
            _entry("sqli/error-based/quote-break#html", content_type="text/html"),
        ]
    )
    result = library.get_payloads(
        "sqli",
        SinkType.SQL,
        context=PayloadContext(
            content_type="application/json; charset=utf-8",
            method="post",
            location="json",
        ),
    )
    assert [entry.payload_ref for entry in result] == ["sqli/error-based/quote-break"]
    assert library.get_payloads("sqli", SinkType.HTML_REFLECTION) == []


def test_mutations_preserve_parent_and_are_hard_capped() -> None:
    parent = _entry("sqli/error-based/quote-break")
    children = expand_payload_mutations([parent], max_per_parent=MAX_MUTATIONS_PER_PARENT)
    variants = [entry for entry in children if entry.parent_ref]
    assert 0 < len(variants) <= MAX_MUTATIONS_PER_PARENT
    assert all(entry.parent_ref == parent.payload_ref for entry in variants)
    assert all(entry.inferred_sink_type is parent.inferred_sink_type for entry in variants)
    assert all(entry.oracle_type is parent.oracle_type for entry in variants)
    assert all(variant_value(entry.payload_ref) for entry in variants)


def test_incompatible_sink_or_oracle_mutation_is_rejected() -> None:
    parent = _entry()
    bad_sink = PayloadEntry(
        **{
            **parent.__dict__,
            "payload_ref": "bad-sink",
            "parent_ref": parent.payload_ref,
            "mutation_kind": "wrapper",
            "mutation_index": 1,
            "inferred_sink_type": SinkType.HTML_REFLECTION,
        }
    )
    with pytest.raises(MutationCompatibilityError, match="sink"):
        validate_mutation(parent, bad_sink, "<script>canary</script>")

    bad_oracle = PayloadEntry(
        **{
            **parent.__dict__,
            "payload_ref": "bad-oracle",
            "parent_ref": parent.payload_ref,
            "mutation_kind": "url",
            "mutation_index": 1,
            "oracle_type": OracleMechanism.TIMING_STATISTICAL,
        }
    )
    with pytest.raises(MutationCompatibilityError, match="oracle"):
        validate_mutation(parent, bad_oracle, "%27")


def test_llm_mutation_request_is_dynamic_parent_allowlisted_and_capped() -> None:
    client = Mock()
    client.propose.return_value = {
        "payload_refs": ["sqli/error-based/quote-break"],
        "mutations": [
            {"parent_ref": "sqli/error-based/quote-break", "kind": "url"},
            {"parent_ref": "sqli/error-based/quote-break", "kind": "casing"},
        ],
    }
    choice = propose_payload_choice(
        {"sink": "sql"},
        "sqli",
        ["sqli/error-based/quote-break"],
        client=client,
    )
    assert choice.mutations == (
        MutationRequest("sqli/error-based/quote-break", "url"),
        MutationRequest("sqli/error-based/quote-break", "casing"),
    )
    assert all(item.parent_ref in {"sqli/error-based/quote-break"} for item in choice.mutations)


def test_llm_cannot_request_unknown_mutation_fields_or_parent() -> None:
    client = Mock()
    client.propose.return_value = {
        "payload_refs": ["a"],
        "mutations": [{"parent_ref": "not-a-candidate", "kind": "url"}],
    }
    choice = propose_payload_choice({"sink": "sql"}, "sqli", ["a"], client=client)
    assert choice.payload_refs == ("a",)
    assert choice.mutations == ()


def test_prior_attempt_outcome_is_forwarded_to_the_model() -> None:
    client = Mock()
    client.propose.return_value = {"payload_refs": ["a"]}
    prior = (PayloadAttemptContext("a", "waf_blocked", 403, "block page"),)
    propose_payload_choice({"sink": "sql"}, "sqli", ["a", "b"], client=client, prior_attempts=prior)
    assert client.propose.call_args.args[3] == prior


def test_requested_mutation_is_generated_only_from_the_parent_bucket() -> None:
    parent = {
        "payload_ref": "sqli/error-based/quote-break",
        "resolved_value": "'",
        "oracle_type": "differential",
        "vuln_class": "sqli",
        "inferred_sink_type": "sql",
        "graph_edge_on_success": "enables",
        "context": "generic",
    }
    choice = Mock(
        payload_refs=(parent["payload_ref"],),
        mutations=(MutationRequest(parent["payload_ref"], "url"),),
    )
    with patch.dict(os.environ, {"REACHAGENT_PAYLOAD_TUNING": "1"}, clear=False):
        with patch("reachagent.recon.payload_tuning.propose_payload_choice", return_value=choice):
            result = _maybe_reorder_payloads([parent], "sqli", "sql", None)
    child = next(item for item in result if item.get("parent_ref"))
    assert child["parent_ref"] == parent["payload_ref"]
    assert child["oracle_type"] == parent["oracle_type"]
    assert child["inferred_sink_type"] == parent["inferred_sink_type"]
