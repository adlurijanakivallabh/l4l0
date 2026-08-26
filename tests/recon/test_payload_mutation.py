"""Payload selection + encoding-variant expansion - hermetic tests.

Covers: expand_encoding_variants wiring into get_payloads, variant ref
resolution, and the failure-context-aware payload ranking.
"""

from __future__ import annotations

from reachagent.graph.nodes import SinkType
from reachagent.oracles import OracleMechanism
from reachagent.payloads.encoding import (
    expand_encoding_variants,
)
from reachagent.payloads.library import PayloadEntry

_TARGET = "target.test"


def _entry(
    ref: str, vuln_class: str = "sqli", sink: SinkType | None = SinkType.SQL
) -> PayloadEntry:
    return PayloadEntry(
        vuln_class=vuln_class,
        context="test",
        inferred_sink_type=sink,
        oracle_type=OracleMechanism.DIFFERENTIAL,
        payload_ref=ref,
        graph_edge_on_success="enables",
    )


class TestExpandEncodingVariants:
    """The encoding-variant expansion (previously dead code, now wired)."""

    def test_expands_url_encoded_variant(self) -> None:
        """A sqli entry with a resolvable template gets a url-encoded variant."""
        entries = [_entry("sqli/error-based/quote-break")]
        expanded = expand_encoding_variants(entries)
        # Original + url variant = at least 2
        assert len(expanded) >= 2
        refs = [e.payload_ref for e in expanded]
        assert any("#url" in r for r in refs)

    def test_does_not_expand_non_variant_class(self) -> None:
        """Classes outside _VARIANT_CLASSES get no variants."""
        entries = [_entry("bola/object-id-substitution", vuln_class="bola", sink=None)]
        expanded = expand_encoding_variants(entries)
        assert len(expanded) == 1  # no expansion for bola

    def test_variant_resolves_to_fireable_value(self) -> None:
        """The variant ref resolves via the cache to the encoded value."""
        from reachagent.payloads.payload_resolver import resolve

        entries = [_entry("sqli/error-based/quote-break")]
        expanded = expand_encoding_variants(entries)
        variant_refs = [e.payload_ref for e in expanded if "#url" in e.payload_ref]
        if variant_refs:
            val = resolve(variant_refs[0])
            assert val != "'"  # should be URL-encoded
            assert "%" in val or val == "%27"


class TestPayloadAttemptContext:
    """The failure-context dataclass for mutation reasoning."""

    def test_context_creation(self) -> None:
        from reachagent.recon.payload_tuning import PayloadAttemptContext

        ctx = PayloadAttemptContext(
            tried_ref="sqli/error-based/quote-break",
            outcome="no_reflection",
            status_code=200,
            detail="payload reflected verbatim, no SQL error",
        )
        assert ctx.outcome == "no_reflection"
        assert ctx.status_code == 200
