"""Explorer data records — fingerprint reports, raw signals, and candidates (§9, §13).

These types are deliberately *not* defined in ``explorer.py``. The role-boundary
invariant (``tests/phase1/test_tool_boundaries.py``) asserts the Explorer module
exposes exactly its four tool names among non-underscore callables, so any
dataclass or exception defined there would leak into the tool surface and break
it. Keeping the records here lets ``explorer.py`` import this as a *module*
(modules aren't callable, so they don't count as tools) and stay a clean
four-tool manifest.

The load-bearing type is :class:`Candidate`: the Explorer's terminal output. A
candidate is *inert* — it records what was observed and which oracle should judge
it, but it carries no verdict and has no method that writes a finding. Only the
Validator's ``run_oracle`` can turn the evidence a candidate points at into a
``confirmed`` result (§7, §13).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from reachagent.graph.nodes import SinkType
from reachagent.oracles import OracleMechanism


@dataclass(frozen=True)
class FingerprintReport:
    """What the benign canary revealed about a parameter's sink (§9 step 1).

    Produced by ``fingerprint_parameter`` before any attack payload fires. The
    ``inferred_sink_type`` here is also written onto the ``Parameter`` graph node
    so downstream ``get_payloads``/``fire_request`` can route by it.
    """

    endpoint_node: str
    param_node: str
    inferred_sink_type: SinkType | None
    reflected: bool
    error_signature: str | None
    observed_content_type: str | None


@dataclass(frozen=True)
class ResponseSignal:
    """Raw, non-judgmental signal extracted from one response (§9 step, §13).

    Just the measurable facts — status, body length, timing, matched error
    strings. No interpretation; ``classify_response`` bundles these into a
    candidate, and only the Validator's oracle interprets them.
    """

    status_code: int
    body_length: int
    elapsed_seconds: float
    error_strings: tuple[str, ...] = ()


@dataclass(frozen=True)
class Candidate:
    """The Explorer's terminal output — an inert lead for the Validator (§13).

    A candidate names the target, the payload that produced it, the raw signal,
    and *which* oracle family should judge it — but it is not a finding and
    cannot become one on its own. There is intentionally no ``confirm()`` or
    ``write_finding`` path on this type: the one-way gate from §7/§13 is that only
    a ``confirmed`` ``run_oracle`` verdict, run by the Validator, unlocks a
    ``Finding``. This record is the handoff, nothing more.
    """

    identity: str
    endpoint_node: str
    param_node: str | None
    vuln_class: str
    suggested_oracle: OracleMechanism
    payload_ref: str | None
    signal: ResponseSignal
    # Free-form provenance notes (secret-free), e.g. "WAF block observed".
    notes: tuple[str, ...] = field(default_factory=tuple)
