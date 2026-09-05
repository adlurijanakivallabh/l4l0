"""Tests for the availability-gated, fault-isolated recon runner chain."""

from __future__ import annotations

from dataclasses import dataclass, field

from lalo.recon import FactKind, ReconFact, run_recon_chain


@dataclass
class _FakeRunner:
    name: str
    available: bool = True
    facts: list[ReconFact] = field(default_factory=list)
    raises: Exception | None = None
    calls: int = 0

    def is_available(self) -> bool:
        return self.available

    def run(self) -> list[ReconFact]:
        self.calls += 1
        if self.raises is not None:
            raise self.raises
        return self.facts


def _fact(name: str) -> ReconFact:
    return ReconFact(kind=FactKind.ENDPOINT, url=f"https://app.example.com/{name}", source=name)


def test_facts_accumulate_from_every_available_runner() -> None:
    a = _FakeRunner("a", facts=[_fact("a1")])
    b = _FakeRunner("b", facts=[_fact("b1"), _fact("b2")])
    report = run_recon_chain([a, b])
    assert {f.url for f in report.facts} == {
        "https://app.example.com/a1",
        "https://app.example.com/b1",
        "https://app.example.com/b2",
    }
    assert report.skipped == []
    assert report.failed == []


def test_unavailable_runner_is_skipped_not_run() -> None:
    unavailable = _FakeRunner("gone", available=False, facts=[_fact("x")])
    report = run_recon_chain([unavailable])
    assert unavailable.calls == 0
    assert report.skipped == ["gone"]
    assert report.facts == []


def test_one_runners_crash_does_not_sink_the_rest_of_the_chain() -> None:
    broken = _FakeRunner("broken", raises=RuntimeError("boom"))
    healthy = _FakeRunner("healthy", facts=[_fact("ok")])
    report = run_recon_chain([broken, healthy])
    assert report.facts == [_fact("ok")]
    assert len(report.failed) == 1
    assert report.failed[0][0] == "broken"
    assert "boom" in report.failed[0][1]
