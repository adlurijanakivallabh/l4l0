"""Consolidated Phase 7 gate runner — hermetic composite logic (stub gates, no live target)."""

from __future__ import annotations

import inspect

from reachagent.eval.consolidated import (
    ConsolidatedGateResult,
    GateSpec,
    GateStatus,
    _as_outcome,
    run_consolidated,
)


def _stub(name: str, status: GateStatus, *, ready: bool = True) -> GateSpec:
    return GateSpec(
        name=name,
        env_doc=f"enable {name}",
        env_ready=lambda: ready,
        run=lambda: _as_outcome(status, detail=f"detail-{name}", report=f"report-{name}"),
    )


def _stubs() -> tuple[GateSpec, ...]:
    return (
        _stub("alpha", GateStatus.PASSED),
        _stub("beta", GateStatus.PASSED),
        _stub("gamma", GateStatus.PASSED),
    )


# -- Composite semantics ---------------------------------------------------------


def test_all_pass_composite_passed_exit_zero() -> None:
    result = run_consolidated(gates=_stubs())
    assert result.composite is GateStatus.PASSED
    assert result.exit_code == 0


def test_any_fail_composite_failed_exit_one() -> None:
    gates = (_stub("a", GateStatus.PASSED), _stub("b", GateStatus.FAILED))
    result = run_consolidated(gates=gates)
    assert result.composite is GateStatus.FAILED
    assert result.exit_code == 1


def test_any_not_measurable_composite_not_measurable_exit_two() -> None:
    gates = (_stub("a", GateStatus.PASSED), _stub("b", GateStatus.NOT_MEASURABLE))
    result = run_consolidated(gates=gates)
    assert result.composite is GateStatus.NOT_MEASURABLE
    assert result.exit_code == 2


def test_skipped_never_blocks_composite() -> None:
    gates = (_stub("a", GateStatus.PASSED), _stub("s", GateStatus.SKIPPED, ready=False))
    result = run_consolidated(gates=gates)
    assert result.composite is GateStatus.PASSED
    assert result.exit_code == 0


def test_all_skipped_is_not_measurable() -> None:
    gates = (
        _stub("s1", GateStatus.SKIPPED, ready=False),
        _stub("s2", GateStatus.SKIPPED, ready=False),
    )
    result = run_consolidated(gates=gates)
    assert result.composite is GateStatus.NOT_MEASURABLE  # nothing ran
    assert result.exit_code == 2


# -- Env gating ----------------------------------------------------------------


def test_unprovisioned_gate_is_skipped_with_reason() -> None:
    gates = (_stub("off", GateStatus.SKIPPED, ready=False), _stub("on", GateStatus.PASSED))
    result = run_consolidated(gates=gates)
    assert result.per_target["off"]["status"] == "skipped"
    assert "enable off" in result.per_target["off"]["detail"]
    # Skipped gate is absent from the composite judgment (only on ran).
    assert result.composite is GateStatus.PASSED


def test_run_error_maps_to_not_measurable() -> None:
    def boom() -> None:
        raise RuntimeError("provisioned but run exploded")

    gates = (GateSpec(name="x", env_doc="env x", env_ready=lambda: True, run=boom),)
    result = run_consolidated(gates=gates)
    assert result.per_target["x"]["status"] == "not_measurable"
    assert "run error: RuntimeError" in result.per_target["x"]["detail"]
    assert result.composite is GateStatus.NOT_MEASURABLE


# -- Subset filter ---------------------------------------------------------------


def test_subset_runs_only_named_gates() -> None:
    gates = (_stub("a", GateStatus.PASSED), _stub("b", GateStatus.FAILED))
    result = run_consolidated(targets=["a"], gates=gates)
    assert set(result.per_target) == {"a"}


# -- Report ----------------------------------------------------------------------


def test_report_contains_per_target_sections_and_composite() -> None:
    gates = (_stub("alpha", GateStatus.PASSED), _stub("beta", GateStatus.SKIPPED, ready=False))
    result = run_consolidated(gates=gates)
    text = result.report()
    assert "[alpha] passed" in text
    assert "[beta] skipped" in text
    assert "enable beta" in text
    assert "report-alpha" in text
    assert "composite: passed (exit 0)" in text


def test_report_deterministic() -> None:
    gates = (_stub("a", GateStatus.PASSED), _stub("b", GateStatus.FAILED))
    assert run_consolidated(gates=gates).report() == run_consolidated(gates=gates).report()


# -- __main__ exit codes ---------------------------------------------------------


def test_main_returns_composite_exit_code(monkeypatch) -> None:  # noqa: ANN001
    import reachagent.eval.__main__ as entry

    def fake_run(targets: list[str] | None) -> ConsolidatedGateResult:
        assert targets == ["portswigger"]
        return ConsolidatedGateResult(
            per_target={"portswigger": _as_outcome(GateStatus.PASSED, detail="d")}
        )

    monkeypatch.setattr(entry, "run_consolidated", fake_run)
    assert entry.main(["--target", "portswigger"]) == 0

    def fake_fail(targets: list[str] | None) -> ConsolidatedGateResult:  # noqa: ARG001
        return ConsolidatedGateResult(
            per_target={"vamp": _as_outcome(GateStatus.FAILED, detail="d")}
        )

    monkeypatch.setattr(entry, "run_consolidated", fake_fail)
    assert entry.main([]) == 1


def test_main_returns_not_measurable_exit_two(monkeypatch) -> None:  # noqa: ANN001
    import reachagent.eval.__main__ as entry

    monkeypatch.setattr(
        entry,
        "run_consolidated",
        lambda targets=None: ConsolidatedGateResult(
            per_target={"vamp": _as_outcome(GateStatus.NOT_MEASURABLE, detail="d")}
        ),
    )
    assert entry.main([]) == 2


# -- No changes to existing harnesses ---------------------------------------------


def test_existing_gate_harnesses_import_and_signatures_unchanged() -> None:
    from reachagent.bola.detector import detect
    from reachagent.eval.harness import evaluate
    from reachagent.eval.juiceshop_ephemeral import run_ephemeral_gate
    from reachagent.eval.portswigger_blind_sqli import build_configured_runner
    from reachagent.graphql.module import discover_schema, resolver_bola_check
    from reachagent.recon.crapi_recon import run_recon

    assert "on_base_url" in inspect.signature(evaluate).parameters
    assert "off_base_url" in inspect.signature(evaluate).parameters
    assert "config" in inspect.signature(run_ephemeral_gate).parameters
    assert "oracle_runner" in inspect.signature(build_configured_runner).parameters
    assert "write_finding" in inspect.signature(build_configured_runner).parameters
    assert "base_url" in inspect.signature(run_recon).parameters
    assert "graph" in inspect.signature(detect).parameters
    assert "client" in inspect.signature(discover_schema).parameters
    assert "baseline" in inspect.signature(resolver_bola_check).parameters
    assert "probe" in inspect.signature(resolver_bola_check).parameters


def test_registry_references_real_run_wrappers() -> None:
    from reachagent.eval import consolidated

    names = {g.name for g in consolidated._GATES}
    assert names == {"vamp", "crapi", "juiceshop", "portswigger", "dvga"}
    # The real registry's run callables are the module-level thin seams.
    assert consolidated._GATES[0].run.__name__ == "_vamp_run"
