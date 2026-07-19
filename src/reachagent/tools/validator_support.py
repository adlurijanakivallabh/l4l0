"""Validator support — error type and verdict-class accessor (plan §13).

The role-boundary test (``tests/phase1/test_tool_boundaries.py``) asserts
``validator.py`` exposes *exactly* ``run_oracle``, ``write_finding``, and
``mark_inconclusive`` among non-underscore callables. Anything callable defined
or imported by name into that module leaks into the tool surface, so two things
live here instead and are reached through a module alias:

  * :class:`UnconfirmedFindingError` — a callable class; defining it in
    ``validator.py`` would add a fifth name to its manifest.
  * :func:`oracle_verdict_type` — lets ``write_finding`` ``isinstance``-check the
    verdict against :class:`~reachagent.oracles.base.OracleVerdict` without
    binding that (callable) class as a module-level name in ``validator.py``.

Same discipline the Explorer uses for its records (Task 5).
"""

from __future__ import annotations

from reachagent.oracles.base import OracleVerdict


class UnconfirmedFindingError(RuntimeError):
    """Raised when ``write_finding`` is asked to commit an unconfirmed finding.

    Code-level enforcement of the CLAUDE.md non-negotiable: no ``Finding`` is
    ever written without a ``confirmed_violation`` verdict from ``run_oracle``.
    The gate is on ``OracleVerdict.is_violation`` — *not* merely ``.confirmed`` —
    because ``confirmed_allowed``/``confirmed_denied`` are confirmed *facts* about
    a ``can_call`` edge (§6), not findings (Task 6 decision). A raw candidate (no
    verdict at all) fails the same gate, before the violation check.
    """


def oracle_verdict_type() -> type[OracleVerdict]:
    """Return the :class:`OracleVerdict` class for a runtime ``isinstance`` check."""
    return OracleVerdict
