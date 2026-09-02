"""Prototype pollution — STRUCTURAL PROTOTYPE_POLLUTION oracle tests (§7, v2 W9).

v3: the fixed decide() decision logic this file tested (including the
evidence-field validation it drove) was removed (live judgment now goes
through reachagent.oracles.llm_judgment.judge), so every test here tested
removed functionality and was deleted. The live browser driver lives in
scan/prototype_pollution.py and is tested via a fake BrowserDriver in
tests/scan/test_prototype_pollution.py.
"""

from __future__ import annotations
