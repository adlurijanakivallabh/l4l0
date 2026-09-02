"""Rate-limit absence — STRUCTURAL RATE_LIMIT_ABSENT oracle tests (§7).

v3: the fixed decide() decision logic this file tested was removed (live
judgment now goes through reachagent.oracles.llm_judgment.judge), so every
test here tested removed functionality and was deleted. The detector/driver
tests live in tests/phase3/test_rate_limit.py and
tests/scan/test_rate_limit_absence_driver.py.
"""

from __future__ import annotations
