"""Known-vulnerable-version — STRUCTURAL KNOWN_VULNERABLE_VERSION oracle tests (§7).

v3: the fixed decide() decision logic this file tested was removed (live
judgment now goes through reachagent.oracles.llm_judgment.judge), so every
test here tested removed functionality and was deleted. The CVE-intel
client/detector tests live in tests/cve_intel/.
"""

from __future__ import annotations
