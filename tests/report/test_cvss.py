"""CVSS v3.1 base-score calculator — verified against well-known reference vectors.

Both reference values below are independently hand-derived from the official
FIRST.org CVSS v3.1 formula (see cvss.py's own docstring) in addition to
being widely published, so this pins the implementation against two
independent sources of truth, not just a memorized number.
"""

from __future__ import annotations

import pytest

from reachagent.report.cvss import base_score, format_score, full_vector_string, parse_vector


def test_canonical_critical_vector_scores_9_8() -> None:
    # The textbook "everything maximal, scope unchanged" vector — ubiquitous
    # in CVSS documentation/tutorials as the canonical 9.8 example.
    assert base_score("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8


def test_log4shell_vector_scores_10_0() -> None:
    # CVE-2021-44228 (Log4Shell) — famously the maximum possible base score,
    # published as 10.0 in the NVD; the scope-changed impact formula's own
    # extra terms are what push this above the unchanged-scope 9.8 case.
    assert base_score("AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H") == 10.0


def test_no_impact_scores_zero_regardless_of_exploitability() -> None:
    assert base_score("AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N") == 0.0


def test_higher_attack_complexity_and_privileges_lowers_the_score() -> None:
    easy = base_score("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    harder = base_score("AV:N/AC:H/PR:H/UI:R/S:U/C:H/I:H/A:H")
    assert harder < easy


def test_score_never_exceeds_ten() -> None:
    assert base_score("AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H") <= 10.0


def test_missing_metric_raises_rather_than_silently_scoring_zero() -> None:
    with pytest.raises(KeyError):
        base_score("AV:N/AC:L/PR:N/UI:N/C:H/I:H/A:H")  # missing S


def test_parse_vector_reads_every_metric() -> None:
    assert parse_vector("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == {
        "AV": "N",
        "AC": "L",
        "PR": "N",
        "UI": "N",
        "S": "U",
        "C": "H",
        "I": "H",
        "A": "H",
    }


def test_format_score_shows_one_decimal_place() -> None:
    assert format_score(9.8) == "9.8"
    assert format_score(10.0) == "10.0"
    assert format_score(0.0) == "0.0"


def test_full_vector_string_adds_the_version_prefix() -> None:
    assert full_vector_string("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == (
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    )
