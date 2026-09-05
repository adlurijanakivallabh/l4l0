"""Sanity checks for the named lab-target benchmark cases."""

from __future__ import annotations

from lalo.eval.targets import CRAPI, DVWA, JUICE_SHOP, LAB_TARGETS, VAMPI


def test_lab_targets_lists_all_four_named_targets() -> None:
    assert LAB_TARGETS == (VAMPI, CRAPI, JUICE_SHOP, DVWA)


def test_every_lab_target_has_a_nonempty_ground_truth() -> None:
    for target in LAB_TARGETS:
        assert target.ground_truth_classes
        assert target.name
        assert target.description


def test_lab_target_names_are_unique() -> None:
    names = [target.name for target in LAB_TARGETS]
    assert len(names) == len(set(names))
