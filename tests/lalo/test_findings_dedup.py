"""Tests for the deterministic (class, target, param) dedup key."""

from __future__ import annotations

from lalo.findings.dedup import dedup_key, find_duplicate
from lalo.graph.model import NodeKind, ReachabilityGraph


def test_dedup_key_is_case_and_whitespace_insensitive() -> None:
    a = dedup_key("SQL-Injection", " https://x.example.com/api ", "id")
    b = dedup_key("sql-injection", "https://x.example.com/api", "ID")
    assert a == b


def test_dedup_key_distinguishes_different_params_on_the_same_endpoint() -> None:
    a = dedup_key("xss", "https://x.example.com/search", "q")
    b = dedup_key("xss", "https://x.example.com/search", "name")
    assert a != b


def test_dedup_key_treats_no_param_as_its_own_bucket() -> None:
    a = dedup_key("ssrf", "https://x.example.com/fetch", None)
    b = dedup_key("ssrf", "https://x.example.com/fetch", "")
    assert a == b


def test_find_duplicate_returns_none_on_an_empty_graph() -> None:
    graph = ReachabilityGraph()
    assert find_duplicate(graph, "sql-injection::x::id") is None


def test_find_duplicate_finds_the_matching_finding_node() -> None:
    graph = ReachabilityGraph()
    graph.add_node("finding-1", NodeKind.FINDING, dedup_key="sql-injection::x::id")
    graph.add_node("finding-2", NodeKind.FINDING, dedup_key="xss::x::q")
    assert find_duplicate(graph, "xss::x::q") == "finding-2"
    assert find_duplicate(graph, "ssti::x::q") is None
