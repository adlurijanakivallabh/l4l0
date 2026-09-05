"""Tests for the issue_oast_probe/poll_oast agent tool wiring."""

from __future__ import annotations

import httpx

from lalo.agent.tools import ToolRegistry
from lalo.oast import OASTServer, build_oast_tools


def test_issue_and_poll_round_trip_through_the_tool_registry() -> None:
    with OASTServer() as oast:
        issue_tool, poll_tool = build_oast_tools(oast)
        registry = ToolRegistry([issue_tool, poll_tool])

        issued = registry.dispatch("issue_oast_probe", {})
        assert issued.ok is True
        token = next(
            line.split("=", 1)[1]
            for line in issued.observation.splitlines()
            if line.startswith("token=")
        )

        no_hit_yet = registry.dispatch("poll_oast", {"token": token})
        assert no_hit_yet.ok is False

        callback_url = next(
            line.split("=", 1)[1]
            for line in issued.observation.splitlines()
            if line.startswith("http_callback_url=")
        )
        httpx.get(callback_url, timeout=5.0)

        hit = registry.dispatch("poll_oast", {"token": token})
        assert hit.ok is True
        assert "http" in hit.observation


def test_poll_oast_requires_a_token() -> None:
    with OASTServer() as oast:
        _issue_tool, poll_tool = build_oast_tools(oast)
        registry = ToolRegistry([poll_tool])
        result = registry.dispatch("poll_oast", {})
        assert result.ok is False


def test_poll_oast_requires_a_token_even_as_explicit_json_null() -> None:
    with OASTServer() as oast:
        _issue_tool, poll_tool = build_oast_tools(oast)
        registry = ToolRegistry([poll_tool])
        result = registry.dispatch("poll_oast", {"token": None})
        assert result.ok is False


def test_issue_oast_probe_accepts_an_optional_probe_ref() -> None:
    with OASTServer() as oast:
        issue_tool, _poll_tool = build_oast_tools(oast)
        registry = ToolRegistry([issue_tool])
        result = registry.dispatch("issue_oast_probe", {"probe_ref": "test-fire-1"})
        assert result.ok is True
        assert "dns_callback_hostname=" in result.observation
