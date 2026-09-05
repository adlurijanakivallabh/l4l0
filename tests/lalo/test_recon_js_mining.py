"""Tests for pure JS/source-map endpoint mining."""

from __future__ import annotations

from lalo.recon import (
    endpoint_urls_from_paths,
    find_sourcemap_url,
    mine_js_for_paths,
    mine_sourcemap_sources,
)


def test_mine_js_for_paths_extracts_api_like_literals() -> None:
    js = """
    const routes = { users: "/api/v1/users/{id}", admin: '/api/v1/admin/settings' };
    fetch("/api/v1/users/{id}").then(r => r.json());
    """
    paths = mine_js_for_paths(js)
    assert "/api/v1/users/{id}" in paths
    assert "/api/v1/admin/settings" in paths


def test_mine_js_for_paths_dedupes() -> None:
    js = '"/api/a" "/api/a" "/api/a"'
    assert mine_js_for_paths(js) == ["/api/a"]


def test_mine_js_for_paths_ignores_static_asset_extensions() -> None:
    js = '"/assets/logo.png" "/api/report.pdf" "/styles/main.css"'
    paths = mine_js_for_paths(js)
    assert "/assets/logo.png" not in paths
    assert "/styles/main.css" not in paths
    assert "/api/report.pdf" in paths  # not a denylisted static extension


def test_find_sourcemap_url_present_and_absent() -> None:
    assert find_sourcemap_url("//# sourceMappingURL=app.js.map\nrest") == "app.js.map"
    assert find_sourcemap_url("no comment here") is None


def test_mine_sourcemap_sources_extracts_string_list() -> None:
    sourcemap = {
        "version": 3,
        "sources": ["webpack:///./src/api/routes.ts", "webpack:///./src/x.ts"],
    }
    assert mine_sourcemap_sources(sourcemap) == [
        "webpack:///./src/api/routes.ts",
        "webpack:///./src/x.ts",
    ]
    assert mine_sourcemap_sources({"sources": "not-a-list"}) == []
    assert mine_sourcemap_sources({}) == []


def test_endpoint_urls_from_paths_joins_against_base() -> None:
    urls = endpoint_urls_from_paths(
        "https://app.example.com/static/bundle.js", ["/api/users", "/api/orders"]
    )
    assert urls == [
        "https://app.example.com/api/users",
        "https://app.example.com/api/orders",
    ]
