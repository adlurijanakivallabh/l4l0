"""Tests for the LLM-driven scan-intake parser."""

from __future__ import annotations

import pytest

from lalo.core.errors import AllProvidersFailedError
from lalo.core.model_router import CompletionRequest, CompletionResponse, ModelRouter
from lalo.intake import ParsedIntent, parse_scan_intent


class _FakeProvider:
    def __init__(
        self,
        *,
        text: str = "",
        texts: list[str] | None = None,
        raises: Exception | None = None,
    ) -> None:
        self.name = "fake"
        self._text = text
        self._texts = texts
        self._raises = raises
        self.seen_prompts: list[CompletionRequest] = []

    def complete(self, request: CompletionRequest) -> CompletionResponse:
        self.seen_prompts.append(request)
        if self._raises is not None:
            raise self._raises
        if self._texts is not None:
            index = min(len(self.seen_prompts) - 1, len(self._texts) - 1)
            text = self._texts[index]
        else:
            text = self._text
        return CompletionResponse(text=text, provider=self.name, model="fake-model")


def _router(provider: _FakeProvider) -> ModelRouter:
    return ModelRouter(providers={"fake": provider}, routes={"intake": ("fake",)})


def test_happy_path_extracts_targets_and_rules_of_engagement() -> None:
    provider = _FakeProvider(
        text='{"targets": ["localhost:5000"], "exclude_targets": [], '
        '"rules_of_engagement": "No DDoS/DoS testing. Focus on API endpoints."}'
    )
    result = parse_scan_intent("test this website localhost:5000, focus on api", _router(provider))
    assert result == ParsedIntent(
        targets=["localhost:5000"],
        exclude_targets=[],
        rules_of_engagement="No DDoS/DoS testing. Focus on API endpoints.",
    )


def test_bare_host_port_is_never_given_a_synthesized_scheme() -> None:
    # The model is instructed not to do this; this test locks in that the
    # parser itself doesn't second-guess or "fix up" what the model returned.
    provider = _FakeProvider(
        text='{"targets": ["localhost:5000"], "exclude_targets": [], "rules_of_engagement": ""}'
    )
    result = parse_scan_intent("test localhost:5000", _router(provider))
    assert result.targets == ["localhost:5000"]


def test_a_scheme_qualified_url_passes_through_unchanged() -> None:
    provider = _FakeProvider(
        text='{"targets": ["https://api.example.com"], "exclude_targets": [], '
        '"rules_of_engagement": ""}'
    )
    result = parse_scan_intent("test https://api.example.com", _router(provider))
    assert result.targets == ["https://api.example.com"]


def test_no_target_named_in_the_text_produces_an_empty_target_list() -> None:
    provider = _FakeProvider(
        text='{"targets": [], "exclude_targets": [], "rules_of_engagement": ""}'
    )
    result = parse_scan_intent("what can you do?", _router(provider))
    assert result.targets == []


def test_malformed_json_retries_once_then_returns_empty_after_max_attempts() -> None:
    provider = _FakeProvider(texts=["not json at all", "still not json"])
    result = parse_scan_intent("test example.com", _router(provider))
    assert result == ParsedIntent(targets=[], exclude_targets=[], rules_of_engagement="")
    assert len(provider.seen_prompts) == 2


def test_a_malformed_reply_followed_by_a_valid_one_succeeds_on_retry() -> None:
    provider = _FakeProvider(
        texts=[
            "not json at all",
            '{"targets": ["example.com"], "exclude_targets": [], "rules_of_engagement": ""}',
        ]
    )
    result = parse_scan_intent("test example.com", _router(provider))
    assert result.targets == ["example.com"]
    assert len(provider.seen_prompts) == 2


def test_all_providers_failed_propagates_rather_than_being_swallowed() -> None:
    provider = _FakeProvider(
        raises=AllProvidersFailedError(role="intake", failures=[("fake", "timeout")])
    )
    with pytest.raises(AllProvidersFailedError):
        parse_scan_intent("test example.com", _router(provider))


def test_all_providers_failed_is_never_retried() -> None:
    # An uncaught exception exits the retry loop on its first raise - the
    # chain has already exhausted itself once, so a second attempt could
    # only repeat the identical failure.
    provider = _FakeProvider(raises=AllProvidersFailedError(role="intake", failures=[]))
    with pytest.raises(AllProvidersFailedError):
        parse_scan_intent("test example.com", _router(provider))
    assert len(provider.seen_prompts) == 1


def test_missing_fields_in_the_reply_default_to_empty() -> None:
    provider = _FakeProvider(text='{"targets": ["example.com"]}')
    result = parse_scan_intent("test example.com", _router(provider))
    assert result == ParsedIntent(
        targets=["example.com"], exclude_targets=[], rules_of_engagement=""
    )


def test_non_string_list_items_are_coerced_to_strings() -> None:
    # Defensive: a model returning a non-string element (e.g. a bare
    # number) must not crash the parser.
    provider = _FakeProvider(
        text='{"targets": [8080], "exclude_targets": [], "rules_of_engagement": ""}'
    )
    result = parse_scan_intent("test port 8080", _router(provider))
    assert result.targets == ["8080"]
