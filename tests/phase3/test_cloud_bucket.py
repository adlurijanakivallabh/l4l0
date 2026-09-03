"""Cloud bucket exposure detector — hermetic tests (§7, Prober-injection pattern).

v3 (CLAUDE.md): decide() is gone — confirmation is now an LLM judgment, not
something a hermetic test can re-derive deterministically. Tests that need a
confirmed verdict inject a fixed `oracle_runner` (see
tests/_oracle_test_support.py) in place of the real default registry runner,
matching the pattern in test_path_traversal.py.
"""

from __future__ import annotations

from reachagent.cloud_bucket.detector import (
    BUCKET_NAME_SUFFIXES,
    BucketProbe,
    BucketProber,
    candidate_bucket_probes,
    derive_seed_names,
    detect_cloud_bucket_exposure,
)
from tests._oracle_test_support import CONFIRMS, INCONCLUSIVE, fixed_oracle_runner

_S3_MARKER = "<ListBucketResult"


def test_derive_seed_names_prefers_registrable_domain_label() -> None:
    assert derive_seed_names("demo.testfire.net") == ("testfire", "demo")


def test_derive_seed_names_single_label_host() -> None:
    assert derive_seed_names("localhost") == ("localhost",)


def test_derive_seed_names_yields_nothing_for_a_bare_ip_address() -> None:
    # An IP-address target (the common shape for local eval stacks like
    # VAmPI's 127.0.0.1) has no organization-name label to guess a bucket
    # from — probing short numeric seeds like "127"/"0" risks hitting a
    # real, unrelated, coincidentally-public bucket and confirming a
    # finding against a target that has nothing to do with it.
    assert derive_seed_names("127.0.0.1") == ()
    assert derive_seed_names("::1") == ()
    assert candidate_bucket_probes("127.0.0.1") == ()


def test_derive_seed_names_strips_a_port_before_the_ip_check() -> None:
    # Caught live: crAPI's own Host fact carries "127.0.0.1:8888" (with
    # port) — ipaddress.ip_address() raises on that string, which silently
    # defeated the IP guard above and reproduced the exact same false
    # positive on the very next run. A host:port or bracketed [::1]:port
    # must resolve to the same "no seeds" answer as the bare host.
    assert derive_seed_names("127.0.0.1:8888") == ()
    assert derive_seed_names("[::1]:8888") == ()
    assert derive_seed_names("demo.testfire.net:8080") == ("testfire", "demo")


def test_candidate_bucket_probes_covers_every_suffix_and_provider() -> None:
    probes = candidate_bucket_probes("demo.testfire.net")
    seeds = len(derive_seed_names("demo.testfire.net"))
    assert len(probes) == seeds * len(BUCKET_NAME_SUFFIXES) * 3  # 3 provider templates
    assert any("testfire.s3.amazonaws.com" in url for url, _marker in probes)
    assert any("testfire.storage.googleapis.com" in url for url, _marker in probes)
    assert any("testfire.blob.core.windows.net" in url for url, _marker in probes)


def test_candidate_bucket_probes_skips_seeds_with_invalid_characters() -> None:
    # A seed with underscores or other non-bucket-safe characters must never
    # produce a malformed probe URL.
    probes = candidate_bucket_probes("my_weird_host")
    assert probes == ()


def test_confirmed_exposure_yields_a_confirmed_result() -> None:
    target_url = "https://testfire.s3.amazonaws.com/"

    def fire_probe(url: str) -> BucketProbe:
        if url == target_url:
            return BucketProbe(status=200, body=f"<?xml?>{_S3_MARKER}<Name>testfire</Name>")
        return BucketProbe(status=404, body="<Error><Code>NoSuchBucket</Code></Error>")

    prober = BucketProber(fire_probe=fire_probe, oracle_runner=fixed_oracle_runner(CONFIRMS))
    probes = ((target_url, _S3_MARKER), ("https://other.s3.amazonaws.com/", _S3_MARKER))
    result = detect_cloud_bucket_exposure(prober, probes=probes, evidence_ref="ref-1")
    assert result.confirmed is True
    assert result.exposed_url == target_url
    assert result.evidence_ref == "ref-1"


def test_no_candidate_matches_yields_no_confirmation() -> None:
    def fire_probe(url: str) -> BucketProbe:
        return BucketProbe(status=404, body="<Error><Code>NoSuchBucket</Code></Error>")

    prober = BucketProber(fire_probe=fire_probe)
    probes = (("https://a.s3.amazonaws.com/", _S3_MARKER),)
    result = detect_cloud_bucket_exposure(prober, probes=probes)
    assert result.confirmed is False


def test_transport_failure_on_one_candidate_does_not_abort_the_rest() -> None:
    target_url = "https://b.s3.amazonaws.com/"

    def fire_probe(url: str) -> BucketProbe:
        if url == "https://a.s3.amazonaws.com/":
            raise ConnectionError("boom")
        if url == target_url:
            return BucketProbe(status=200, body=_S3_MARKER)
        return BucketProbe(status=404, body="")

    prober = BucketProber(fire_probe=fire_probe, oracle_runner=fixed_oracle_runner(CONFIRMS))
    probes = (
        ("https://a.s3.amazonaws.com/", _S3_MARKER),
        (target_url, _S3_MARKER),
    )
    result = detect_cloud_bucket_exposure(prober, probes=probes)
    assert result.confirmed is True
    assert result.exposed_url == target_url


class _SequencedRunner:
    """Returns a different fixed verdict on each successive call — matches
    tests/phase3/test_cache_poisoning.py's own pattern."""

    def __init__(self, verdicts: list) -> None:
        self._verdicts = list(verdicts)

    def __call__(self, mechanism, evidence):  # noqa: ANN001
        return fixed_oracle_runner(self._verdicts.pop(0))(mechanism, evidence)


def test_no_fire_delayed_reread_is_byte_for_byte_unchanged() -> None:
    target_url = "https://testfire.s3.amazonaws.com/"

    def fire_probe(url: str) -> BucketProbe:
        return BucketProbe(status=200, body=_S3_MARKER)

    prober = BucketProber(fire_probe=fire_probe, oracle_runner=fixed_oracle_runner(CONFIRMS))
    result = detect_cloud_bucket_exposure(prober, probes=((target_url, _S3_MARKER),))
    assert result.confirmed is True
    assert result.corroborated is False


def test_delayed_reread_still_exposed_corroborates() -> None:
    target_url = "https://testfire.s3.amazonaws.com/"

    def fire_probe(url: str) -> BucketProbe:
        return BucketProbe(status=200, body=_S3_MARKER)

    prober = BucketProber(
        fire_probe=fire_probe,
        oracle_runner=_SequencedRunner([CONFIRMS, CONFIRMS]),
        fire_delayed_reread=fire_probe,
    )
    result = detect_cloud_bucket_exposure(
        prober, probes=((target_url, _S3_MARKER),), evidence_ref="ref-corroborated"
    )
    assert result.confirmed is True
    assert result.corroborated is True
    assert result.exposed_url == target_url


def test_delayed_reread_no_longer_exposed_fails_closed_but_tries_the_next_candidate() -> None:
    """A candidate that goes from exposed to locked-down between the two
    reads must not be confirmed — but since every remaining candidate is a
    wholly independent third-party bucket, the search still moves on and
    can confirm a DIFFERENT, genuinely (and stably) exposed candidate."""
    flapping_url = "https://a.s3.amazonaws.com/"
    stable_url = "https://b.s3.amazonaws.com/"

    def fire_probe(url: str) -> BucketProbe:
        return BucketProbe(status=200, body=_S3_MARKER)

    def fire_delayed_reread(url: str) -> BucketProbe:
        if url == flapping_url:
            return BucketProbe(status=403, body="<Error><Code>AccessDenied</Code></Error>")
        return BucketProbe(status=200, body=_S3_MARKER)

    prober = BucketProber(
        fire_probe=fire_probe,
        oracle_runner=_SequencedRunner([CONFIRMS, INCONCLUSIVE, CONFIRMS, CONFIRMS]),
        fire_delayed_reread=fire_delayed_reread,
    )
    probes = ((flapping_url, _S3_MARKER), (stable_url, _S3_MARKER))
    result = detect_cloud_bucket_exposure(prober, probes=probes)
    assert result.confirmed is True
    assert result.corroborated is True
    assert result.exposed_url == stable_url
