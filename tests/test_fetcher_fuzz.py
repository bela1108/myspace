# Copyright 2026, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Deterministic security fuzzing for the ngclient fetcher.

The campaign uses a fixed seed, in-memory HTTP responses, independent limits
for redirects and response size, and URL normalization/containment checks.
Failing attack cases are greedily reduced while retaining the features that
made the raw URL misleading and the stable final rejection reason.
"""

from __future__ import annotations

import random
import unittest
from collections import Counter
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING
from unittest.mock import patch

import urllib3

from tuf.api import exceptions
from tuf.ngclient import Urllib3Fetcher
from tuf.ngclient._internal.fetch_policy import (
    REASON_BYTE_LIMIT,
    REASON_ORIGIN_MISMATCH,
    REASON_PATH_ESCAPE,
    REASON_REDIRECT_LIMIT,
    FetchPolicy,
    FetchPolicyError,
)

if TYPE_CHECKING:
    from collections.abc import Iterator

FUZZ_SEED = 20261125036
FUZZ_BASE_URL = "http://fuzz-fetcher.test/repo/metadata/"
LEGACY_BODY = b"junk data"
OK = "ok"

REQUIRED_ATTACK_SURFACE = frozenset(
    {
        "redirect",
        "percent_encoding",
        "parent_path_alias",
        "separator_alias",
    }
)

MINIMAL_ESCAPE_LOCATIONS = (
    "..%2f",
    "%2e%2e/",
    "..%2F",
    ".%2e/",
    "%2e%2e%2f",
)


@dataclass(frozen=True)
class FuzzCase:
    """One deterministic fetcher scenario."""

    initial_url: str = FUZZ_BASE_URL + "start"
    locations: tuple[str, ...] = ()
    chunks: tuple[bytes, ...] = (b"payload",)
    max_redirects: int = 3
    max_bytes: int = 4096
    chunk_size: int = 7
    base_url: str = FUZZ_BASE_URL
    name: str = "fuzz-case"

    @property
    def body(self) -> bytes:
        return b"".join(self.chunks)


@dataclass(frozen=True)
class Observation:
    """Observable result of running a FuzzCase."""

    reason: str | None
    body: bytes | None
    requested_urls: tuple[str, ...]
    redirect_options: tuple[object, ...]
    final_url: str | None = None
    normalized_path: str | None = None
    status_code: int | None = None


@dataclass(frozen=True)
class MinimizedFailure:
    """Reduced counterexample and the reason that must remain stable."""

    case: FuzzCase
    reason: str
    attack_surface: tuple[str, ...]
    requested_urls: tuple[str, ...]
    rejected_url: str | None
    naive_prefix_bypass: bool


class FakeResponse:
    """Minimal urllib3 response double."""

    def __init__(
        self,
        status: int = 200,
        chunks: tuple[bytes, ...] = (),
        location: str | None = None,
        slice_by_amount: bool = False,
    ) -> None:
        self.status = status
        self._chunks = chunks
        self.headers: dict[str, str] = {}
        if location is not None:
            self.headers["Location"] = location
        self._slice_by_amount = slice_by_amount
        self.closed = False

    def getheader(self, name: str, default: str | None = None) -> str | None:
        return self.headers.get(name, default)

    def stream(self, amount: int | None = None) -> Iterator[bytes]:
        if self._slice_by_amount and amount:
            body = b"".join(self._chunks)
            for start in range(0, len(body), amount):
                yield body[start : start + amount]
            return

        yield from self._chunks

    def close(self) -> None:
        self.closed = True

    def release_conn(self) -> None:
        return None

    def drain_conn(self) -> None:
        return None


class ScriptedTransport:
    """Callable transport that returns responses in request order."""

    def __init__(self, responses: list[FakeResponse]) -> None:
        self._responses = responses
        self.requested_urls: list[str] = []
        self.redirect_options: list[object] = []

    def __call__(self, method: str, url: str, **kwargs: object) -> FakeResponse:
        index = len(self.requested_urls)
        self.requested_urls.append(url)
        self.redirect_options.append(kwargs.get("redirect", "missing"))
        if index >= len(self._responses):
            raise AssertionError(f"unexpected extra request {method} {url}")
        return self._responses[index]


def _scripted_responses(case: FuzzCase) -> list[FakeResponse]:
    responses = [
        FakeResponse(status=302, location=location)
        for location in case.locations
    ]
    responses.append(FakeResponse(status=200, chunks=case.chunks))
    return responses


def _classify_reason(error: Exception) -> str:
    if isinstance(error, FetchPolicyError):
        return error.reason
    if isinstance(error, exceptions.DownloadLengthMismatchError):
        return REASON_BYTE_LIMIT
    if isinstance(error, exceptions.DownloadHTTPError):
        return f"http_{error.status_code}"
    return f"unexpected:{type(error).__name__}"


def observe(case: FuzzCase) -> Observation:
    """Run a case through the real Urllib3Fetcher public download API."""
    policy = FetchPolicy(
        allowed_base_url=case.base_url,
        max_redirects=case.max_redirects,
    )
    fetcher = Urllib3Fetcher(
        chunk_size=case.chunk_size,
        fetch_policy=policy,
    )
    transport = ScriptedTransport(_scripted_responses(case))

    try:
        with patch.object(fetcher._proxy_env, "request", new=transport):
            body = fetcher.download_bytes(case.initial_url, case.max_bytes)
    except Exception as error:  # noqa: BLE001 - classified in observation
        return Observation(
            reason=_classify_reason(error),
            body=None,
            requested_urls=tuple(transport.requested_urls),
            redirect_options=tuple(transport.redirect_options),
            final_url=getattr(error, "final_url", None),
            normalized_path=getattr(error, "normalized_path", None),
            status_code=getattr(error, "status_code", None),
        )

    return Observation(
        reason=None,
        body=body,
        requested_urls=tuple(transport.requested_urls),
        redirect_options=tuple(transport.redirect_options),
    )


def assert_security_invariants(
    case: FuzzCase, observation: Observation
) -> None:
    """Check bounds and prove rejected targets were never requested."""
    policy = FetchPolicy(
        allowed_base_url=case.base_url,
        max_redirects=case.max_redirects,
    )

    for requested_url in observation.requested_urls:
        try:
            policy.inspect(requested_url)
        except FetchPolicyError as error:
            raise AssertionError(
                f"fetcher requested unauthorized URL {requested_url}"
            ) from error

    for option in observation.redirect_options:
        assert option is False, "policy mode must disable urllib3 redirects"

    if observation.reason is None:
        assert observation.body == case.body
        assert len(case.body) <= case.max_bytes
        assert len(observation.requested_urls) == len(case.locations) + 1
        return

    if observation.reason == REASON_REDIRECT_LIMIT:
        assert len(observation.requested_urls) == case.max_redirects + 1
        assert len(case.locations) >= case.max_redirects + 1
        return

    if observation.reason in (
        REASON_PATH_ESCAPE,
        REASON_ORIGIN_MISMATCH,
    ):
        assert observation.final_url is not None
        assert observation.final_url not in observation.requested_urls
        return

    if observation.reason == REASON_BYTE_LIMIT:
        assert len(case.body) > case.max_bytes
        assert len(observation.requested_urls) == len(case.locations) + 1
        return

    raise AssertionError(f"unexpected observation: {observation.reason}")


def _random_bytes(rng: random.Random, size: int) -> bytes:
    return bytes(rng.randrange(256) for _ in range(size))


def _random_chunks(rng: random.Random, data: bytes) -> tuple[bytes, ...]:
    if not data:
        return ()
    if len(data) == 1:
        return (data,)

    chunk_count = rng.randint(1, 4)
    if chunk_count == 1:
        return (data,)

    cut_count = min(chunk_count - 1, len(data) - 1)
    cuts = sorted(rng.sample(range(1, len(data)), cut_count))
    chunks: list[bytes] = []
    start = 0
    for cut in cuts:
        chunks.append(data[start:cut])
        start = cut
    chunks.append(data[start:])
    return tuple(chunks)


def _safe_location(rng: random.Random, index: int) -> str:
    return rng.choice(
        (
            f"hop-{index}",
            f"./hop-{index}",
            f"../metadata/hop-{index}",
            f"hop-{index}?trace={index}/../../outside",
            f"%68op-{index}",
        )
    )


def random_redirect_case(rng: random.Random, index: int) -> FuzzCase:
    location_count = rng.randint(0, 7)
    data = f"redirect-body-{index}".encode()
    return FuzzCase(
        name=f"redirect-{index}",
        locations=tuple(
            _safe_location(rng, hop) for hop in range(location_count)
        ),
        chunks=_random_chunks(rng, data),
        max_redirects=rng.randint(0, 6),
        max_bytes=len(data) + rng.randint(0, 8),
        chunk_size=rng.randint(1, 12),
    )


def random_byte_case(rng: random.Random, index: int) -> FuzzCase:
    size = rng.randint(0, 48)
    data = _random_bytes(rng, size)
    return FuzzCase(
        name=f"bytes-{index}",
        chunks=_random_chunks(rng, data),
        max_bytes=rng.randint(0, size + 3),
        chunk_size=rng.randint(1, 12),
    )


def _random_escape_location(rng: random.Random) -> str:
    parents = (
        "..",
        "%2e%2e",
        "%2E%2E",
        ".%2e",
        "%2e.",
        "..;params",
        "..%3bparams",
        "%252e%252e",
    )
    separators = (
        "/",
        "%2f",
        "%2F",
        "%5c",
        "%5C",
        "%252f",
        chr(92),
    )
    prefixes = ("", "", "./", "safe/../", "a/b/../../")
    targets = ("secret", "target", "unauthorized")

    depth = rng.randint(1, 3)
    segments = [rng.choice(parents) for _ in range(depth)]
    segments.append(rng.choice(targets))
    separator = rng.choice(separators)
    return rng.choice(prefixes) + separator.join(segments)


def random_path_case(rng: random.Random, index: int) -> FuzzCase:
    prefix_count = rng.randint(0, 2)
    locations = (
        *(_safe_location(rng, hop) for hop in range(prefix_count)),
        _random_escape_location(rng),
    )
    data = b"unauthorized-body"
    return FuzzCase(
        name=f"path-{index}",
        locations=locations,
        chunks=_random_chunks(rng, data),
        max_redirects=4,
        max_bytes=4096,
        chunk_size=rng.randint(1, 12),
    )


def random_combined_case(rng: random.Random, index: int) -> FuzzCase:
    selector = rng.randrange(10)
    if selector < 4:
        return random_redirect_case(rng, index)
    if selector < 7:
        return random_byte_case(rng, index)

    case = random_path_case(rng, index)
    if rng.choice((False, True)):
        case = replace(
            case,
            max_redirects=rng.randint(0, max(0, len(case.locations))),
        )
    if rng.choice((False, True)):
        case = replace(case, max_bytes=rng.randint(0, 16))
    return case


def surface_tags(value: str) -> frozenset[str]:
    lower = value.lower()
    tags: set[str] = set()
    if "%" in value:
        tags.add("percent_encoding")
    if ".." in value or "%2e" in lower or ".%2e" in lower or "%2e." in lower:
        tags.add("parent_path_alias")
    if "%2f" in lower or "%5c" in lower or chr(92) in value or "//" in value:
        tags.add("separator_alias")
    if ";" in value or "%3b" in lower:
        tags.add("matrix_alias")
    if "%25" in lower:
        tags.add("double_encoding")
    return frozenset(tags)


def surface_for_case(case: FuzzCase) -> frozenset[str]:
    tags: set[str] = set()
    for value in (case.initial_url, *case.locations):
        tags.update(surface_tags(value))
    if case.locations:
        tags.add("redirect")
    return frozenset(tags)


def naive_prefix_bypass(case: FuzzCase, observation: Observation) -> bool:
    """Model the old prefix-only check: raw string startswith is insufficient."""
    if observation.reason != REASON_PATH_ESCAPE:
        return False
    if observation.final_url is None:
        return False
    return observation.final_url.startswith(case.base_url)


def _reduction_accepted(
    candidate: FuzzCase,
    baseline_reason: str,
    required_surface: frozenset[str],
) -> bool:
    observation = observe(candidate)
    if observation.reason != baseline_reason:
        return False
    if not required_surface.issubset(surface_for_case(candidate)):
        return False
    try:
        assert_security_invariants(candidate, observation)
    except AssertionError:
        return False
    return naive_prefix_bypass(candidate, observation)


def _deletion_candidate(
    case: FuzzCase,
    baseline_reason: str,
    required_surface: frozenset[str],
) -> FuzzCase | None:
    initial_url = case.initial_url
    for index in range(len(initial_url)):
        candidate = replace(
            case,
            initial_url=initial_url[:index] + initial_url[index + 1 :],
        )
        if _reduction_accepted(candidate, baseline_reason, required_surface):
            return candidate

    for location_index, location in enumerate(case.locations):
        for index in range(len(location)):
            shortened = location[:index] + location[index + 1 :]
            locations = (
                *case.locations[:location_index],
                shortened,
                *case.locations[location_index + 1 :],
            )
            candidate = replace(case, locations=locations)
            if _reduction_accepted(
                candidate, baseline_reason, required_surface
            ):
                return candidate

    return None


def minimize_attack_case(case: FuzzCase) -> MinimizedFailure:
    """Greedily shrink a path escape without changing its rejection reason."""
    baseline = observe(case)
    if baseline.reason != REASON_PATH_ESCAPE:
        raise ValueError("minimize_attack_case requires a path escape")

    current = replace(case, chunks=(), max_bytes=0, chunk_size=1)
    for location in MINIMAL_ESCAPE_LOCATIONS:
        candidate = replace(current, locations=(location,), max_redirects=1)
        if _reduction_accepted(
            candidate, REASON_PATH_ESCAPE, REQUIRED_ATTACK_SURFACE
        ):
            current = candidate
            break

    for max_redirects in range(current.max_redirects + 1):
        candidate = replace(current, max_redirects=max_redirects)
        if _reduction_accepted(
            candidate, REASON_PATH_ESCAPE, REQUIRED_ATTACK_SURFACE
        ):
            current = candidate
            break

    while True:
        shortened = _deletion_candidate(
            current, REASON_PATH_ESCAPE, REQUIRED_ATTACK_SURFACE
        )
        if shortened is None:
            break
        current = shortened

    observation = observe(current)
    surface = tuple(sorted(surface_for_case(current)))
    return MinimizedFailure(
        case=current,
        reason=observation.reason or REASON_PATH_ESCAPE,
        attack_surface=surface,
        requested_urls=observation.requested_urls,
        rejected_url=observation.final_url,
        naive_prefix_bypass=naive_prefix_bypass(current, observation),
    )


def run_seeded_campaign(
    iterations: int = 240,
) -> tuple[Counter[str], MinimizedFailure | None, int]:
    rng = random.Random(FUZZ_SEED)
    reason_counts: Counter[str] = Counter()
    bypass_cases: list[FuzzCase] = []

    for index in range(iterations):
        case = random_combined_case(rng, index)
        observation = observe(case)
        assert_security_invariants(case, observation)
        reason_counts[observation.reason or OK] += 1
        if naive_prefix_bypass(case, observation):
            bypass_cases.append(case)

    minimal = minimize_attack_case(bypass_cases[0]) if bypass_cases else None
    return reason_counts, minimal, len(bypass_cases)


class FetcherFuzzTests(unittest.TestCase):
    def test_redirect_limit_fuzz(self) -> None:
        rng = random.Random(FUZZ_SEED + 1)
        saw_redirect_rejection = False
        saw_success = False

        for index in range(80):
            case = random_redirect_case(rng, index)
            observation = observe(case)
            assert_security_invariants(case, observation)
            if observation.reason == REASON_REDIRECT_LIMIT:
                saw_redirect_rejection = True
            if observation.reason is None:
                saw_success = True

        self.assertTrue(saw_redirect_rejection)
        self.assertTrue(saw_success)

    def test_response_byte_limit_fuzz(self) -> None:
        rng = random.Random(FUZZ_SEED + 2)
        saw_byte_rejection = False
        saw_success = False

        for index in range(100):
            case = random_byte_case(rng, index)
            observation = observe(case)
            assert_security_invariants(case, observation)
            if observation.reason == REASON_BYTE_LIMIT:
                saw_byte_rejection = True
            if observation.reason is None:
                saw_success = True

        self.assertTrue(saw_byte_rejection)
        self.assertTrue(saw_success)

    def test_normalized_path_fuzz(self) -> None:
        rng = random.Random(FUZZ_SEED + 3)
        saw_raw_prefix_bypass = False

        for index in range(120):
            case = random_path_case(rng, index)
            observation = observe(case)
            self.assertEqual(
                observation.reason,
                REASON_PATH_ESCAPE,
                msg=f"case {index}: {case}",
            )
            assert_security_invariants(case, observation)
            if naive_prefix_bypass(case, observation):
                saw_raw_prefix_bypass = True

        self.assertTrue(saw_raw_prefix_bypass)

    def test_fixed_seed_campaign_and_minimal_failure(self) -> None:
        counts, minimal, bypass_count = run_seeded_campaign()

        self.assertGreater(bypass_count, 0)
        self.assertIn(OK, counts)
        self.assertIn(REASON_REDIRECT_LIMIT, counts)
        self.assertIn(REASON_BYTE_LIMIT, counts)
        self.assertIn(REASON_PATH_ESCAPE, counts)

        self.assertIsNotNone(minimal)
        assert minimal is not None
        self.assertEqual(minimal.reason, REASON_PATH_ESCAPE)
        self.assertTrue(minimal.naive_prefix_bypass)
        self.assertEqual(minimal.case.initial_url, FUZZ_BASE_URL)
        self.assertEqual(minimal.case.locations, ("..%2f",))
        self.assertEqual(minimal.case.max_redirects, 1)
        self.assertEqual(minimal.requested_urls, (FUZZ_BASE_URL,))
        self.assertEqual(minimal.rejected_url, FUZZ_BASE_URL + "..%2f")
        self.assertIn("redirect", minimal.attack_surface)
        self.assertIn("percent_encoding", minimal.attack_surface)
        self.assertIn("parent_path_alias", minimal.attack_surface)
        self.assertIn("separator_alias", minimal.attack_surface)


class LegacyFetcherSamplesTests(unittest.TestCase):
    """Characterization samples for the old fetcher behavior."""

    def test_junk_data_sample_remains_unchanged(self) -> None:
        url = "http://legacy-fetcher.test/file.txt"
        response = FakeResponse(200, (LEGACY_BODY,), slice_by_amount=True)

        with (
            patch(
                "tuf.ngclient._internal.proxy.getproxies",
                return_value={},
            ),
            patch.object(
                urllib3.PoolManager, "request", return_value=response
            ) as request_mock,
        ):
            fetcher = Urllib3Fetcher()
            data = fetcher.download_bytes(url, len(LEGACY_BODY) + 4)

        self.assertEqual(data, LEGACY_BODY)
        self.assertNotIn("redirect", request_mock.call_args.kwargs)

    def test_chunked_junk_sample_remains_unchanged(self) -> None:
        url = "http://legacy-fetcher.test/file.txt"
        response = FakeResponse(200, (LEGACY_BODY,), slice_by_amount=True)

        with (
            patch(
                "tuf.ngclient._internal.proxy.getproxies",
                return_value={},
            ),
            patch.object(urllib3.PoolManager, "request", return_value=response),
        ):
            fetcher = Urllib3Fetcher()
            fetcher.chunk_size = 4
            chunks = list(fetcher.fetch(url))

        self.assertEqual(chunks, [b"junk", b" dat", b"a"])

    def test_legacy_valid_url_samples_are_not_rewritten(self) -> None:
        valid_urls = (
            FUZZ_BASE_URL + "timestamp.json",
            FUZZ_BASE_URL + "./timestamp.json",
            FUZZ_BASE_URL + "../metadata/timestamp.json",
            FUZZ_BASE_URL + "timestamp%2Ejson",
            "http://fuzz-fetcher.test/%72epo/%6detadata/timestamp.json",
            FUZZ_BASE_URL + "timestamp.json?next=../../outside",
            FUZZ_BASE_URL + "timestamp.json#fragment",
        )

        for raw_url in valid_urls:
            with self.subTest(url=raw_url):
                case = FuzzCase(
                    initial_url=raw_url,
                    chunks=(LEGACY_BODY,),
                    max_bytes=len(LEGACY_BODY),
                )
                observation = observe(case)
                self.assertIsNone(observation.reason)
                self.assertEqual(observation.requested_urls, (raw_url,))
                self.assertEqual(observation.body, LEGACY_BODY)


if __name__ == "__main__":
    unittest.main(verbosity=2)
