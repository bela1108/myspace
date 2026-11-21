from __future__ import annotations

import pytest
from packaging.version import Version

from pip_audit._fix_windows import (
    AdvisorySource,
    CandidateRelease,
    ExclusionReason,
    ReleaseChannel,
    VersionRange,
    explain_fix_windows,
)


STABLE = ReleaseChannel("stable")
BETA = ReleaseChannel("beta")


def test_explain_fix_windows_with_boundary_conflict():
    candidates = [
        CandidateRelease(Version("1.0.0"), STABLE),
        CandidateRelease(Version("1.0.1"), STABLE),
        CandidateRelease(Version("1.0.2"), STABLE, withdrawn=True),
        CandidateRelease(Version("1.0.3"), STABLE),
        CandidateRelease(Version("1.0.4"), BETA),
        CandidateRelease(Version("1.0.5a1"), STABLE),
        CandidateRelease(Version("1.0.5"), STABLE),
    ]
    advisories = [
        AdvisorySource(
            name="advisory-a",
            coverage=VersionRange(Version("1.0.0"), Version("1.0.3")),
            affected_ranges=(VersionRange(Version("1.0.0"), Version("1.0.1")),),
        ),
        AdvisorySource(
            name="advisory-b",
            coverage=VersionRange(Version("1.0.0"), Version("1.0.5")),
            affected_ranges=(VersionRange(Version("1.0.0"), Version("1.0.2")),),
        ),
    ]

    explanation = explain_fix_windows("example-package", candidates, advisories, [STABLE])

    assert len(explanation.fix_windows) == 1
    window = explanation.fix_windows[0]
    assert window.start_version == Version("1.0.3")
    assert window.end_version == Version("1.0.3")
    assert window.versions == (Version("1.0.3"),)
    assert window.channels == frozenset({STABLE})
    assert window.sources == frozenset({"advisory-a", "advisory-b"})

    exclusions = {
        exclusion.candidate.version: exclusion for exclusion in explanation.excluded_releases
    }
    assert exclusions[Version("1.0.0")].reasons == (ExclusionReason.SOURCE_AFFECTED,)
    assert exclusions[Version("1.0.1")].reasons == (ExclusionReason.SOURCE_AFFECTED,)
    assert exclusions[Version("1.0.2")].reasons == (
        ExclusionReason.WITHDRAWN,
        ExclusionReason.SOURCE_AFFECTED,
    )
    assert exclusions[Version("1.0.2")].details == (
        "1.0.2 has been withdrawn",
        "advisory-b lists 1.0.2 as affected",
    )
    assert exclusions[Version("1.0.4")].reasons == (ExclusionReason.CHANNEL_UNAVAILABLE,)
    assert exclusions[Version("1.0.5a1")].reasons == (ExclusionReason.UNSTABLE,)
    assert exclusions[Version("1.0.5")].reasons == (ExclusionReason.SOURCE_COVERAGE_GAP,)
    assert exclusions[Version("1.0.5")].details == (
        "advisory-a does not cover 1.0.5; its safety cannot be inferred",
    )


def test_explain_fix_windows_keeps_supported_candidates_consecutive():
    candidates = [
        CandidateRelease(Version("1.0.0"), STABLE),
        CandidateRelease(Version("1.0.1"), STABLE),
        CandidateRelease(Version("1.0.2"), STABLE),
        CandidateRelease(Version("1.0.3"), STABLE),
    ]
    advisories = [
        AdvisorySource(
            name="advisory-a",
            coverage=VersionRange(Version("1.0.0"), Version("1.0.3")),
            affected_ranges=(VersionRange(Version("1.0.0"), Version("1.0.1")),),
        ),
        AdvisorySource(
            name="advisory-b",
            coverage=VersionRange(Version("1.0.0"), Version("1.0.3")),
            affected_ranges=(VersionRange(Version("1.0.0"), Version("1.0.1")),),
        ),
    ]

    explanation = explain_fix_windows("example-package", candidates, advisories, [STABLE])

    assert len(explanation.fix_windows) == 1
    assert explanation.fix_windows[0].versions == (
        Version("1.0.2"),
        Version("1.0.3"),
    )
    assert [exclusion.candidate.version for exclusion in explanation.excluded_releases] == [
        Version("1.0.0"),
        Version("1.0.1"),
    ]


def test_explain_fix_windows_without_candidates():
    advisories = [
        AdvisorySource(
            name="advisory-a",
            coverage=VersionRange(Version("1.0.0"), Version("1.0.1")),
            affected_ranges=(),
        )
    ]

    explanation = explain_fix_windows("example-package", [], advisories, [STABLE])

    assert explanation.fix_windows == ()
    assert explanation.excluded_releases == ()


@pytest.mark.parametrize(
    ("advisories", "allowed_channels", "message"),
    [
        (
            [],
            [STABLE],
            "at least one advisory source is required",
        ),
        (
            [
                AdvisorySource(
                    "advisory-a",
                    VersionRange(Version("1.0.0"), Version("1.0.1")),
                    (),
                )
            ],
            [],
            "at least one allowed release channel is required",
        ),
    ],
)
def test_explain_fix_windows_rejects_incomplete_inputs(
    advisories,
    allowed_channels,
    message,
):
    candidates = [CandidateRelease(Version("1.0.0"), STABLE)]

    with pytest.raises(ValueError, match=message):
        explain_fix_windows("example-package", candidates, advisories, allowed_channels)
