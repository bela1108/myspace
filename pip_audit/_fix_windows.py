"""
Explain supported fix windows using advisory coverage and release channels.
"""

from __future__ import annotations

from collections.abc import Collection, Sequence
from dataclasses import dataclass
from enum import Enum
from typing import NewType

from packaging.version import Version

ReleaseChannel = NewType("ReleaseChannel", str)


@dataclass(frozen=True)
class VersionRange:
    """
    An inclusive range of PEP 440 versions.
    """

    start: Version
    end: Version

    def contains(self, version: Version) -> bool:
        """
        Return whether the range contains the given version.
        """
        return self.start <= version <= self.end


@dataclass(frozen=True)
class CandidateRelease:
    """
    A package version available through a release channel.
    """

    version: Version
    channel: ReleaseChannel
    withdrawn: bool = False


@dataclass(frozen=True)
class AdvisorySource:
    """
    Confirmed affected ranges and the versions covered by one advisory source.
    """

    name: str
    coverage: VersionRange
    affected_ranges: tuple[VersionRange, ...]


class ExclusionReason(str, Enum):
    """
    Reasons why a candidate cannot be included in a supported fix window.
    """

    UNSTABLE = "unstable"
    CHANNEL_UNAVAILABLE = "channel-unavailable"
    WITHDRAWN = "withdrawn"
    SOURCE_COVERAGE_GAP = "source-coverage-gap"
    SOURCE_AFFECTED = "source-affected"


@dataclass(frozen=True)
class ExcludedRelease:
    """
    A candidate release and every reason that excludes it.
    """

    candidate: CandidateRelease
    reasons: tuple[ExclusionReason, ...]
    details: tuple[str, ...]


@dataclass(frozen=True)
class FixWindow:
    """
    A consecutive sequence of candidate releases supported by every source.
    """

    package_name: str
    start_version: Version
    end_version: Version
    versions: tuple[Version, ...]
    channels: frozenset[ReleaseChannel]
    sources: frozenset[str]


@dataclass(frozen=True)
class FixWindowExplanation:
    """
    Supported fix windows together with the candidates that could not join them.
    """

    package_name: str
    fix_windows: tuple[FixWindow, ...]
    excluded_releases: tuple[ExcludedRelease, ...]


def explain_fix_windows(
    package_name: str,
    candidates: Sequence[CandidateRelease],
    advisories: Sequence[AdvisorySource],
    allowed_channels: Collection[ReleaseChannel],
) -> FixWindowExplanation:
    """
    Explain which consecutive candidate versions form fully supported fix windows.

    A candidate is safe only when it is stable, available through an allowed channel,
    not withdrawn, covered by every advisory source, and outside every confirmed
    affected range. Unsupported candidates break continuity because versions outside
    the supplied candidate sequence are never inferred.
    """
    _validate_inputs(package_name, candidates, advisories, allowed_channels)

    allowed = frozenset(allowed_channels)
    excluded: list[ExcludedRelease] = []
    safe_indices: list[int] = []

    for index, candidate in enumerate(candidates):
        reasons: list[ExclusionReason] = []
        details: list[str] = []

        if candidate.version.is_prerelease:
            reasons.append(ExclusionReason.UNSTABLE)
            details.append(f"{candidate.version} is not a stable release")
        if candidate.channel not in allowed:
            reasons.append(ExclusionReason.CHANNEL_UNAVAILABLE)
            details.append(f"{candidate.version} is not published to an allowed channel")
        if candidate.withdrawn:
            reasons.append(ExclusionReason.WITHDRAWN)
            details.append(f"{candidate.version} has been withdrawn")

        release_eligible = not (
            candidate.version.is_prerelease or candidate.channel not in allowed
        )
        if release_eligible:
            for advisory in advisories:
                if not advisory.coverage.contains(candidate.version):
                    reasons.append(ExclusionReason.SOURCE_COVERAGE_GAP)
                    details.append(
                        f"{advisory.name} does not cover {candidate.version}; "
                        "its safety cannot be inferred"
                    )
                elif any(
                    affected_range.contains(candidate.version)
                    for affected_range in advisory.affected_ranges
                ):
                    reasons.append(ExclusionReason.SOURCE_AFFECTED)
                    details.append(f"{advisory.name} lists {candidate.version} as affected")

        if reasons:
            unique_reasons = tuple(dict.fromkeys(reasons))
            excluded.append(ExcludedRelease(candidate, unique_reasons, tuple(details)))
        else:
            safe_indices.append(index)

    windows: list[FixWindow] = []
    group: list[int] = []

    def close_window(group_indices: list[int]) -> None:
        if not group_indices:
            return

        group_candidates = [candidates[index] for index in group_indices]
        windows.append(
            FixWindow(
                package_name=package_name,
                start_version=group_candidates[0].version,
                end_version=group_candidates[-1].version,
                versions=tuple(candidate.version for candidate in group_candidates),
                channels=frozenset(candidate.channel for candidate in group_candidates),
                sources=frozenset(advisory.name for advisory in advisories),
            )
        )

    for position, index in enumerate(safe_indices):
        if group and index != safe_indices[position - 1] + 1:
            close_window(group)
            group = []
        group.append(index)
    close_window(group)

    return FixWindowExplanation(
        package_name=package_name,
        fix_windows=tuple(windows),
        excluded_releases=tuple(excluded),
    )


def _validate_inputs(
    package_name: str,
    candidates: Sequence[CandidateRelease],
    advisories: Sequence[AdvisorySource],
    allowed_channels: Collection[ReleaseChannel],
) -> None:
    """
    Validate that the inputs can produce an explanation without hidden assumptions.
    """
    if not package_name:
        raise ValueError("package_name must not be empty")
    if not advisories:
        raise ValueError("at least one advisory source is required")
    if not allowed_channels:
        raise ValueError("at least one allowed release channel is required")

    source_names = [advisory.name for advisory in advisories]
    if len(source_names) != len(set(source_names)):
        raise ValueError("advisory source names must be unique")

    for advisory in advisories:
        if not advisory.name:
            raise ValueError("advisory source names must not be empty")
        if advisory.coverage.start > advisory.coverage.end:
            raise ValueError("advisory coverage ranges must start before their end")
        for affected_range in advisory.affected_ranges:
            if affected_range.start > affected_range.end:
                raise ValueError("affected ranges must start before their end")
            starts_in_coverage = advisory.coverage.contains(affected_range.start)
            ends_in_coverage = advisory.coverage.contains(affected_range.end)
            if not starts_in_coverage or not ends_in_coverage:
                raise ValueError("affected ranges must be contained by source coverage")

    seen_versions: set[Version] = set()
    previous_version: Version | None = None
    for candidate in candidates:
        if candidate.version in seen_versions:
            raise ValueError(f"duplicate candidate version: {candidate.version}")
        seen_versions.add(candidate.version)

        if previous_version is not None and candidate.version <= previous_version:
            raise ValueError("candidate releases must be sorted by version")
        previous_version = candidate.version
