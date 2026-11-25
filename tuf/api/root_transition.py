# Copyright 2026, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Read-only analysis helpers for root metadata transitions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

from tuf.api.metadata import (
    TOP_LEVEL_ROLE_NAMES,
    Metadata,
    Role,
    Root,
)

if TYPE_CHECKING:
    from collections.abc import Sequence
    from datetime import datetime

TransitionGapKind = Literal[
    "version_sequence",
    "missing_role_key",
    "unreachable_threshold",
    "effective_time",
]


@dataclass(frozen=True)
class RootTransitionGap:
    """First continuity problem found in a root transition plan.

    Args:
        kind: Machine-readable category of the problem.
        stage_version: Version of the root stage where the problem was found.
        role: Affected top-level role, or ``None`` for a root-wide problem.
        effective_time: Relevant expiration time, when applicable.
        message: Human-readable description of the problem.
    """

    kind: TransitionGapKind
    stage_version: int
    role: str | None
    effective_time: datetime | None
    message: str


@dataclass(frozen=True)
class RootTransitionPrecheckResult:
    """Result of a read-only root transition precheck.

    Args:
        stages_checked: Number of root stages inspected before returning.
        first_gap: First continuity problem, or ``None`` if no gap was found.
    """

    stages_checked: int
    first_gap: RootTransitionGap | None

    @property
    def verified(self) -> bool:
        """Return whether the complete transition plan is continuous."""
        return self.first_gap is None


def _role_gap(root: Root, role_name: str) -> RootTransitionGap | None:
    role: Role = root.roles[role_name]

    for keyid in role.keyids:
        if keyid not in root.keys:
            return RootTransitionGap(
                kind="missing_role_key",
                stage_version=root.version,
                role=role_name,
                effective_time=root.expires,
                message=(
                    f"Role {role_name} references unknown key {keyid} in "
                    f"root v{root.version}"
                ),
            )

    if role.threshold > len(role.keyids):
        return RootTransitionGap(
            kind="unreachable_threshold",
            stage_version=root.version,
            role=role_name,
            effective_time=root.expires,
            message=(
                f"Role {role_name} requires {role.threshold} signatures but "
                f"only has {len(role.keyids)} responsible keys in root "
                f"v{root.version}"
            ),
        )

    return None


def precheck_root_transition(
    root_metadata: Sequence[Metadata[Root]],
) -> RootTransitionPrecheckResult:
    """Check a planned sequence of root versions without modifying it.

    Each metadata object represents one transition stage. Stages are checked
    in order and the first gap is returned. A stage must use the next root
    version number, every top-level role must have enough responsible keys to
    meet its threshold, and each later stage must remain valid beyond the
    previous stage's expiration.

    TUF root metadata has no separate effective-start field, so expiration
    times are used as the stage effective-time boundaries. This policy check
    does not verify signatures and does not write metadata.

    Args:
        root_metadata: Ordered root metadata files in the transition plan.

    Raises:
        ValueError: ``root_metadata`` does not contain at least one stage.

    Returns:
        A result containing the first transition gap, if one was found.
    """

    if not root_metadata:
        raise ValueError("At least one root metadata stage is required")

    roots = [metadata.signed for metadata in root_metadata]
    previous_root: Root | None = None

    for stage_number, root in enumerate(roots, start=1):
        if previous_root is not None:
            expected_version = previous_root.version + 1
            if root.version != expected_version:
                return RootTransitionPrecheckResult(
                    stages_checked=stage_number,
                    first_gap=RootTransitionGap(
                        kind="version_sequence",
                        stage_version=root.version,
                        role=None,
                        effective_time=root.expires,
                        message=(
                            "Expected root version "
                            f"v{expected_version} after "
                            f"v{previous_root.version}, "
                            f"got v{root.version}"
                        ),
                    ),
                )

        for role_name in TOP_LEVEL_ROLE_NAMES:
            role_gap = _role_gap(root, role_name)
            if role_gap is not None:
                return RootTransitionPrecheckResult(
                    stages_checked=stage_number,
                    first_gap=role_gap,
                )

        if previous_root is not None and root.expires <= previous_root.expires:
            return RootTransitionPrecheckResult(
                stages_checked=stage_number,
                first_gap=RootTransitionGap(
                    kind="effective_time",
                    stage_version=root.version,
                    role=None,
                    effective_time=root.expires,
                    message=(
                        f"Root v{root.version} expires at {root.expires}, "
                        "which does not extend beyond the previous stage "
                        f"expiration at {previous_root.expires}"
                    ),
                ),
            )

        previous_root = root

    return RootTransitionPrecheckResult(
        stages_checked=len(roots),
        first_gap=None,
    )
