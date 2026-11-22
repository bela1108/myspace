# Copyright 2026 python-tuf contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Read-only precheck for staged signing handovers

When signing responsibility moves from one team to another (for example
during a department merger), the handover can be rehearsed as a sequence
of stages: each stage contains the pending-release metadata, signed with
test keys, that would be published at that point in time.

handover_precheck() walks the stages in order and checks, for every stage:

* trust verification: the stage root is signed by both the previous and
  the current root keys, and every other pending metadata is signed by
  the keys its delegator requires for the role
* role service coverage: every role still has enough available keys to
  meet its threshold, given the currently available signing keys

The precheck is read-only: it never modifies the metadata it consumes.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from tuf.api.metadata import Root, Targets

if TYPE_CHECKING:
    from collections.abc import Collection, Mapping

    from tuf.api.metadata import Metadata

logger = logging.getLogger(__name__)


@dataclass
class HandoverGap:
    """A role that no one can serve at a handover stage, with evidence.

    Attributes:
        stage: Name of the handover stage the gap was found in.
        role: Name of the role that cannot be served.
        reason: "trust" if the pending metadata does not verify,
            "coverage" if the role lacks enough available keys.
        evidence: Human readable details (key counts and keyids).
    """

    stage: str
    role: str
    reason: str
    evidence: str


@dataclass
class HandoverStageReport:
    """Precheck result for a single handover stage.

    Attributes:
        stage: Name of the handover stage.
        gaps: Gaps found in this stage, in check order.
    """

    stage: str
    gaps: list[HandoverGap] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        """True if no gaps were found in this stage."""
        return not self.gaps


@dataclass
class HandoverReport:
    """Precheck result for a full handover plan.

    Attributes:
        stages: Per-stage reports in handover order.
    """

    stages: list[HandoverStageReport]

    @property
    def ok(self) -> bool:
        """True if no gaps were found in any stage."""
        return all(stage.ok for stage in self.stages)

    @property
    def first_gap(self) -> HandoverGap | None:
        """First point in the handover no one can serve, or None."""
        for stage in self.stages:
            if stage.gaps:
                return stage.gaps[0]
        return None


def _format_keyids(keyids: Collection[str]) -> str:
    return ", ".join(sorted(keyids)) or "none"


def _check_root_chain(
    report: HandoverStageReport,
    root: Root,
    root_md: Metadata,
    previous_root: Root | None,
) -> None:
    """Record a gap if the root chain from the previous stage is broken"""
    stage = report.stage
    # trust: root chain from the previous stage must be intact. A stage
    # may re-publish the previous root version (e.g. a rehearsal): then
    # no rotation happens and self-verification is enough.
    chain_root = previous_root
    if previous_root is not None and root.version == previous_root.version:
        chain_root = None
    try:
        chain = root.get_root_verification_result(
            chain_root, root_md.signed_bytes, root_md.signatures
        )
    except ValueError as e:
        report.gaps.append(
            HandoverGap(stage, Root.type, "trust", f"root chain broken: {e}")
        )
    else:
        if not chain.verified:
            missing = chain.first.unsigned.keys() | chain.second.unsigned.keys()
            evidence = (
                f"root v{root.version} verified by "
                f"{len(chain.first.signed)}/{chain.first.threshold} keys of "
                f"the previous root and "
                f"{len(chain.second.signed)}/{chain.second.threshold} keys "
                f"of the current root; missing signatures from keyids: "
                f"{_format_keyids(missing)}"
            )
            report.gaps.append(HandoverGap(stage, Root.type, "trust", evidence))


def _collect_delegators(
    root: Root, metadata: Mapping[str, Metadata]
) -> dict[str, Root | Targets]:
    """Find every role served in a stage and its delegator metadata

    Root delegates the top-level roles, targets metadata delegate the rest.
    """
    delegators: dict[str, Root | Targets] = dict.fromkeys(root.roles, root)
    queue = [Targets.type]
    while queue:
        name = queue.pop(0)
        md = metadata.get(name)
        if md is None or not isinstance(md.signed, Targets):
            continue
        targets: Targets = md.signed
        if targets.delegations is None:
            continue
        for child_name in targets.delegations.roles:
            if child_name not in delegators:
                delegators[child_name] = targets
                queue.append(child_name)

    return delegators


def _check_role(
    report: HandoverStageReport,
    role_name: str,
    delegator: Root | Targets,
    metadata: Mapping[str, Metadata],
    available_keys: Mapping[str, Collection[str]],
) -> None:
    """Record gaps if a role does not verify or has no one to serve it"""
    stage = report.stage
    role = delegator.get_delegated_role(role_name)

    # trust: pending metadata must verify against its delegator
    if role_name != Root.type and role_name in metadata:
        md = metadata[role_name]
        result = delegator.get_verification_result(
            role_name, md.signed_bytes, md.signatures
        )
        if not result.verified:
            evidence = (
                f"{role_name} v{md.signed.version} verified by "
                f"{len(result.signed)}/{result.threshold} required "
                f"keys; missing signatures from keyids: "
                f"{_format_keyids(result.unsigned)}"
            )
            report.gaps.append(HandoverGap(stage, role_name, "trust", evidence))

    # coverage: enough designated keys must still be available
    available = set(available_keys.get(role_name, ()))
    unmanned = [keyid for keyid in role.keyids if keyid not in available]
    staffed = len(role.keyids) - len(unmanned)
    if staffed < role.threshold:
        evidence = (
            f"{role_name} requires {role.threshold} key(s) but only "
            f"{staffed} of {len(role.keyids)} designated key(s) are "
            f"available; unmanned keyids: {_format_keyids(unmanned)}"
        )
        report.gaps.append(HandoverGap(stage, role_name, "coverage", evidence))


def _check_stage(
    stage: str,
    metadata: Mapping[str, Metadata],
    previous_root: Root | None,
    available_keys: Mapping[str, Collection[str]],
) -> tuple[HandoverStageReport, Root | None]:
    """Check a single stage, return its report and the stage root"""
    report = HandoverStageReport(stage)

    root_md = metadata.get(Root.type)
    if root_md is None or not isinstance(root_md.signed, Root):
        report.gaps.append(
            HandoverGap(
                stage, Root.type, "trust", "stage contains no root metadata"
            )
        )
        return report, previous_root
    root: Root = root_md.signed

    _check_root_chain(report, root, root_md, previous_root)

    delegators = _collect_delegators(root, metadata)
    for role_name in sorted(delegators, key=lambda n: (n != Root.type, n)):
        _check_role(
            report, role_name, delegators[role_name], metadata, available_keys
        )

    return report, root


def handover_precheck(
    stages: Mapping[str, Mapping[str, Metadata]],
    available_keys: Mapping[str, Collection[str]],
) -> HandoverReport:
    """Check a staged signing handover plan without modifying it.

    Args:
        stages: Handover stages in order. Each stage maps role names to
            the pending-release metadata (signed with test keys) planned
            for that stage. Every stage should contain root metadata.
        available_keys: Currently available signing keys: maps role names
            to the keyids that can still sign for the role.

    Returns:
        HandoverReport with per-stage results. ``report.first_gap`` is
        the first point in the handover where a role has no one to serve
        it, or None if every stage is fully covered.
    """
    reports = []
    previous_root = None
    for stage, metadata in stages.items():
        report, previous_root = _check_stage(
            stage, metadata, previous_root, available_keys
        )
        reports.append(report)
        logger.debug("Handover stage %s: %d gap(s)", stage, len(report.gaps))
    return HandoverReport(reports)
