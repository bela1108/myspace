# Copyright 2026, the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Offline export planner for a TUF repository.

The planner answers a narrow, offline question: given the repository's
existing role metadata, the target hit conditions (the TUF delegation graph)
and a caller-supplied *transferable* manifest, which is the *minimal* set of
signed role files that an offline review group needs in order to re-verify a
collection of target paths?

The module never reaches out to a network and never signs, re-aliases or
fabricates metadata. A role whose signed file cannot be handed over (or whose
signature threshold cannot be proven from the delivered material) is reported
as an explicit gap: it is never replaced by an unsigned alias or by an
arbitrary digest.

The result has two parts:

* ``roles``: the de-duplicated, hand-off ready role files that together prove
  everything that *can* be proven, and
* ``gaps``: the structured "no-proof range" describing which target paths
  cannot be fully re-verified offline and why.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Protocol
from urllib import parse

from tuf.api.metadata import (
    Metadata,
    Root,
    Snapshot,
    SuccinctRoles,
    Targets,
    Timestamp,
)

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence


class GapReason(str, Enum):
    """Why a target path cannot be fully proven from the hand-off material."""

    #: The signed role file is not present in the transferable manifest.
    ROLE_NOT_TRANSFERABLE = "role_not_transferable"
    #: The role bytes in the manifest cannot be parsed as TUF metadata.
    ROLE_UNREADABLE = "role_unreadable"
    #: The delegating role does not describe how to verify this child role.
    DELEGATION_MISSING = "delegation_missing"
    #: The delivered signatures do not meet the delegated role threshold.
    THRESHOLD_UNMET = "threshold_unmet"
    #: The role snapshot entry (version / hash anchor) is missing.
    NOT_IN_SNAPSHOT = "not_in_snapshot"
    #: The traversal hit the configured delegation depth limit.
    DELEGATION_LIMIT = "delegation_limit"
    #: No role on the traversed graph claims the target path.
    TARGET_NOT_FOUND = "target_not_found"


@dataclass
class RoleRequirement:
    """A role file that is required on the verification chain.

    Attributes:
        role: TUF role name (``"targets"`` or a delegated role name).
        delegator: Role that delegates and verifies ``role``; ``"root"`` for
            the top-level roles.
        filename: Canonical metadata file name used in the hand-off bundle.
        proves_targets: Target paths whose lookup depends on this role.
    """

    role: str
    delegator: str
    filename: str
    proves_targets: set[str] = field(default_factory=set)


@dataclass(frozen=True)
class Gap:
    """A single unprovable target path together with the blocking role."""

    target_path: str
    role: str
    delegator: str
    reason: GapReason
    detail: str


@dataclass
class ExportPlan:
    """The hand-off description for one or more target lookup requests.

    Attributes:
        roles: Minimal, de-duplicated role files required for verification,
            restricted to roles that are actually deliverable.
        gaps: Structured no-proof range. Every target path that cannot be
            fully re-verified from ``roles`` appears at least once.
        requested_targets: Target paths the planner was asked about.
        proven_targets: Subset of requested targets with a complete, signed
            and snapshot-anchored verification chain.
    """

    roles: list[RoleRequirement] = field(default_factory=list)
    gaps: list[Gap] = field(default_factory=list)
    requested_targets: frozenset[str] = frozenset()
    proven_targets: frozenset[str] = frozenset()

    @property
    def unproven_targets(self) -> frozenset[str]:
        """Requested target paths that have at least one open gap."""
        return frozenset(gap.target_path for gap in self.gaps)

    def role_names(self) -> list[str]:
        """Return the ordered de-duplicated role names in the plan."""
        seen: set[str] = set()
        ordered: list[str] = []
        for requirement in self.roles:
            if requirement.role not in seen:
                seen.add(requirement.role)
                ordered.append(requirement.role)
        return ordered

    def to_dict(self) -> dict:
        """Serialize the plan to a JSON-friendly hand-off description."""
        return {
            "requested_targets": sorted(self.requested_targets),
            "proven_targets": sorted(self.proven_targets),
            "unproven_targets": sorted(self.unproven_targets),
            "roles": [
                {
                    "role": requirement.role,
                    "delegator": requirement.delegator,
                    "filename": requirement.filename,
                    "proves_targets": sorted(requirement.proves_targets),
                }
                for requirement in self.roles
            ],
            "gaps": [
                {
                    "target_path": gap.target_path,
                    "role": gap.role,
                    "delegator": gap.delegator,
                    "reason": gap.reason.value,
                    "detail": gap.detail,
                }
                for gap in self.gaps
            ],
        }

class MetadataSource(Protocol):
    """Read-only access to the repository existing, signed role files.

    Implementations serve the canonical on-disk metadata bytes (for example a
    read-only view of the repository metadata directories). The planner
    treats this as the source of truth for the delegation graph and for
    signature material; it never mutates it.
    """

    def role_bytes(self, role: str) -> bytes | None:
        """Return the signed metadata bytes for ``role`` or ``None``."""

    def has_role(self, role: str) -> bool:
        """Return whether signed metadata exists for ``role``."""


class TransferManifest:
    """Caller-supplied manifest of role files that may be handed over.

    The manifest is an allow-list: only roles listed here are considered
    transferable. Omitting a role (or withholding it) means the signed
    material for that role is *not* deliverable. The planner must not work
    around such a hole with an unsigned alias or a free-form digest.
    """

    def __init__(self, transferable: Iterable[str] | None = None) -> None:
        self._transferable: set[str] = set(transferable or [])

    @classmethod
    def top_level(cls) -> "TransferManifest":
        """Build a manifest containing only the four top-level role names."""
        return cls([Root.type, Timestamp.type, Snapshot.type, Targets.type])

    def permit(self, role: str) -> "TransferManifest":
        """Mark ``role`` as transferable and return the manifest."""
        self._transferable.add(role)
        return self

    def withhold(self, role: str) -> "TransferManifest":
        """Mark ``role`` as not deliverable and return the manifest."""
        self._transferable.discard(role)
        return self

    def is_transferable(self, role: str) -> bool:
        """Return whether the signed role file may be handed over."""
        return role in self._transferable

    def __contains__(self, role: object) -> bool:
        return isinstance(role, str) and role in self._transferable

class DictMetadataSource:
    """An in-memory :class:`MetadataSource` backed by signed role bytes."""

    def __init__(self, role_files: dict[str, bytes] | None = None) -> None:
        self._role_files: dict[str, bytes] = dict(role_files or {})

    def add(self, role: str, data: bytes) -> "DictMetadataSource":
        """Store signed metadata ``data`` for ``role`` and return self."""
        self._role_files[role] = data
        return self

    def has_role(self, role: str) -> bool:
        return role in self._role_files

    def role_bytes(self, role: str) -> bytes | None:
        return self._role_files.get(role)

class OfflineExportPlanner:
    """Compute the minimal hand-off set for offline target re-verification.

    The planner is fully offline: it only reads the supplied
    :class:`MetadataSource` and the caller :class:`TransferManifest`. It
    mirrors the TUF client delegation walk (preorder, depth-first, in
    delegation order) and the same signature threshold and snapshot anchor
    rules, but instead of downloading anything it records the smallest set
    of signed role files that the review group must receive.
    """

    def __init__(
        self,
        source: MetadataSource,
        manifest: TransferManifest,
        *,
        max_delegations: int = 64,
    ) -> None:
        self._source = source
        self._manifest = manifest
        self._max_delegations = max_delegations
        self._parsed: dict[
            str,
            Metadata[Targets] | Metadata[Root]
            | Metadata[Snapshot] | Metadata[Timestamp],
        ] = {}
        self._parse_errors: dict[str, Exception] = {}

    @staticmethod
    def filename_for(role: str) -> str:
        """Return the canonical, URL-encoded metadata file name."""
        return f"{parse.quote(role, "")}.json"

    def _load(self, role: str) -> Metadata | None:
        """Parse and cache the delivered metadata for ``role``.

        Parsing happens on the *delivered* bytes only: nothing is fetched
        and nothing is regenerated. A parse failure is cached so that the
        same unreadable role is reported consistently.
        """
        if role in self._parsed:
            return self._parsed[role]
        data = self._source.role_bytes(role)
        if data is None:
            return None
        try:
            metadata = Metadata.from_bytes(data)
        except Exception as exc:  # noqa: BLE001 - surface any parse failure
            self._parse_errors[role] = exc
            return None
        self._parsed[role] = metadata
        return metadata

    def _snapshot_anchors(self, role: str) -> bool:
        """Return whether snapshot pins ``role`` by version and hashes."""
        snapshot_md = self._load(Snapshot.type)
        if not isinstance(snapshot_md, Metadata):
            return False
        snapshot = snapshot_md.signed
        if not isinstance(snapshot, Snapshot):
            return False
        return f"{role}.json" in snapshot.meta

    def _threshold_proven(
        self,
        role: str,
        delegator_name: str,
        child: Metadata,
    ) -> tuple[bool, str]:
        """Re-check the signature threshold from delivered material only.

        Returns ``(ok, detail)``. The check uses the delegating role keys
        and threshold exactly as ``TrustedMetadataSet`` would, so an
        under-signed file is detected rather than silently accepted.
        """
        delegator_md = self._load(delegator_name)
        if delegator_md is None:
            return False, f"delegator {delegator_name} material missing"
        delegator = delegator_md.signed
        try:
            result = delegator.get_verification_result(
                role, child.signed_bytes, child.signatures
            )
        except ValueError as exc:
            return False, str(exc)
        if result:
            return True, "threshold met"
        missing = result.threshold - len(result.signed)
        return (
            False,
            f"{len(result.signed)}/{result.threshold} valid signatures, "
            f"need {missing} more",
        )

    def _gate_role(
        self,
        role: str,
        delegator: str,
        target_path: str,
    ) -> tuple[Metadata[Targets] | None, Gap | None]:
        """Return the parsed targets metadata for ``role`` or a gap.

        The gate never substitutes anything for missing material:

        * a role withheld from the manifest is a hard gap;
        * unparseable bytes are a gap, not an unsigned stand-in;
        * a threshold that cannot be proven is a gap, not a digest claim;
        * a role absent from snapshot.meta cannot be version-anchored.
        """
        if not self._manifest.is_transferable(role):
            return None, Gap(
                target_path, role, delegator,
                GapReason.ROLE_NOT_TRANSFERABLE,
                f"signed {role}.json is not in the transferable manifest",
            )

        metadata = self._load(role)
        if metadata is None:
            reason = GapReason.ROLE_UNREADABLE
            detail = f"{role}.json could not be parsed as TUF metadata"
            if role in self._parse_errors:
                detail = f"{detail}: {self._parse_errors[role]}"
            return None, Gap(target_path, role, delegator, reason, detail)

        if not isinstance(metadata.signed, Targets):
            return None, Gap(
                target_path, role, delegator, GapReason.ROLE_UNREADABLE,
                f"{role}.json signed type is {metadata.signed._type}, "
                "expected targets",
            )

        if delegator != Root.type:
            delegator_md = self._load(delegator)
            delegator_signed = (
                delegator_md.signed if delegator_md is not None else None
            )
            if not isinstance(delegator_signed, Targets):
                return None, Gap(
                    target_path, role, delegator,
                    GapReason.DELEGATION_MISSING,
                    f"delegator {delegator} has no targets material",
                )
            try:
                delegator_signed.get_delegated_role(role)
            except ValueError:
                return None, Gap(
                    target_path, role, delegator,
                    GapReason.DELEGATION_MISSING,
                    f"{delegator} does not delegate {role}",
                )

        ok, detail = self._threshold_proven(role, delegator, metadata)
        if not ok:
            return None, Gap(
                target_path, role, delegator,
                GapReason.THRESHOLD_UNMET, detail,
            )

        if not self._snapshot_anchors(role):
            return None, Gap(
                target_path, role, delegator,
                GapReason.NOT_IN_SNAPSHOT,
                f"snapshot.meta has no {role}.json entry",
            )

        return metadata, None

    def _matching_children(
        self, delegator: Targets, target_path: str
    ) -> list[tuple[str, bool]]:
        """Replicate Delegations.get_roles_for_target hit conditions."""
        if delegator.delegations is None:
            return []
        delegations = delegator.delegations
        if delegations.roles is not None:
            matched: list[tuple[str, bool]] = []
            for child in delegations.roles.values():
                if child.is_delegated_path(target_path):
                    matched.append((child.name, child.terminating))
            return matched
        succinct: SuccinctRoles = delegations.succinct_roles
        return [(succinct.get_role_for_target(target_path), True)]

    def _walk_target(
        self, target_path: str
    ) -> tuple[list[RoleRequirement], list[Gap], bool]:
        """Walk the delegation graph for one target path.

        Mirrors Updater preorder depth-first traversal in delegation order,
        honouring terminating delegations. Returns the roles visited along
        the lookup, any gaps encountered, and whether the target was claimed.
        """
        requirements: list[RoleRequirement] = []
        gaps: list[Gap] = []
        visited: set[str] = set()
        stack: list[tuple[str, str]] = [(Targets.type, Root.type)]
        delegations_seen = 0

        while stack:
            role_name, parent_role = stack.pop()
            if role_name in visited:
                continue
            visited.add(role_name)

            metadata, gap = self._gate_role(role_name, parent_role, target_path)
            if gap is not None:
                gaps.append(gap)
                if gap.reason is GapReason.ROLE_NOT_TRANSFERABLE:
                    break
                continue

            requirements.append(
                RoleRequirement(
                    role_name,
                    parent_role,
                    self.filename_for(role_name),
                    {target_path},
                )
            )

            if target_path in metadata.signed.targets:
                return requirements, gaps, True

            children = self._matching_children(metadata.signed, target_path)
            if not children:
                continue
            terminating = any(flag for _, flag in children)
            for child_name, _flag in reversed(children):
                delegations_seen += 1
                if delegations_seen > self._max_delegations:
                    gaps.append(Gap(
                        target_path, child_name, role_name,
                        GapReason.DELEGATION_LIMIT,
                        f"exceeded max_delegations={self._max_delegations}",
                    ))
                    break
                stack.append((child_name, role_name))
            if terminating:
                break

        return requirements, gaps, False

    def _gate_anchor(self, role: str, target_path: str) -> Gap | None:
        """Verify a top-level anchor (root/timestamp/snapshot) is deliverable.

        Root is the offline trust anchor and only needs to be present and
        parseable. Timestamp and snapshot additionally must prove their
        signature threshold against the delivered root keys.
        """
        if not self._manifest.is_transferable(role):
            return Gap(
                target_path, role, Root.type,
                GapReason.ROLE_NOT_TRANSFERABLE,
                f"signed {role}.json is not in the transferable manifest",
            )
        metadata = self._load(role)
        if metadata is None:
            detail = f"{role}.json could not be parsed as TUF metadata"
            if role in self._parse_errors:
                detail = f"{detail}: {self._parse_errors[role]}"
            return Gap(target_path, role, Root.type,
                       GapReason.ROLE_UNREADABLE, detail)
        ok, threshold_detail = self._threshold_proven(
            role, Root.type, metadata
        )
        if not ok:
            return Gap(target_path, role, Root.type,
                       GapReason.THRESHOLD_UNMET, threshold_detail)
        return None

    def plan(self, target_paths: Sequence[str]) -> ExportPlan:
        """Build the minimal hand-off plan for ``target_paths``.

        Multiple requests share one top-level chain: anchor roles are added
        once, and per-target delegated chains are unioned so a common parent
        role is handed over a single time. A target whose chain cannot be
        fully delivered stays in the no-proof range instead of weakening the
        requirements for the targets that can be proven.
        """
        requested = frozenset(target_paths)
        ordered_targets = list(dict.fromkeys(target_paths))
        plan = ExportPlan(requested_targets=requested)
        gap_keys: set[tuple[str, str, GapReason]] = set()
        proven: set[str] = set()

        def add_gap(gap: Gap) -> None:
            key = (gap.target_path, gap.role, gap.reason)
            if key not in gap_keys:
                gap_keys.add(key)
                plan.gaps.append(gap)

        anchor_order = (Root.type, Timestamp.type, Snapshot.type)
        anchors_ok = True
        representative = next(iter(requested), "")
        for anchor in anchor_order:
            anchor_gap = self._gate_anchor(anchor, representative)
            if anchor_gap is not None:
                anchors_ok = False
                for target_path in ordered_targets:
                    add_gap(
                        Gap(
                            target_path,
                            anchor_gap.role,
                            anchor_gap.delegator,
                            anchor_gap.reason,
                            anchor_gap.detail,
                        )
                    )

        merged: dict[str, RoleRequirement] = {}

        def require(requirement: RoleRequirement) -> None:
            existing = merged.get(requirement.role)
            if existing is None:
                merged[requirement.role] = RoleRequirement(
                    requirement.role,
                    requirement.delegator,
                    requirement.filename,
                    set(requirement.proves_targets),
                )
            else:
                merged[requirement.role].proves_targets.update(
                    requirement.proves_targets
                )

        if anchors_ok:
            for anchor in anchor_order:
                require(RoleRequirement(anchor, Root.type,
                                       self.filename_for(anchor)))
            for target_path in ordered_targets:
                chain, target_gaps, claimed = self._walk_target(target_path)
                for gap in target_gaps:
                    add_gap(gap)
                if claimed and not any(
                    gap.target_path == target_path for gap in target_gaps
                ):
                    for requirement in chain:
                        require(requirement)
                    proven.add(target_path)
                elif not claimed and not target_gaps:
                    add_gap(Gap(
                        target_path, Targets.type, Root.type,
                        GapReason.TARGET_NOT_FOUND,
                        "no delegated role claims the target path",
                    ))

        plan.roles = list(merged.values())
        plan.proven_targets = frozenset(proven)
        return plan

    def materialize(self, plan: ExportPlan, output_dir: str) -> dict[str, str]:
        """Write the hand-off bundle for ``plan`` into ``output_dir``.

        Only roles that passed the gate are copied, byte-for-byte, from the
        delivered source: the method never emits an unsigned alias or a
        digest in place of a withheld role. A machine-readable ``plan.json``
        records both the role list and the no-proof range. Returns the map
        of role name to written file path.
        """
        from json import dumps
        from pathlib import Path

        destination = Path(output_dir)
        destination.mkdir(parents=True, exist_ok=True)
        written: dict[str, str] = {}
        for requirement in plan.roles:
            data = self._source.role_bytes(requirement.role)
            if data is None:
                continue
            target = destination / requirement.filename
            target.write_bytes(data)
            written[requirement.role] = str(target)
        (destination / "plan.json").write_text(
            dumps(plan.to_dict(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return written
