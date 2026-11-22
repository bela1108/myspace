"""Offline access-control evidence collection and two-collection comparison.

This module answers a narrow forensic question: given two offline collections
of the same registry hive, did a key actually *change its permissions*, or did
it merely *re-point* at a different security key (``sk``) cell whose security
descriptor carries the identical owner/group/DACL/SACL semantics?

Windows stores a single security descriptor per ``sk`` cell and lets many key
(``nk``) cells reference it. Conclusions are therefore always reported per key
path while the shared descriptor identity is kept explicit, and every row of
the reference-difference table carries the exact in-hive locations of both the
key and the descriptor so the evidence can be jumped back to in either
collection.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from construct import ConstError, StreamError

from regipy.exceptions import RegistryParsingException
from regipy.structs import REGF_HEADER_SIZE

logger = logging.getLogger(__name__)

# Outcome categories (stable, machine-readable constants).
PERMISSION_CHANGED = "permission_changed"
EQUIVALENT_REPOINT = "equivalent_repoint"
UNCHANGED = "unchanged"
UNCOLLECTABLE = "uncollectable"


@dataclass
class SecurityKeyEvidence:
    """Access-control evidence for one key, as found in one collection."""

    sk_offset: int
    sk_cell_offset: int
    sk_file_offset: int
    reference_count: int
    descriptor_bytes: bytes
    owner: str
    group: str
    dacl: list[dict[str, Any]] | None
    sacl: list[dict[str, Any]] | None


# Reasons a key's evidence could not be collected from one side.
REASON_KEY_MISSING = "key_missing"
REASON_DESCRIPTOR_UNPARSEABLE = "descriptor_unparseable"


@dataclass
class SIDProfile:
    """Caller-provided, non-sensitive summary for one trustee SID.

    The library never invents meaning for a SID: profiles are supplied by the
    caller from trusted, sanitized case material. permission_summary is a
    human-readable label attached to evidence rows and reports;
    expected_access_mask optionally lists the exact access mask flags the
    DACL is expected to grant this SID, enabling semantic verification without
    embedding any sensitive principal data in the hive.
    """

    sid: str
    permission_summary: str = ""
    expected_access_mask: list[str] | None = None


@dataclass
class KeySecurityEvidence:
    """All access-control evidence located for one key in one collection."""

    key_path: str
    collection: str
    nk_cell_offset: int
    nk_file_offset: int
    security_key_offset: int
    sk_cell_offset: int
    sk_file_offset: int
    shared_by: list[str] = field(default_factory=list)
    evidence: SecurityKeyEvidence | None = None
    error_reason: str | None = None

    @property
    def collectable(self) -> bool:
        return self.evidence is not None

    def to_dict(self) -> dict[str, Any]:
        return {
            "key_path": self.key_path,
            "collection": self.collection,
            "nk_cell_offset": self.nk_cell_offset,
            "nk_file_offset": self.nk_file_offset,
            "security_key_offset": self.security_key_offset,
            "sk_cell_offset": self.sk_cell_offset,
            "sk_file_offset": self.sk_file_offset,
            "shared_by": list(self.shared_by),
            "evidence": _evidence_to_dict(self.evidence) if self.evidence else None,
            "error_reason": self.error_reason,
        }


@dataclass
class SIDVerification:
    """Result of matching one descriptor against caller-supplied SID profiles."""

    matched: dict[str, SIDProfile] = field(default_factory=dict)
    unverified_sids: list[str] = field(default_factory=list)
    mask_mismatches: list[dict[str, Any]] = field(default_factory=list)

    @property
    def verified(self) -> bool:
        """True only when every SID is profiled and every mask expectation holds."""
        return not self.unverified_sids and not self.mask_mismatches

    def to_dict(self) -> dict[str, Any]:
        return {
            "verified": self.verified,
            "matched": {sid: profile.permission_summary for sid, profile in self.matched.items()},
            "unverified_sids": list(self.unverified_sids),
            "mask_mismatches": list(self.mask_mismatches),
        }


@dataclass
class AccessControlDifference:
    """Per-key conclusion when comparing two offline collections.

    outcome is one of the module-level constants: PERMISSION_CHANGED,
    EQUIVALENT_REPOINT, UNCHANGED or UNCOLLECTABLE. The two
    KeySecurityEvidence objects carry the jump-back locations (NK and SK
    cell offsets) inside each collected hive.
    """

    key_path: str
    outcome: str
    first: KeySecurityEvidence
    second: KeySecurityEvidence
    descriptor_identical: bool
    first_verification: SIDVerification | None = None
    second_verification: SIDVerification | None = None
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "key_path": self.key_path,
            "outcome": self.outcome,
            "detail": self.detail,
            "descriptor_identical": self.descriptor_identical,
            "first": self.first.to_dict(),
            "second": self.second.to_dict(),
            "first_verification": self.first_verification.to_dict() if self.first_verification else None,
            "second_verification": self.second_verification.to_dict() if self.second_verification else None,
        }


@dataclass
class AccessControlDiffReport:
    """Full result of a two-collection access-control comparison."""

    first_collection: str
    second_collection: str
    differences: list[AccessControlDifference] = field(default_factory=list)

    def by_outcome(self, outcome: str) -> list[AccessControlDifference]:
        return [difference for difference in self.differences if difference.outcome == outcome]

    def reference_difference_table(self) -> list[dict[str, Any]]:
        """Flat rows of every key whose SK reference moved or could not be read.

        Each row is self-contained and jump-able back to the key position and
        the descriptor position in either collection, including the list of
        sibling keys sharing the same descriptor.
        """
        rows: list[dict[str, Any]] = []
        for difference in self.differences:
            if difference.outcome == UNCHANGED:
                continue
            rows.append(
                {
                    "key_path": difference.key_path,
                    "outcome": difference.outcome,
                    "first": _reference_row(difference.first),
                    "second": _reference_row(difference.second),
                    "shared_by_first": difference.first.shared_by,
                    "shared_by_second": difference.second.shared_by,
                    "descriptor_identical": difference.descriptor_identical,
                }
            )
        return rows

    def to_dict(self) -> dict[str, Any]:
        return {
            "first_collection": self.first_collection,
            "second_collection": self.second_collection,
            "differences": [difference.to_dict() for difference in self.differences],
            "reference_difference_table": self.reference_difference_table(),
        }


def _evidence_to_dict(evidence: SecurityKeyEvidence) -> dict[str, Any]:
    return {
        "sk_offset": evidence.sk_offset,
        "sk_cell_offset": evidence.sk_cell_offset,
        "sk_file_offset": evidence.sk_file_offset,
        "reference_count": evidence.reference_count,
        "descriptor_hex": evidence.descriptor_bytes.hex(),
        "owner": evidence.owner,
        "group": evidence.group,
        "dacl": evidence.dacl,
        "sacl": evidence.sacl,
    }


def _reference_row(key_evidence: KeySecurityEvidence) -> dict[str, Any]:
    """One side of the reference-difference table, with jump-back locations."""
    row: dict[str, Any] = {
        "key_path": key_evidence.key_path,
        "collection": key_evidence.collection,
        "nk_cell_offset": key_evidence.nk_cell_offset,
        "nk_file_offset": key_evidence.nk_file_offset,
        "sk_cell_offset": key_evidence.sk_cell_offset,
        "sk_file_offset": key_evidence.sk_file_offset,
        "error_reason": key_evidence.error_reason,
    }
    if key_evidence.evidence:
        row["descriptor_hex"] = key_evidence.evidence.descriptor_bytes.hex()
        row["reference_count"] = key_evidence.evidence.reference_count
    return row


def _canonical_aces(aces: list[dict[str, Any]] | None) -> tuple[Any, ...]:
    """Order-independent canonical form of an ACL for semantic comparison."""
    if not aces:
        return ()
    canonical = []
    for ace in aces:
        access_mask = ace.get("access_mask") or {}
        flags = ace.get("flags") or {}
        granted = sorted(flag for flag, enabled in access_mask.items() if enabled)
        ace_flags = sorted(flag for flag, enabled in flags.items() if enabled)
        canonical.append((str(ace.get("ace_type")), str(ace.get("sid")), tuple(granted), tuple(ace_flags)))
    return tuple(sorted(canonical))


def descriptor_semantic_fingerprint(evidence: SecurityKeyEvidence) -> tuple[Any, ...]:
    """Semantic identity of a descriptor: owner, group and canonical ACLs.

    Two descriptors with different binary layout (padding, ACE ordering) but the
    same trustee permissions compare equal here.
    """
    return (
        evidence.owner,
        evidence.group,
        _canonical_aces(evidence.dacl),
        _canonical_aces(evidence.sacl),
    )


def _all_descriptor_sids(evidence: SecurityKeyEvidence) -> list[str]:
    sids = {evidence.owner, evidence.group}
    for acl_name in ("dacl", "sacl"):
        for ace in getattr(evidence, acl_name) or []:
            sids.add(str(ace.get("sid")))
    return sorted(sids)


def verify_descriptor(
    evidence: SecurityKeyEvidence,
    sid_profiles: dict[str, SIDProfile] | None,
) -> SIDVerification:
    """Check a descriptor against the caller-supplied, sanitized SID summaries.

    Profiles never add or hide permissions: they annotate SIDs and optionally
    assert the exact access mask flags a SID is expected to hold. SIDs without
    a profile are reported (not guessed), and the verification only counts as
    verified when every SID is covered and every mask expectation matches.
    """
    profiles = sid_profiles or {}
    verification = SIDVerification()
    for sid in _all_descriptor_sids(evidence):
        profile = profiles.get(sid)
        if profile is None:
            verification.unverified_sids.append(sid)
        else:
            verification.matched[sid] = profile

    for ace in evidence.dacl or []:
        profile = profiles.get(str(ace.get("sid")))
        if profile is None or not profile.expected_access_mask:
            continue
        granted = sorted(flag for flag, enabled in (ace.get("access_mask") or {}).items() if enabled)
        expected = sorted(profile.expected_access_mask)
        if granted != expected:
            verification.mask_mismatches.append(
                {
                    "sid": profile.sid,
                    "permission_summary": profile.permission_summary,
                    "expected": expected,
                    "observed": granted,
                }
            )
    return verification


def collect_key_security_evidence(registry_hive, collection_name: str) -> dict[str, KeySecurityEvidence]:
    """Collect access-control evidence for every key in one offline hive.

    Walks every key once, reads the referenced SK cell per key and groups the
    results by key path. Keys whose SK cell is missing or unparseable are kept
    as uncollectable entries (with the reason) instead of aborting the run, so a
    single corrupted cell never hides the rest of the evidence.
    """
    key_records: dict[str, Any] = {}
    raw_sk_offsets: dict[str, int] = {}
    for subkey in registry_hive.recurse_subkeys(fetch_values=False):
        key_record = registry_hive.get_key(subkey.path)
        key_records[subkey.path] = key_record
        raw_sk_offsets[subkey.path] = int(key_record.header.security_key_offset)

    sharing: dict[int, list[str]] = {}
    for key_path, sk_offset in raw_sk_offsets.items():
        sharing.setdefault(sk_offset, []).append(key_path)

    collected: dict[str, KeySecurityEvidence] = {}
    for key_path, key_record in key_records.items():
        sk_offset = raw_sk_offsets[key_path]
        nk_cell_offset = int(getattr(key_record, "cell_offset", -1))
        base = REGF_HEADER_SIZE
        row = KeySecurityEvidence(
            key_path=key_path,
            collection=collection_name,
            nk_cell_offset=nk_cell_offset,
            nk_file_offset=base + nk_cell_offset if nk_cell_offset >= 0 else -1,
            security_key_offset=sk_offset,
            sk_cell_offset=sk_offset - 4,
            sk_file_offset=base + sk_offset - 4,
            shared_by=sorted(sharing.get(sk_offset, [])),
        )
        try:
            row.evidence = key_record.get_security_evidence()
        except (RegistryParsingException, ConstError, StreamError) as ex:
            logger.warning("Access-control evidence uncollectable for %s: %s", key_path, ex)
            row.error_reason = REASON_DESCRIPTOR_UNPARSEABLE
        collected[key_path] = row
    return collected


def _missing_key_evidence(key_path: str, collection_name: str) -> KeySecurityEvidence:
    return KeySecurityEvidence(
        key_path=key_path,
        collection=collection_name,
        nk_cell_offset=-1,
        nk_file_offset=-1,
        security_key_offset=-1,
        sk_cell_offset=-1,
        sk_file_offset=-1,
        error_reason=REASON_KEY_MISSING,
    )


def compare_access_control(
    first_hive,
    second_hive,
    sid_profiles: dict[str, SIDProfile | dict[str, Any]] | None = None,
    first_collection_name: str = "first_collection",
    second_collection_name: str = "second_collection",
) -> AccessControlDiffReport:
    """Compare access-control evidence between two offline hive collections.

    :param first_hive: A RegistryHive instance (Python or Rust backend) or
                       a path to the first collected hive file.
    :param second_hive: The second collected hive, same forms as first_hive.
    :param sid_profiles: Optional mapping of SID to SIDProfile (or plain dicts
                       with the same fields) supplied by the caller. These
                       are the only source of SID semantics; nothing about the
                       trustees is guessed.
    :param first_collection_name: Label used in every jump-back row for hive one.
    :param second_collection_name: Label used in every jump-back row for hive two.
    :return: An AccessControlDiffReport whose per-key outcomes separate
             real permission changes from equivalent re-points and uncollectable
             evidence.
    """
    first_registry = _coerce_hive(first_hive)
    second_registry = _coerce_hive(second_hive)
    profiles = _coerce_profiles(sid_profiles)

    first_evidence = collect_key_security_evidence(first_registry, first_collection_name)
    second_evidence = collect_key_security_evidence(second_registry, second_collection_name)

    report = AccessControlDiffReport(
        first_collection=first_collection_name,
        second_collection=second_collection_name,
    )
    all_paths = sorted(set(first_evidence) | set(second_evidence))
    for key_path in all_paths:
        first_row = first_evidence.get(key_path) or _missing_key_evidence(key_path, first_collection_name)
        second_row = second_evidence.get(key_path) or _missing_key_evidence(key_path, second_collection_name)
        report.differences.append(_classify_key(key_path, first_row, second_row, profiles))
    return report


def _classify_key(
    key_path: str,
    first_row: KeySecurityEvidence,
    second_row: KeySecurityEvidence,
    profiles: dict[str, SIDProfile],
) -> AccessControlDifference:
    if not first_row.collectable or not second_row.collectable:
        reasons = [row.error_reason for row in (first_row, second_row) if row.error_reason]
        return AccessControlDifference(
            key_path=key_path,
            outcome=UNCOLLECTABLE,
            first=first_row,
            second=second_row,
            descriptor_identical=False,
            detail=f"Evidence not collectable: {', '.join(reasons)}",
        )

    first_descriptor = first_row.evidence
    second_descriptor = second_row.evidence
    assert first_descriptor is not None and second_descriptor is not None

    first_verification = verify_descriptor(first_descriptor, profiles)
    second_verification = verify_descriptor(second_descriptor, profiles)

    # Backends that do not expose raw descriptor bytes (e.g. the Rust wrapper)
    # hand back empty bytes; in that case fall back to semantic identity rather
    # than reporting two empty blobs as byte-identical.
    raw_bytes_available = bool(first_descriptor.descriptor_bytes) and bool(second_descriptor.descriptor_bytes)
    bytes_identical = first_descriptor.descriptor_bytes == second_descriptor.descriptor_bytes if raw_bytes_available else False
    semantics_equal = descriptor_semantic_fingerprint(first_descriptor) == descriptor_semantic_fingerprint(second_descriptor)

    if semantics_equal:
        if first_row.security_key_offset == second_row.security_key_offset and bytes_identical:
            outcome = UNCHANGED
            detail = "Same SK reference and identical security descriptor"
        else:
            outcome = EQUIVALENT_REPOINT
            if first_row.security_key_offset != second_row.security_key_offset:
                detail = "SK reference moved to a descriptor with identical owner/group/ACL semantics"
            else:
                detail = "Same SK reference; descriptor bytes differ but owner/group/ACL semantics are identical"
    else:
        outcome = PERMISSION_CHANGED
        detail = _describe_permission_change(first_descriptor, second_descriptor)

    return AccessControlDifference(
        key_path=key_path,
        outcome=outcome,
        first=first_row,
        second=second_row,
        descriptor_identical=bytes_identical,
        first_verification=first_verification,
        second_verification=second_verification,
        detail=detail,
    )


def _describe_permission_change(first: SecurityKeyEvidence, second: SecurityKeyEvidence) -> str:
    changes = []
    if first.owner != second.owner:
        changes.append(f"owner {first.owner} -> {second.owner}")
    if first.group != second.group:
        changes.append(f"group {first.group} -> {second.group}")
    first_dacl = _canonical_aces(first.dacl)
    second_dacl = _canonical_aces(second.dacl)
    if first_dacl != second_dacl:
        removed = sorted(set(first_dacl) - set(second_dacl))
        added = sorted(set(second_dacl) - set(first_dacl))
        if removed:
            changes.append(f"removed ACEs: {_format_ace_changes(removed)}")
        if added:
            changes.append(f"added ACEs: {_format_ace_changes(added)}")
    first_sacl = _canonical_aces(first.sacl)
    second_sacl = _canonical_aces(second.sacl)
    if first_sacl != second_sacl:
        changes.append("SACL semantics changed")
    return "; ".join(changes) if changes else "Security descriptor semantics changed"


def _format_ace_changes(aces: Sequence[tuple[Any, ...]]) -> str:
    return ", ".join(f"{ace_type}:{sid}" for ace_type, sid, _, _ in aces)


def _coerce_hive(hive_or_path) -> Any:
    if isinstance(hive_or_path, (str, bytes, os.PathLike)):
        from regipy.registry import RegistryHive

        return RegistryHive(os.fspath(hive_or_path))
    return hive_or_path


def _coerce_profiles(
    profiles: dict[str, SIDProfile | dict[str, Any]] | None,
) -> dict[str, SIDProfile]:
    coerced: dict[str, SIDProfile] = {}
    for sid, profile in (profiles or {}).items():
        if isinstance(profile, SIDProfile):
            coerced[sid] = profile
        else:
            coerced[sid] = SIDProfile(
                sid=sid,
                permission_summary=str(profile.get("permission_summary", "")),
                expected_access_mask=profile.get("expected_access_mask"),
            )
    return coerced
