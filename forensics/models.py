"""Data model for the offline TUF statement cross-check.

The vocabulary used here mirrors the forensic task rather than the TUF
wireline format:

* a "party" is one of the two mirrors that handed in signed metadata,
* a "statement" is a target file description (length and content hashes)
  found inside a verified targets role,
* a "verdict" is the per-target result of comparing the two parties.

A verdict can only be ``CONFLICT`` when both parties produced a statement
that independently verified against their own trusted root. If one side
cannot provide or verify a statement, the verdict stays ``UNDECIDED``:
missing evidence and a broken trust chain never prove a disagreement.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Verdict constants. Kept as plain strings so the JSON report is stable.
CONSISTENT = "consistent"
CONFLICT = "conflict"
UNDECIDED = "undecided"

VERDICTS = (CONSISTENT, CONFLICT, UNDECIDED)

# Machine-readable reasons attached to undecided and conflict verdicts.
REASON_MISSING = "missing_on_one_side"
REASON_TRUST = "unverified_on_one_side"
REASON_OUT_OF_SCOPE = "not_in_both_scopes"
REASON_HASH = "hash_mismatch"
REASON_LENGTH = "length_mismatch"
REASON_CUSTOM = "custom_field_mismatch"


@dataclass(frozen=True)
class Evidence:
    """Pointer back to the original signed metadata a statement came from.

    The evidence references the file as collected on disk and records the
    file's sha256 so that the "two originals" behind a proven conflict can be
    located and re-opened without relying on this tool.
    """

    metadata_file: str
    role: str
    metadata_sha256: str
    metadata_version: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "metadata_file": self.metadata_file,
            "role": self.role,
            "metadata_sha256": self.metadata_sha256,
            "metadata_version": self.metadata_version,
        }


@dataclass(frozen=True)
class Statement:
    """One independently verified release statement about a target path."""

    target_path: str
    length: int
    hashes: dict[str, str]
    evidence: Evidence
    custom: Any = None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "target_path": self.target_path,
            "length": self.length,
            "hashes": self.hashes,
            "evidence": self.evidence.to_dict(),
        }
        if self.custom is not None:
            data["custom"] = self.custom
        return data


@dataclass
class TargetVerdict:
    """Comparison result for a single target path."""

    target_path: str
    verdict: str
    reasons: list[str] = field(default_factory=list)
    statements: dict[str, Statement] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_path": self.target_path,
            "verdict": self.verdict,
            "reasons": self.reasons,
            "statements": {
                party: statement.to_dict()
                for party, statement in sorted(self.statements.items())
            },
        }


@dataclass
class PartyResult:
    """Outcome of verifying one party's bundle against its own root."""

    party: str
    root_file: str
    verified: bool
    statements: dict[str, Statement] = field(default_factory=dict)
    verified_roles: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    scope: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "party": self.party,
            "root_file": self.root_file,
            "verified": self.verified,
            "scope": self.scope,
            "verified_roles": self.verified_roles,
            "errors": self.errors,
            "warnings": self.warnings,
            "statement_count": len(self.statements),
        }


@dataclass
class CrosscheckReport:
    """Aggregate result of :func:`forensics.crosscheck.run_crosscheck`."""

    parties: dict[str, PartyResult]
    verdicts: list[TargetVerdict]
    offline: bool = True

    @property
    def conflicts(self) -> list[TargetVerdict]:
        return [v for v in self.verdicts if v.verdict == CONFLICT]

    @property
    def undecided(self) -> list[TargetVerdict]:
        return [v for v in self.verdicts if v.verdict == UNDECIDED]

    @property
    def consistent(self) -> list[TargetVerdict]:
        return [v for v in self.verdicts if v.verdict == CONSISTENT]

    def to_dict(self) -> dict[str, Any]:
        counts = {verdict: 0 for verdict in VERDICTS}
        for verdict in self.verdicts:
            counts[verdict.verdict] += 1
        return {
            "offline": self.offline,
            "summary": {
                "parties": len(self.parties),
                "targets_compared": len(self.verdicts),
                "conflicts": counts[CONFLICT],
                "undecided": counts[UNDECIDED],
                "consistent": counts[CONSISTENT],
            },
            "parties": {
                party: result.to_dict()
                for party, result in sorted(self.parties.items())
            },
            "verdicts": [verdict.to_dict() for verdict in self.verdicts],
        }


@dataclass(frozen=True)
class PartyInput:
    """All locally saved material handed in by one party.

    Attributes:
        party: Short identifier used in the report (e.g. ``"alpha"``).
        root: Path to the root metadata the party itself vouches for.
        metadata_dir: Directory with the saved role metadata files
            (``root.json``, ``timestamp.json``, ``snapshot.json``,
            ``targets.json`` and any delegated ``*.json`` roles).
        scope: Target path patterns the party claims to have observed. Only
            targets matching the scope on both sides are compared.
    """

    party: str
    root: Path
    metadata_dir: Path
    scope: tuple[str, ...]
