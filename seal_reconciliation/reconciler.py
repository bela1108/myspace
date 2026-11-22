"""Offline seal-usage reconciliation engine.

The engine works on three local inputs only, so no network access is needed:

* the authorization ledger (who may settle which number interval per
  category, including the half-segment handed to a substitute);
* a public-key registry keyed by key id;
* the archived signed seal statements (primary archive plus backup volume).

Accounting rules implemented here:

* numbers may repeat across statement categories but a settled number can be
  accounted to exactly one usage within a single category;
* identical signed material re-appearing in a backup is counted once;
* different material sharing one (category, number) pair is a collision and
  the number is proposed for freezing, with both original locations reported;
* signatures are verified with securesystemslib before anything is counted;
* every counted usage must fall inside an authorization interval, and the
  signing key must belong to the authorized officer.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from securesystemslib.exceptions import (
    UnverifiedSignatureError,
    VerificationError,
)
from securesystemslib.signer import Key

from seal_reconciliation.models import Authorization, SealStatement


@dataclass(frozen=True)
class Usage:
    """One uniquely accounted seal usage."""

    category: str
    seal_number: int
    material_digest: str
    officer_id: str
    keyid: str
    sources: tuple[str, ...]


@dataclass(frozen=True)
class Collision:
    """A (category, number) pair claimed by materially different statements.

    Attributes:
        category: Statement category in which the conflict occurs.
        seal_number: Seal number that must be frozen pending review.
        material_digests: Distinct material digests sharing the number.
        sources: Locations of every original impression involved.
        keyids: Signing key ids involved in the conflict.
    """

    category: str
    seal_number: int
    material_digests: tuple[str, ...]
    sources: tuple[str, ...]
    keyids: tuple[str, ...]


@dataclass(frozen=True)
class InvalidSignature:
    """A statement whose securesystemslib signature check failed."""

    statement_id: str
    category: str
    seal_number: int
    source: str
    reason: str


@dataclass(frozen=True)
class AuthorizationInterval:
    """Finance-facing view of one granted interval and its consumption."""

    officer_id: str
    category: str
    start: int
    end: int
    note: str
    used_numbers: tuple[int, ...]

    @property
    def interval(self) -> str:
        return f"[{self.start}, {self.end}]"


@dataclass
class ReconciliationReport:
    """Result container covering the finance page and the security page."""

    authorizations: tuple[AuthorizationInterval, ...]
    usages: tuple[Usage, ...]
    collisions: tuple[Collision, ...]
    invalid_signatures: tuple[InvalidSignature, ...]
    out_of_range: tuple[Usage, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {
            "authorizations": [
                {
                    "officer_id": item.officer_id,
                    "category": item.category,
                    "interval": item.interval,
                    "start": item.start,
                    "end": item.end,
                    "note": item.note,
                    "used_numbers": list(item.used_numbers),
                }
                for item in self.authorizations
            ],
            "usages": [
                {
                    "category": usage.category,
                    "seal_number": usage.seal_number,
                    "material_digest": usage.material_digest,
                    "officer_id": usage.officer_id,
                    "keyid": usage.keyid,
                    "sources": list(usage.sources),
                }
                for usage in self.usages
            ],
            "freeze_candidates": [
                {
                    "category": collision.category,
                    "seal_number": collision.seal_number,
                    "material_digests": list(collision.material_digests),
                    "sources": list(collision.sources),
                    "keyids": list(collision.keyids),
                }
                for collision in self.collisions
            ],
            "invalid_signatures": [
                {
                    "statement_id": item.statement_id,
                    "category": item.category,
                    "seal_number": item.seal_number,
                    "source": item.source,
                    "reason": item.reason,
                }
                for item in self.invalid_signatures
            ],
            "out_of_range": [
                {
                    "category": usage.category,
                    "seal_number": usage.seal_number,
                    "material_digest": usage.material_digest,
                    "officer_id": usage.officer_id,
                    "keyid": usage.keyid,
                    "sources": list(usage.sources),
                }
                for usage in self.out_of_range
            ],
        }


class Reconciler:
    """Reconcile archived seal statements against the authorization ledger."""

    def __init__(
        self,
        authorizations: list[Authorization],
        key_registry: dict[str, Key],
    ) -> None:
        self._authorizations = tuple(authorizations)
        self._key_registry = dict(key_registry)
        self._auth_by_category: dict[str, list[Authorization]] = defaultdict(list)
        for authorization in self._authorizations:
            self._auth_by_category[authorization.category].append(authorization)

    def reconcile(
        self, statements: list[SealStatement]
    ) -> ReconciliationReport:
        verified, invalid = self._verify(statements)
        usages, collisions = self._deduplicate(verified)
        in_range, out_of_range = self._check_authorization(usages)
        intervals = self._build_intervals(in_range)
        return ReconciliationReport(
            authorizations=intervals,
            usages=tuple(in_range),
            collisions=tuple(collisions),
            invalid_signatures=tuple(invalid),
            out_of_range=tuple(out_of_range),
        )

    def _verify(
        self, statements: list[SealStatement]
    ) -> tuple[list[SealStatement], list[InvalidSignature]]:
        valid: list[SealStatement] = []
        invalid: list[InvalidSignature] = []
        for statement in statements:
            key = self._key_registry.get(statement.keyid)
            if key is None:
                invalid.append(
                    InvalidSignature(
                        statement_id=statement.statement_id,
                        category=statement.category,
                        seal_number=statement.seal_number,
                        source=str(statement.source),
                        reason=f"unknown keyid {statement.keyid}",
                    )
                )
                continue
            try:
                key.verify_signature(
                    statement.signature, statement.canonical_payload()
                )
            except (UnverifiedSignatureError, VerificationError) as error:
                invalid.append(
                    InvalidSignature(
                        statement_id=statement.statement_id,
                        category=statement.category,
                        seal_number=statement.seal_number,
                        source=str(statement.source),
                        reason=str(error),
                    )
                )
                continue
            valid.append(statement)
        return valid, invalid

    def _deduplicate(
        self, statements: list[SealStatement]
    ) -> tuple[list[Usage], list[Collision]]:
        # Group everything that claims the same (category, seal_number) pair.
        claims: dict[tuple[str, int], list[SealStatement]] = defaultdict(list)
        for statement in statements:
            claims[(statement.category, statement.seal_number)].append(statement)

        usages: list[Usage] = []
        collisions: list[Collision] = []
        for (category, seal_number), group in sorted(claims.items()):
            digests = sorted({item.material_digest for item in group})
            if len(digests) > 1:
                collisions.append(
                    Collision(
                        category=category,
                        seal_number=seal_number,
                        material_digests=tuple(digests),
                        sources=tuple(
                            sorted({str(item.source) for item in group})
                        ),
                        keyids=tuple(sorted({item.keyid for item in group})),
                    )
                )
                continue

            # One digest: backup duplicates collapse into a single usage while
            # every original location remains traceable.
            canonical = group[0]
            usages.append(
                Usage(
                    category=category,
                    seal_number=seal_number,
                    material_digest=canonical.material_digest,
                    officer_id=self._officer_for_key(canonical.keyid),
                    keyid=canonical.keyid,
                    sources=tuple(
                        sorted({str(item.source) for item in group})
                    ),
                )
            )
        return usages, collisions

    def _officer_for_key(self, keyid: str) -> str:
        for authorization in self._authorizations:
            if authorization.keyid == keyid:
                return authorization.officer_id
        return "unregistered"

    def _check_authorization(
        self, usages: list[Usage]
    ) -> tuple[list[Usage], list[Usage]]:
        in_range: list[Usage] = []
        out_of_range: list[Usage] = []
        for usage in usages:
            matching = [
                authorization
                for authorization in self._auth_by_category.get(
                    usage.category, []
                )
                if authorization.contains(usage.seal_number)
                and authorization.keyid == usage.keyid
            ]
            if matching:
                in_range.append(usage)
            else:
                out_of_range.append(usage)
        return in_range, out_of_range

    def _build_intervals(
        self, usages: list[Usage]
    ) -> tuple[AuthorizationInterval, ...]:
        consumed: dict[tuple[str, str], set[int]] = defaultdict(set)
        for usage in usages:
            for authorization in self._auth_by_category.get(
                usage.category, []
            ):
                if (
                    authorization.contains(usage.seal_number)
                    and authorization.keyid == usage.keyid
                ):
                    key = (authorization.officer_id, authorization.category)
                    consumed[key].add(usage.seal_number)

        intervals = []
        for authorization in self._authorizations:
            key = (authorization.officer_id, authorization.category)
            intervals.append(
                AuthorizationInterval(
                    officer_id=authorization.officer_id,
                    category=authorization.category,
                    start=authorization.start,
                    end=authorization.end,
                    note=authorization.note,
                    used_numbers=tuple(sorted(consumed.get(key, set()))),
                )
            )
        return tuple(intervals)
