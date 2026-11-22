"""Business-layer reconciliation of verified ownership statements.

The cryptographic layer only decides whether a signature is valid. This module
answers the business question: *for a given purpose, interval and jurisdiction,
which organization should be recognized?*

Two rules are central:

* statements with an identical payload are the same evidence and are merged,
  no matter how many times they were filed; and
* when two independently signed authorizations claim overlapping intervals for
  the same key material, the overlap is reported as a conflict instead of being
  resolved by silently keeping the newer statement.

Handoff statements do not override authorization conflicts. They are recorded
on the receipt -- including the witnesses that were actually used -- and they
determine the recognized owner only on segments where no authorization claims
the material.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from securesystemslib.ownership._model import (
    AUTHORIZATION,
    HANDOFF,
    Authorization,
    Handoff,
    Registration,
    Statement,
    material_id,
)
from securesystemslib.ownership._verify import StatementVerifier

RECOGNIZED = "recognized"
CONFLICTED = "conflicted"
UNDETERMINED = "undetermined"


@dataclass
class Segment:
    """A maximal time interval with a single reconciliation outcome."""

    start: str
    end: str
    status: str
    organizations: list[str]
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "start": self.start,
            "end": self.end,
            "status": self.status,
            "organizations": list(self.organizations),
            "evidence": list(self.evidence),
        }


@dataclass
class Receipt:
    """Handoff receipt for one (purpose, jurisdiction) scope of one material.

    It records which statements actually served as witnesses, which filings
    were merged as duplicates and the time segments that still need human
    clarification.
    """

    material_id: str
    purpose: str
    jurisdiction: str
    registrations: list[str]
    segments: list[Segment]
    witnesses: list[dict[str, Any]]
    merged_duplicates: list[dict[str, Any]]
    rejected: list[dict[str, Any]]
    ambiguous_intervals: list[dict[str, str]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "material_id": self.material_id,
            "purpose": self.purpose,
            "jurisdiction": self.jurisdiction,
            "registrations": list(self.registrations),
            "segments": [segment.to_dict() for segment in self.segments],
            "witnesses": [dict(item) for item in self.witnesses],
            "merged_duplicates": [dict(item) for item in self.merged_duplicates],
            "rejected": [dict(item) for item in self.rejected],
            "ambiguous_intervals": [dict(item) for item in self.ambiguous_intervals],
        }


@dataclass
class ReconciliationReport:
    """All receipts produced during one offline reconciliation run."""

    receipts: list[Receipt] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"receipts": [receipt.to_dict() for receipt in self.receipts]}

    def get_receipt(self, purpose: str, jurisdiction: str) -> Receipt:
        """Return the receipt for a scope, raising if it is absent."""
        for receipt in self.receipts:
            if receipt.purpose == purpose and receipt.jurisdiction == jurisdiction:
                return receipt
        raise KeyError(
            f"no receipt for purpose {purpose!r} and jurisdiction {jurisdiction!r}"
        )


class OwnershipReconciler:
    """Reconcile signed ownership statements against registrations offline."""

    def __init__(self, registrations: list[Registration]) -> None:
        self._registrations = list(registrations)
        self._verifier = StatementVerifier(self._registrations)

    def reconcile(self, statements: list[Statement]) -> ReconciliationReport:
        """Verify statements and produce a receipt for every material/scope."""
        verified, rejected = self._verifier.verify_all(statements)

        rejected_records = [
            {
                "statement_id": statement.statement_id,
                "keyid": statement.signature.keyid,
                "reason": str(error),
            }
            for statement, error in rejected
        ]

        scoped: dict[tuple[Any, str, str], list[tuple[Statement, Registration]]] = (
            defaultdict(list)
        )
        for statement, registration in verified:
            fingerprint = registration.material_fingerprint
            scoped[(fingerprint, statement.purpose, statement.jurisdiction)].append(
                (statement, registration)
            )

        report = ReconciliationReport()
        for (fingerprint, purpose, jurisdiction), items in sorted(
            scoped.items(), key=lambda entry: repr(entry[0])
        ):
            report.receipts.append(
                self._reconcile_scope(
                    fingerprint, purpose, jurisdiction, items, rejected_records
                )
            )

        return report

    def _reconcile_scope(
        self,
        fingerprint: tuple[Any, Any, Any],
        purpose: str,
        jurisdiction: str,
        items: list[tuple[Statement, Registration]],
        rejected_records: list[dict[str, Any]],
    ) -> Receipt:
        merged_duplicates: list[dict[str, Any]] = []
        unique_by_id: dict[str, tuple[Statement, Registration]] = {}

        for statement, registration in items:
            statement_id = statement.statement_id
            if statement_id in unique_by_id:
                merged_duplicates.append(
                    {
                        "statement_id": statement_id,
                        "keyid": statement.signature.keyid,
                        "merged_into": statement_id,
                    }
                )
                continue
            unique_by_id[statement_id] = (statement, registration)

        authorizations: list[tuple[Authorization, Statement]] = []
        handoffs: list[tuple[Handoff, Statement]] = []
        for statement, _registration in unique_by_id.values():
            if statement.statement_type == AUTHORIZATION:
                authorizations.append(
                    (Authorization.from_payload(statement.payload), statement)
                )
            elif statement.statement_type == HANDOFF:
                handoffs.append((Handoff.from_payload(statement.payload), statement))

        segments = self._build_segments(authorizations, handoffs)
        witnesses = [
            {
                "statement_id": statement.statement_id,
                "keyid": statement.signature.keyid,
                "from_organization": handoff.from_organization,
                "to_organization": handoff.to_organization,
                "effective_at": handoff.effective_at,
                "witnesses": list(handoff.witnesses),
            }
            for handoff, statement in sorted(
                handoffs, key=lambda item: item[0].effective_at
            )
        ]
        ambiguous_intervals = [
            {
                "start": segment.start,
                "end": segment.end,
                "organizations": ", ".join(segment.organizations),
            }
            for segment in segments
            if segment.status != RECOGNIZED
        ]
        registrations = sorted(
            {
                registration.organization
                for registration in self._registrations
                if registration.material_fingerprint == fingerprint
            }
        )

        return Receipt(
            material_id=material_id(fingerprint),
            purpose=purpose,
            jurisdiction=jurisdiction,
            registrations=registrations,
            segments=segments,
            witnesses=witnesses,
            merged_duplicates=merged_duplicates,
            rejected=list(rejected_records),
            ambiguous_intervals=ambiguous_intervals,
        )

    def _build_segments(
        self,
        authorizations: list[tuple[Authorization, Statement]],
        handoffs: list[tuple[Handoff, Statement]],
    ) -> list[Segment]:
        boundaries = {
            value
            for authorization, _statement in authorizations
            for value in (authorization.valid_from, authorization.valid_to)
        }
        boundaries.update(handoff.effective_at for handoff, _statement in handoffs)
        ordered = sorted(boundaries)

        if not ordered:
            return []

        raw_segments: list[Segment] = []
        for index, start in enumerate(ordered):
            end = ordered[index + 1] if index + 1 < len(ordered) else start
            active = [
                (authorization, statement)
                for authorization, statement in authorizations
                if authorization.valid_from <= start and end <= authorization.valid_to
            ]
            organizations = sorted(
                {authorization.organization for authorization, _statement in active}
            )
            evidence = sorted(statement.statement_id for _auth, statement in active)

            if len(organizations) > 1:
                raw_segments.append(
                    Segment(start, end, CONFLICTED, organizations, evidence)
                )
            elif len(organizations) == 1:
                raw_segments.append(
                    Segment(start, end, RECOGNIZED, organizations, evidence)
                )
            else:
                owner = self._owner_from_handoffs(start, handoffs)
                if owner is None:
                    raw_segments.append(Segment(start, end, UNDETERMINED, [], []))
                else:
                    raw_segments.append(Segment(start, end, RECOGNIZED, [owner], []))

        return self._merge_adjacent(raw_segments)

    @staticmethod
    def _owner_from_handoffs(
        point: str, handoffs: list[tuple[Handoff, Statement]]
    ) -> str | None:
        effective = sorted(
            (
                handoff
                for handoff, _statement in handoffs
                if handoff.effective_at <= point
            ),
            key=lambda handoff: handoff.effective_at,
        )
        if not effective:
            return None
        return effective[-1].to_organization

    @staticmethod
    def _merge_adjacent(segments: list[Segment]) -> list[Segment]:
        merged: list[Segment] = []
        for segment in segments:
            if (
                merged
                and merged[-1].end == segment.start
                and merged[-1].status == segment.status
                and merged[-1].organizations == segment.organizations
            ):
                merged[-1].end = segment.end
                merged[-1].evidence = sorted(
                    set(merged[-1].evidence) | set(segment.evidence)
                )
            else:
                merged.append(
                    Segment(
                        segment.start,
                        segment.end,
                        segment.status,
                        list(segment.organizations),
                        list(segment.evidence),
                    )
                )
        return merged
