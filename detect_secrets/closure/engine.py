from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Dict
from typing import Optional
from typing import Tuple

from .model import EvidenceBundle
from .model import ensure_fingerprint
from .proof import BlockedReason
from .proof import ProofResolution
from .proof import resolve_grounded
from .validation import CheckResult
from .validation import validate_receipt


class BranchStatus(Enum):
    CLOSABLE = 'closable'
    OPEN = 'open'


@dataclass(frozen=True)
class BranchDecision:
    branch: str
    status: BranchStatus
    supporting_receipts: Tuple[str, ...]
    reasons: Tuple[str, ...]


@dataclass(frozen=True)
class ClosureReport:
    """One decision per branch, stamped with the evidence version it used."""
    fingerprint: str
    environment: str
    evidence_version: int
    evaluated_at: datetime
    decisions: Tuple[BranchDecision, ...]

    @property
    def closable_branches(self) -> Tuple[str, ...]:
        return tuple(
            decision.branch
            for decision in self.decisions
            if decision.status is BranchStatus.CLOSABLE
        )

    @property
    def open_branches(self) -> Tuple[str, ...]:
        return tuple(
            decision.branch
            for decision in self.decisions
            if decision.status is BranchStatus.OPEN
        )

    def decision_for(self, branch: str) -> BranchDecision:
        for decision in self.decisions:
            if decision.branch == branch:
                return decision
        raise KeyError(branch)


@dataclass(frozen=True)
class ReportDiff:
    """What an auditor sees after the evidence changed (e.g. a revocation)."""
    original_evidence_version: int
    current_evidence_version: int
    reopened: Tuple[str, ...]
    still_closable: Tuple[str, ...]
    newly_closable: Tuple[str, ...]
    still_open: Tuple[str, ...]


def diff_reports(original: ClosureReport, current: ClosureReport) -> ReportDiff:
    if original.fingerprint != current.fingerprint:
        raise ValueError('cannot diff reports for different fingerprints')
    original_closable = set(original.closable_branches)
    current_closable = set(current.closable_branches)
    return ReportDiff(
        original_evidence_version=original.evidence_version,
        current_evidence_version=current.evidence_version,
        reopened=tuple(sorted(original_closable - current_closable)),
        still_closable=tuple(sorted(original_closable & current_closable)),
        newly_closable=tuple(sorted(current_closable - original_closable)),
        still_open=tuple(sorted(
            set(original.open_branches) & set(current.open_branches),
        )),
    )


class ClosureEngine:
    """Evaluates closure for one evidence bundle; revocations bump its version."""

    def __init__(self, bundle: EvidenceBundle) -> None:
        self.bundle = bundle

    def revoke(self, receipt_id: str) -> None:
        """:raises: KeyError if the receipt is not part of the evidence"""
        self.bundle = self.bundle.with_revocation(receipt_id)

    def evaluate(
        self,
        fingerprint: Optional[str] = None,
        as_of: Optional[datetime] = None,
    ) -> ClosureReport:
        fingerprint = fingerprint or self.bundle.fingerprint
        as_of = as_of or self.bundle.evaluated_at
        ensure_fingerprint(fingerprint)

        checks = {
            receipt.receipt_id: validate_receipt(
                receipt,
                as_of=as_of,
                environment=self.bundle.environment,
                scope=self.bundle.scope,
            )
            for receipt in self.bundle.receipts
        }
        resolution = resolve_grounded(
            self.bundle.receipts,
            is_valid=lambda receipt: all(
                result.passed for result in checks[receipt.receipt_id]
            ),
        )

        return ClosureReport(
            fingerprint=fingerprint,
            environment=self.bundle.environment,
            evidence_version=self.bundle.version,
            evaluated_at=as_of,
            decisions=tuple(
                self._decide(branch, fingerprint, checks, resolution)
                for branch in sorted(self.bundle.scope.branches)
            ),
        )

    def _decide(
        self,
        branch: str,
        fingerprint: str,
        checks: Dict[str, Tuple[CheckResult, ...]],
        resolution: ProofResolution,
    ) -> BranchDecision:
        covering = [
            receipt
            for receipt in self.bundle.receipts
            if receipt.fingerprint == fingerprint and branch in receipt.revocation_scope
        ]
        if not covering:
            return BranchDecision(
                branch=branch,
                status=BranchStatus.OPEN,
                supporting_receipts=(),
                reasons=(
                    'no receipt revokes the identifier on this branch',
                ),
            )

        supporting = tuple(sorted(
            receipt.receipt_id
            for receipt in covering
            if receipt.receipt_id in resolution.grounded
        ))
        if supporting:
            return BranchDecision(
                branch=branch,
                status=BranchStatus.CLOSABLE,
                supporting_receipts=supporting,
                reasons=(),
            )

        reasons = []
        for receipt in sorted(covering, key=lambda item: item.receipt_id):
            blocked = resolution.blocked[receipt.receipt_id]
            if blocked is BlockedReason.FAILED_VALIDATION:
                reasons.extend(
                    reason
                    for result in checks[receipt.receipt_id]
                    if not result.passed
                    for reason in result.reasons
                )
            else:
                reasons.append(
                    'receipt {} is not proven: {}'.format(receipt.receipt_id, blocked.value),
                )
        return BranchDecision(
            branch=branch,
            status=BranchStatus.OPEN,
            supporting_receipts=(),
            reasons=tuple(reasons),
        )
