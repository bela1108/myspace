from datetime import datetime
from typing import Dict
from typing import List
from typing import Optional
from typing import Set
from typing import Tuple

from .models import EvidenceBundle
from .models import RotationReceipt
from .report import ClosureReport
from .report import Decision
from .report import ReceiptFailure
from .report import STATUS_CLOSED
from .report import STATUS_OPEN


def validate_window(receipt: RotationReceipt, as_of: datetime) -> Optional[str]:
    """Checks the receipt's validity window against the decision time."""
    if as_of < receipt.not_before:
        return f'not valid before {receipt.not_before.isoformat()}'
    if as_of > receipt.not_after:
        return f'expired at {receipt.not_after.isoformat()}'
    return None


def validate_environment(receipt: RotationReceipt, environment: str) -> Optional[str]:
    """Checks the receipt was issued for the environment under evaluation."""
    if receipt.environment != environment:
        return f'issued for {receipt.environment!r}, not {environment!r}'
    return None


def validate_revocation_scope(receipt: RotationReceipt, branch: str) -> Optional[str]:
    """Checks the receipt's own revocation scope covers the branch."""
    if branch not in receipt.branches:
        return f'branch {branch!r} not in revocation scope'
    return None


def check_receipt(
    receipt: RotationReceipt,
    environment: str,
    as_of: datetime,
) -> Dict[str, str]:
    """Runs every per-receipt check and returns all failures found.

    Eligibility (approved, not revoked), window and environment are
    validated independently of any particular branch.
    """
    errors = {}
    if receipt.is_revoked:
        errors['ineligible'] = 'receipt was revoked'
    elif not receipt.is_approved:
        errors['ineligible'] = 'receipt is not approved'

    window_error = validate_window(receipt, as_of)
    if window_error is not None:
        errors['window'] = window_error

    environment_error = validate_environment(receipt, environment)
    if environment_error is not None:
        errors['environment'] = environment_error

    return errors


def evaluate(bundle: EvidenceBundle) -> ClosureReport:
    """Evaluates a frozen evidence bundle into a closure report.

    A (fingerprint, branch) alert may be closed when a receipt covering the
    fingerprint passes all checks and the branch lies in the union of
    revocation scopes reachable through its references. Reference cycles
    contribute no proof beyond the receipts' own scopes.
    """
    receipts = _index_receipts(bundle.receipts)
    warnings = _dangling_reference_warnings(bundle.receipts, receipts)
    check_errors = {
        receipt_id: check_receipt(receipt, bundle.environment, bundle.as_of)
        for receipt_id, receipt in receipts.items()
    }
    reachability = {
        receipt_id: _reachable_ids(receipt_id, receipts)
        for receipt_id in receipts
    }
    effective_branches = {
        receipt_id: _effective_branches(reachable, receipts, check_errors)
        for receipt_id, reachable in reachability.items()
    }

    decisions = {}
    for fingerprint in sorted(bundle.fingerprints):
        for branch in sorted(bundle.branch_scope.branches):
            decisions[(fingerprint, branch)] = _decide(
                fingerprint,
                branch,
                receipts,
                check_errors,
                reachability,
                effective_branches,
            )

    return ClosureReport(
        evidence_version=bundle.version,
        environment=bundle.environment,
        as_of=bundle.as_of,
        decisions=decisions,
        cycles=_cycle_groups(receipts),
        warnings=warnings,
    )


def _index_receipts(receipts: Tuple[RotationReceipt, ...]) -> Dict[str, RotationReceipt]:
    indexed = {}
    for receipt in receipts:
        if receipt.receipt_id in indexed:
            raise ValueError(f'duplicate receipt id: {receipt.receipt_id}')
        indexed[receipt.receipt_id] = receipt
    return indexed


def _dangling_reference_warnings(
    receipts: Tuple[RotationReceipt, ...],
    indexed: Dict[str, RotationReceipt],
) -> List[str]:
    return sorted(
        f'receipt {receipt.receipt_id} references unknown receipt {reference}'
        for receipt in receipts
        for reference in receipt.references
        if reference not in indexed
    )


def _reachable_ids(start: str, receipts: Dict[str, RotationReceipt]) -> Set[str]:
    """All receipt ids reachable from ``start`` (inclusive).

    The visited set guards against reference cycles: a cycle can never
    expand the reachable set beyond the receipts actually in it, so no
    extra proof is manufactured.
    """
    seen = {start}
    stack = [start]
    while stack:
        current = stack.pop()
        for reference in receipts[current].references:
            if reference in receipts and reference not in seen:
                seen.add(reference)
                stack.append(reference)
    return seen


def _effective_branches(
    reachable: Set[str],
    receipts: Dict[str, RotationReceipt],
    check_errors: Dict[str, Dict[str, str]],
) -> Set[str]:
    branches: Set[str] = set()
    for receipt_id in reachable:
        if not check_errors[receipt_id]:
            branches.update(receipts[receipt_id].branches)
    return branches


def _decide(
    fingerprint: str,
    branch: str,
    receipts: Dict[str, RotationReceipt],
    check_errors: Dict[str, Dict[str, str]],
    reachability: Dict[str, Set[str]],
    effective_branches: Dict[str, Set[str]],
) -> Decision:
    justification = []
    support = {}
    failures = []

    for receipt_id in sorted(receipts):
        receipt = receipts[receipt_id]
        if fingerprint not in receipt.fingerprints:
            continue

        errors = check_errors[receipt_id]
        if errors:
            failures.append(ReceiptFailure(receipt_id=receipt_id, **errors))
            continue

        if branch in effective_branches[receipt_id]:
            justification.append(receipt_id)
            support[receipt_id] = tuple(sorted(
                other
                for other in reachability[receipt_id]
                if not check_errors[other] and branch in receipts[other].branches
            ))
        else:
            failures.append(ReceiptFailure(
                receipt_id=receipt_id,
                # The branch is outside the effective scope, so it is
                # necessarily outside the receipt's own scope as well.
                revocation_scope=validate_revocation_scope(receipt, branch),
            ))

    return Decision(
        fingerprint=fingerprint,
        branch=branch,
        status=STATUS_CLOSED if justification else STATUS_OPEN,
        justification=tuple(justification),
        support=support,
        failures=tuple(failures),
    )


def _cycle_groups(receipts: Dict[str, RotationReceipt]) -> List[List[str]]:
    """Groups of receipts whose references form a cycle, for reporting."""
    reachability = {
        receipt_id: _reachable_ids(receipt_id, receipts)
        for receipt_id in receipts
    }
    parent = {receipt_id: receipt_id for receipt_id in receipts}

    def find(receipt_id: str) -> str:
        while parent[receipt_id] != receipt_id:
            parent[receipt_id] = parent[parent[receipt_id]]
            receipt_id = parent[receipt_id]
        return receipt_id

    ids = sorted(receipts)
    for left in ids:
        for right in ids:
            if left < right and right in reachability[left] and left in reachability[right]:
                parent[find(left)] = find(right)

    groups: Dict[str, List[str]] = {}
    for receipt_id in ids:
        groups.setdefault(find(receipt_id), []).append(receipt_id)

    cycles = [sorted(members) for members in groups.values() if len(members) > 1]
    for receipt_id in ids:
        if receipt_id in receipts[receipt_id].references:
            cycles.append([receipt_id])
    return sorted(cycles)
