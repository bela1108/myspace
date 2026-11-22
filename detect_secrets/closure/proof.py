from dataclasses import dataclass
from enum import Enum
from typing import Callable
from typing import Dict
from typing import FrozenSet
from typing import Iterable

from .model import ReceiptStatus
from .model import RotationReceipt


class BlockedReason(Enum):
    NOT_APPROVED = 'not-approved'
    FAILED_VALIDATION = 'failed-validation'
    UNKNOWN_REFERENCE = 'unknown-reference'
    UNPROVEN_REFERENCE = 'unproven-reference'
    CYCLIC_REFERENCE = 'cyclic-reference'


@dataclass(frozen=True)
class ProofResolution:
    """Which receipts count as proven, and why the rest do not."""
    grounded: FrozenSet[str]
    blocked: Dict[str, BlockedReason]


def resolve_grounded(
    receipts: Iterable[RotationReceipt],
    is_valid: Callable[[RotationReceipt], bool],
) -> ProofResolution:
    """Resolves which receipts carry proof, without letting cycles invent any.

    A receipt is grounded iff it is approved, passes ``is_valid`` and either
    cites nothing or cites an already-grounded receipt. Receipts that only
    cite each other (a citation cycle) never become grounded: the fixed-point
    computation has nothing to start from, so a loop produces no proof.
    """
    by_id = {receipt.receipt_id: receipt for receipt in receipts}
    blocked: Dict[str, BlockedReason] = {}
    candidates: Dict[str, RotationReceipt] = {}
    for receipt in by_id.values():
        if receipt.status is not ReceiptStatus.APPROVED:
            blocked[receipt.receipt_id] = BlockedReason.NOT_APPROVED
        elif not is_valid(receipt):
            blocked[receipt.receipt_id] = BlockedReason.FAILED_VALIDATION
        else:
            candidates[receipt.receipt_id] = receipt

    grounded = set()
    changed = True
    while changed:
        changed = False
        for receipt_id, receipt in candidates.items():
            if receipt_id in grounded:
                continue
            if receipt.based_on is None or receipt.based_on in grounded:
                grounded.add(receipt_id)
                changed = True

    # Everything left either points at a missing/blocked receipt, or is stuck
    # in a citation cycle. Propagate the terminal reasons first; whatever
    # remains afterwards can only be cyclic.
    changed = True
    while changed:
        changed = False
        for receipt_id, receipt in candidates.items():
            if receipt_id in grounded or receipt_id in blocked:
                continue
            if receipt.based_on not in by_id:
                blocked[receipt_id] = BlockedReason.UNKNOWN_REFERENCE
                changed = True
            elif receipt.based_on in blocked:
                blocked[receipt_id] = BlockedReason.UNPROVEN_REFERENCE
                changed = True

    for receipt_id in candidates:
        if receipt_id not in grounded and receipt_id not in blocked:
            blocked[receipt_id] = BlockedReason.CYCLIC_REFERENCE

    return ProofResolution(grounded=frozenset(grounded), blocked=blocked)
