import re
from dataclasses import dataclass
from dataclasses import replace
from datetime import datetime
from enum import Enum
from typing import FrozenSet
from typing import Optional
from typing import Tuple


# sha1 (40) or sha256 (64) hex digests only. The closure flow never touches
# secret plaintext, so anything that is not a digest is rejected up front.
FINGERPRINT_PATTERN = re.compile(r'\A(?:[0-9a-f]{40}|[0-9a-f]{64})\Z')


def ensure_fingerprint(value: str) -> str:
    if not FINGERPRINT_PATTERN.match(value):
        raise ValueError(
            'expected a credential fingerprint (40 or 64 lowercase hex characters); '
            'plaintext secrets are never accepted here',
        )
    return value


class ReceiptStatus(Enum):
    APPROVED = 'approved'
    REVOKED = 'revoked'


class ReceiptKind(Enum):
    ROTATION = 'rotation'
    TEST = 'test'


@dataclass(frozen=True)
class RotationWindow:
    """Inclusive time window during which a rotation receipt is effective."""
    opens_at: datetime
    closes_at: datetime

    def __post_init__(self) -> None:
        if not self.opens_at < self.closes_at:
            raise ValueError('a rotation window must open before it closes')

    def contains(self, moment: datetime) -> bool:
        return self.opens_at <= moment <= self.closes_at


@dataclass(frozen=True)
class BranchScope:
    """The frozen set of branches a closure decision is allowed to reason about."""
    name: str
    branches: FrozenSet[str]
    frozen_at: str

    def __post_init__(self) -> None:
        if not self.branches:
            raise ValueError('a frozen branch scope must name at least one branch')


@dataclass(frozen=True)
class RotationReceipt:
    """An approved statement that a fingerprint was rotated away.

    ``revocation_scope`` names the branches on which the old identifier is
    declared invalid; a receipt may cite another receipt via ``based_on``,
    but citations are evidence, not proof -- see ``proof.resolve_grounded``.
    """
    receipt_id: str
    fingerprint: str
    window: RotationWindow
    environment: str
    revocation_scope: FrozenSet[str]
    status: ReceiptStatus = ReceiptStatus.APPROVED
    kind: ReceiptKind = ReceiptKind.ROTATION
    based_on: Optional[str] = None

    def __post_init__(self) -> None:
        if not self.receipt_id:
            raise ValueError('a receipt needs an id')
        ensure_fingerprint(self.fingerprint)
        if not self.environment:
            raise ValueError('a receipt needs an environment')
        if self.based_on == self.receipt_id:
            raise ValueError('a receipt cannot cite itself')

    def revoke(self) -> 'RotationReceipt':
        return replace(self, status=ReceiptStatus.REVOKED)


@dataclass(frozen=True)
class EvidenceBundle:
    """An immutable, versioned snapshot of everything a decision is based on."""
    version: int
    fingerprint: str
    environment: str
    evaluated_at: datetime
    scope: BranchScope
    receipts: Tuple[RotationReceipt, ...]

    def __post_init__(self) -> None:
        ensure_fingerprint(self.fingerprint)
        if not self.environment:
            raise ValueError('an evidence bundle needs an environment')
        if self.version < 1:
            raise ValueError('evidence versions start at 1')
        receipt_ids = [receipt.receipt_id for receipt in self.receipts]
        if len(set(receipt_ids)) != len(receipt_ids):
            raise ValueError('receipt ids must be unique within a bundle')

    def with_revocation(self, receipt_id: str) -> 'EvidenceBundle':
        """Returns a new bundle (version bumped) with one receipt revoked."""
        if receipt_id not in {receipt.receipt_id for receipt in self.receipts}:
            raise KeyError(receipt_id)
        return replace(
            self,
            version=self.version + 1,
            receipts=tuple(
                receipt.revoke() if receipt.receipt_id == receipt_id else receipt
                for receipt in self.receipts
            ),
        )
