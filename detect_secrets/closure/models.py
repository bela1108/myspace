import hashlib
import json
from dataclasses import dataclass
from dataclasses import replace
from datetime import datetime
from typing import Any
from typing import Dict
from typing import FrozenSet
from typing import Set
from typing import Tuple


@dataclass(frozen=True)
class RotationReceipt:
    """An approved assertion that a credential was rotated.

    The credential is identified only by its fingerprint; the secret itself
    is never stored or read. ``branches`` is the revocation scope: the
    branches on which the old identifier is claimed to be invalid.
    """
    receipt_id: str
    fingerprints: FrozenSet[str]
    branches: FrozenSet[str]
    environment: str
    not_before: datetime
    not_after: datetime
    references: Tuple[str, ...] = ()
    is_approved: bool = True
    is_test: bool = False
    is_revoked: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            'receipt_id': self.receipt_id,
            'fingerprints': sorted(self.fingerprints),
            'branches': sorted(self.branches),
            'environment': self.environment,
            'not_before': self.not_before.isoformat(),
            'not_after': self.not_after.isoformat(),
            'references': sorted(self.references),
            'is_approved': self.is_approved,
            'is_test': self.is_test,
            'is_revoked': self.is_revoked,
        }


@dataclass(frozen=True)
class FrozenBranchScope:
    """The fixed set of branches a closure decision is allowed to cover."""
    branches: FrozenSet[str]
    frozen_at: datetime
    label: str = ''

    def to_dict(self) -> Dict[str, Any]:
        return {
            'branches': sorted(self.branches),
            'frozen_at': self.frozen_at.isoformat(),
            'label': self.label,
        }


@dataclass(frozen=True)
class EvidenceBundle:
    """An immutable snapshot of everything a closure decision is based on.

    Any change (e.g. revoking a receipt) produces a new bundle with a new
    evidence version, so historical decisions remain attributable.
    """
    fingerprints: FrozenSet[str]
    branch_scope: FrozenBranchScope
    receipts: Tuple[RotationReceipt, ...]
    environment: str
    as_of: datetime

    @property
    def version(self) -> str:
        canonical = json.dumps(self.to_dict(), sort_keys=True)
        return 'ev-' + hashlib.sha256(canonical.encode('utf-8')).hexdigest()[:12]

    def to_dict(self) -> Dict[str, Any]:
        return {
            'fingerprints': sorted(self.fingerprints),
            'branch_scope': self.branch_scope.to_dict(),
            'receipts': sorted(
                (receipt.to_dict() for receipt in self.receipts),
                key=lambda item: item['receipt_id'],
            ),
            'environment': self.environment,
            'as_of': self.as_of.isoformat(),
        }

    def revoke(self, receipt_id: str) -> 'EvidenceBundle':
        """Returns a new bundle with the given receipt revoked.

        :raises: KeyError
        """
        if receipt_id not in {receipt.receipt_id for receipt in self.receipts}:
            raise KeyError(f'unknown receipt: {receipt_id}')

        return replace(
            self,
            receipts=tuple(
                replace(receipt, is_revoked=True)
                if receipt.receipt_id == receipt_id
                else receipt
                for receipt in self.receipts
            ),
        )


def load_fingerprints_from_baseline(filename: str) -> Set[str]:
    """Collects hashed secrets from a detect-secrets baseline file.

    Only the ``hashed_secret`` fingerprints are read; the baseline never
    contains the plaintext secrets, and this function does not either.
    """
    with open(filename) as f:
        baseline = json.load(f)

    return {
        item['hashed_secret']
        for items in baseline.get('results', {}).values()
        for item in items
    }
