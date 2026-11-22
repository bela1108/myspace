from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Tuple

from .model import BranchScope
from .model import RotationReceipt


class Check(Enum):
    WINDOW = 'window'
    ENVIRONMENT = 'environment'
    REVOCATION_SCOPE = 'revocation-scope'


@dataclass(frozen=True)
class CheckResult:
    check: Check
    passed: bool
    reasons: Tuple[str, ...] = ()


def validate_window(receipt: RotationReceipt, as_of: datetime) -> CheckResult:
    """The evaluation moment must fall inside the receipt's rotation window."""
    if receipt.window.contains(as_of):
        return CheckResult(Check.WINDOW, True)
    return CheckResult(
        Check.WINDOW,
        False,
        (
            'receipt {} window {}..{} does not cover {}'.format(
                receipt.receipt_id,
                receipt.window.opens_at.isoformat(),
                receipt.window.closes_at.isoformat(),
                as_of.isoformat(),
            ),
        ),
    )


def validate_environment(receipt: RotationReceipt, environment: str) -> CheckResult:
    """A receipt only counts in the environment it was approved for."""
    if receipt.environment == environment:
        return CheckResult(Check.ENVIRONMENT, True)
    return CheckResult(
        Check.ENVIRONMENT,
        False,
        (
            'receipt {} is approved for environment {!r}, not {!r}'.format(
                receipt.receipt_id,
                receipt.environment,
                environment,
            ),
        ),
    )


def validate_revocation_scope(receipt: RotationReceipt, scope: BranchScope) -> CheckResult:
    """The receipt's revocation scope must stay inside the frozen branch scope."""
    if not receipt.revocation_scope:
        return CheckResult(
            Check.REVOCATION_SCOPE,
            False,
            ('receipt {} declares an empty revocation scope'.format(receipt.receipt_id),),
        )
    unknown = sorted(receipt.revocation_scope - scope.branches)
    if unknown:
        return CheckResult(
            Check.REVOCATION_SCOPE,
            False,
            (
                'receipt {} revokes on branches outside the frozen scope {}: {}'.format(
                    receipt.receipt_id,
                    scope.name,
                    ', '.join(unknown),
                ),
            ),
        )
    return CheckResult(Check.REVOCATION_SCOPE, True)


def validate_receipt(
    receipt: RotationReceipt,
    as_of: datetime,
    environment: str,
    scope: BranchScope,
) -> Tuple[CheckResult, CheckResult, CheckResult]:
    """Runs the window, environment and revocation-scope checks separately."""
    return (
        validate_window(receipt, as_of),
        validate_environment(receipt, environment),
        validate_revocation_scope(receipt, scope),
    )
