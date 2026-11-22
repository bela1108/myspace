from datetime import datetime
from datetime import timedelta
from datetime import timezone

import pytest

from detect_secrets.closure import evaluate
from detect_secrets.closure import EvidenceBundle
from detect_secrets.closure import FrozenBranchScope
from detect_secrets.closure import RotationReceipt
from detect_secrets.closure import validate_environment
from detect_secrets.closure import validate_revocation_scope
from detect_secrets.closure import validate_window


AS_OF = datetime(2026, 11, 22, tzinfo=timezone.utc)
FINGERPRINT = 'fictional-fingerprint-001'


def make_receipt(receipt_id='R-1', branches=('main',), **overrides):
    kwargs = {
        'receipt_id': receipt_id,
        'fingerprints': frozenset({FINGERPRINT}),
        'branches': frozenset(branches),
        'environment': 'production',
        'not_before': AS_OF - timedelta(days=1),
        'not_after': AS_OF + timedelta(days=1),
    }
    kwargs.update(overrides)
    return RotationReceipt(**kwargs)


def make_bundle(receipts, branches=('main', 'maintenance/1.x')):
    return EvidenceBundle(
        fingerprints=frozenset({FINGERPRINT}),
        branch_scope=FrozenBranchScope(
            branches=frozenset(branches),
            frozen_at=AS_OF,
            label='freeze-2026-11',
        ),
        receipts=tuple(receipts),
        environment='production',
        as_of=AS_OF,
    )


class TestValidators:
    def test_window_ok(self):
        assert validate_window(make_receipt(), AS_OF) is None

    def test_window_not_yet_valid(self):
        receipt = make_receipt(not_before=AS_OF + timedelta(hours=1))
        assert validate_window(receipt, AS_OF) is not None

    def test_window_expired(self):
        receipt = make_receipt(not_after=AS_OF - timedelta(hours=1))
        assert validate_window(receipt, AS_OF) is not None

    def test_environment_mismatch(self):
        receipt = make_receipt(environment='staging')
        assert validate_environment(receipt, 'production') is not None
        assert validate_environment(receipt, 'staging') is None

    def test_revocation_scope(self):
        receipt = make_receipt(branches=('main',))
        assert validate_revocation_scope(receipt, 'main') is None
        assert validate_revocation_scope(receipt, 'maintenance/1.x') is not None


class TestEvaluate:
    def test_close_only_covered_branch(self):
        report = evaluate(make_bundle([make_receipt()]))

        assert report.decision(FINGERPRINT, 'main').status == 'closed'
        maintenance = report.decision(FINGERPRINT, 'maintenance/1.x')
        assert maintenance.status == 'open'
        assert maintenance.failures[0].revocation_scope is not None
        assert maintenance.failures[0].window is None
        assert maintenance.failures[0].environment is None

    def test_expired_receipt_fails_window_only(self):
        receipt = make_receipt(
            branches=('main', 'maintenance/1.x'),
            not_after=AS_OF - timedelta(hours=1),
        )
        report = evaluate(make_bundle([receipt]))

        failure = report.decision(FINGERPRINT, 'main').failures[0]
        assert failure.window is not None
        assert failure.environment is None
        assert failure.revocation_scope is None

    def test_wrong_environment_fails_environment_only(self):
        receipt = make_receipt(
            branches=('main', 'maintenance/1.x'),
            environment='staging',
        )
        report = evaluate(make_bundle([receipt]))

        failure = report.decision(FINGERPRINT, 'main').failures[0]
        assert failure.environment is not None
        assert failure.window is None

    def test_unapproved_receipt_is_ineligible(self):
        report = evaluate(make_bundle([make_receipt(is_approved=False)]))

        failure = report.decision(FINGERPRINT, 'main').failures[0]
        assert failure.ineligible is not None
        assert report.decision(FINGERPRINT, 'main').status == 'open'

    def test_reference_extends_revocation_scope(self):
        root = make_receipt('R-root', branches=('main',), references=('R-maint',))
        leaf = make_receipt('R-maint', branches=('maintenance/1.x',))
        report = evaluate(make_bundle([root, leaf]))

        decision = report.decision(FINGERPRINT, 'maintenance/1.x')
        assert decision.status == 'closed'
        # The leaf covers the branch directly; the root covers it via reference.
        assert decision.justification == ('R-maint', 'R-root')
        # Only the leaf's own scope actually supplies the maintenance branch.
        assert decision.support['R-root'] == ('R-maint',)

    def test_cycle_produces_no_extra_proof(self):
        first = make_receipt('R-a', branches=('main',), references=('R-b',))
        second = make_receipt('R-b', branches=('release/2.x',), references=('R-a',))
        report = evaluate(make_bundle([first, second], branches=(
            'main',
            'release/2.x',
            'maintenance/1.x',
        )))

        # The union of the cycle's own scopes is available...
        assert report.decision(FINGERPRINT, 'main').status == 'closed'
        assert report.decision(FINGERPRINT, 'release/2.x').status == 'closed'
        # ...but the cycle manufactures nothing beyond it.
        assert report.decision(FINGERPRINT, 'maintenance/1.x').status == 'open'
        assert report.cycles == [['R-a', 'R-b']]

    def test_self_reference_cycle_is_reported(self):
        receipt = make_receipt('R-self', references=('R-self',))
        report = evaluate(make_bundle([receipt]))

        assert report.decision(FINGERPRINT, 'main').status == 'closed'
        assert report.cycles == [['R-self']]

    def test_revoked_link_contributes_nothing(self):
        root = make_receipt('R-root', branches=('main',), references=('R-maint',))
        leaf = make_receipt('R-maint', branches=('maintenance/1.x',), is_revoked=True)
        report = evaluate(make_bundle([root, leaf]))

        assert report.decision(FINGERPRINT, 'main').status == 'closed'
        assert report.decision(FINGERPRINT, 'maintenance/1.x').status == 'open'

    def test_dangling_reference_warns(self):
        receipt = make_receipt(references=('R-missing',))
        report = evaluate(make_bundle([receipt]))

        assert report.warnings == [
            'receipt R-1 references unknown receipt R-missing',
        ]
        assert report.decision(FINGERPRINT, 'main').status == 'closed'

    def test_duplicate_receipt_id_rejected(self):
        with pytest.raises(ValueError):
            evaluate(make_bundle([make_receipt(), make_receipt()]))
