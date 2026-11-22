import pytest

from detect_secrets.closure.engine import BranchStatus
from detect_secrets.closure.engine import ClosureEngine
from detect_secrets.closure.engine import diff_reports
from detect_secrets.closure.model import ReceiptKind
from tests.closure.conftest import AS_OF
from tests.closure.conftest import make_bundle
from tests.closure.conftest import make_receipt
from tests.closure.conftest import make_scope
from tests.closure.conftest import make_window


def test_branch_without_revocation_coverage_stays_open():
    # The rotation ticket covers main, but nobody declared the old identifier
    # invalid on the maintenance branch.
    engine = ClosureEngine(make_bundle())
    report = engine.evaluate()

    assert report.closable_branches == ('main',)
    assert report.open_branches == ('maint/1.x',)
    decision = report.decision_for('maint/1.x')
    assert decision.reasons == ('no receipt revokes the identifier on this branch',)


def test_branch_covered_by_grounded_receipt_is_closable():
    bundle = make_bundle(receipts=[
        make_receipt('RT-1'),
        make_receipt('RT-2', revocation_scope=frozenset({'maint/1.x'}), based_on='RT-1'),
    ])
    report = ClosureEngine(bundle).evaluate()

    assert set(report.closable_branches) == {'main', 'maint/1.x'}
    assert report.decision_for('maint/1.x').supporting_receipts == ('RT-2',)
    assert report.evidence_version == bundle.version


def test_window_miss_is_reported_separately():
    receipt = make_receipt(window=make_window(
        opens_at=AS_OF.replace(year=2020),
        closes_at=AS_OF.replace(year=2021),
    ))
    report = ClosureEngine(make_bundle(receipts=[receipt])).evaluate()

    decision = report.decision_for('main')
    assert decision.status is BranchStatus.OPEN
    assert any('window' in reason for reason in decision.reasons)


def test_environment_mismatch_is_reported_separately():
    receipt = make_receipt(environment='staging')
    report = ClosureEngine(make_bundle(receipts=[receipt])).evaluate()

    decision = report.decision_for('main')
    assert decision.status is BranchStatus.OPEN
    assert any('environment' in reason for reason in decision.reasons)


def test_revocation_scope_outside_frozen_scope_fails_validation():
    receipt = make_receipt(revocation_scope=frozenset({'main', 'feature/x'}))
    report = ClosureEngine(make_bundle(receipts=[receipt])).evaluate()

    decision = report.decision_for('main')
    assert decision.status is BranchStatus.OPEN
    assert any('outside the frozen scope' in reason for reason in decision.reasons)


def test_cyclic_receipts_cannot_close_a_branch():
    receipts = [
        make_receipt('RT-1', based_on='RT-2'),
        make_receipt('RT-2', based_on='RT-1'),
    ]
    report = ClosureEngine(make_bundle(receipts=receipts)).evaluate()

    decision = report.decision_for('main')
    assert decision.status is BranchStatus.OPEN
    assert decision.reasons == (
        'receipt RT-1 is not proven: cyclic-reference',
        'receipt RT-2 is not proven: cyclic-reference',
    )


def test_evaluate_with_other_fingerprint_finds_no_coverage():
    report = ClosureEngine(make_bundle()).evaluate(fingerprint='c' * 40)
    assert report.closable_branches == ()
    assert set(report.open_branches) == {'main', 'maint/1.x'}


def test_evaluate_rejects_plaintext_fingerprint_override():
    with pytest.raises(ValueError):
        ClosureEngine(make_bundle()).evaluate(fingerprint='hunter2')


def test_revoke_unknown_receipt_raises():
    with pytest.raises(KeyError):
        ClosureEngine(make_bundle()).revoke('RT-404')


def test_report_decision_for_unknown_branch_raises():
    report = ClosureEngine(make_bundle()).evaluate()
    with pytest.raises(KeyError):
        report.decision_for('no/such-branch')


class TestRevocationFallout:
    """The auditor flow: revoke a test receipt, then read the diff."""

    def build_engine(self):
        scope = make_scope(branches=frozenset({'main', 'maint/1.x', 'release/2.0'}))
        receipts = [
            make_receipt('RT-1'),  # rotation on main
            make_receipt(  # only proof for the maintenance branch
                'RT-TEST',
                kind=ReceiptKind.TEST,
                revocation_scope=frozenset({'maint/1.x'}),
            ),
        ]
        return ClosureEngine(make_bundle(receipts=receipts, scope=scope, version=7))

    def test_revoking_test_receipt_reopens_only_its_branch(self):
        engine = self.build_engine()
        original = engine.evaluate()
        assert original.closable_branches == ('main', 'maint/1.x')
        assert original.open_branches == ('release/2.0',)

        engine.revoke('RT-TEST')
        current = engine.evaluate()
        diff = diff_reports(original, current)

        assert diff.reopened == ('maint/1.x',)
        assert diff.still_closable == ('main',)
        assert diff.newly_closable == ()
        assert diff.still_open == ('release/2.0',)
        assert diff.original_evidence_version == 7
        assert diff.current_evidence_version == 8
        assert current.decision_for('maint/1.x').reasons == (
            'receipt RT-TEST is not proven: not-approved',
        )

    def test_revocation_is_visible_in_the_bundle(self):
        engine = self.build_engine()
        engine.revoke('RT-TEST')
        assert engine.bundle.version == 8


def test_diff_reports_rejects_different_fingerprints():
    engine = ClosureEngine(make_bundle())
    original = engine.evaluate()
    other = engine.evaluate(fingerprint='c' * 40)
    with pytest.raises(ValueError):
        diff_reports(original, other)


def test_diff_reports_notices_newly_closable_branches():
    scope = make_scope()
    engine = ClosureEngine(make_bundle(receipts=[], scope=scope))
    original = engine.evaluate()

    receipts = [
        make_receipt('RT-1'),
        make_receipt('RT-2', revocation_scope=frozenset({'maint/1.x'})),
    ]
    current = ClosureEngine(make_bundle(receipts=receipts, scope=scope, version=2)).evaluate()
    diff = diff_reports(original, current)

    assert diff.newly_closable == ('main', 'maint/1.x')
    assert diff.reopened == ()
    assert diff.still_open == ()
