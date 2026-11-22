from datetime import datetime
from datetime import timedelta
from datetime import timezone

from detect_secrets.closure import ClosureJournal
from detect_secrets.closure import evaluate
from detect_secrets.closure import EvidenceBundle
from detect_secrets.closure import FrozenBranchScope
from detect_secrets.closure import RotationReceipt


AS_OF = datetime(2026, 11, 22, tzinfo=timezone.utc)
FINGERPRINT = 'fictional-fingerprint-001'


def make_receipt(receipt_id, branches, is_test=False):
    return RotationReceipt(
        receipt_id=receipt_id,
        fingerprints=frozenset({FINGERPRINT}),
        branches=frozenset(branches),
        environment='production',
        not_before=AS_OF - timedelta(days=1),
        not_after=AS_OF + timedelta(days=1),
        is_test=is_test,
    )


def make_bundle(receipts):
    return EvidenceBundle(
        fingerprints=frozenset({FINGERPRINT}),
        branch_scope=FrozenBranchScope(
            branches=frozenset({'main', 'maintenance/1.x'}),
            frozen_at=AS_OF,
            label='freeze-2026-11',
        ),
        receipts=tuple(receipts),
        environment='production',
        as_of=AS_OF,
    )


def build_journal():
    """The auditor workflow: close on a test receipt, then revoke it."""
    bundle_v1 = make_bundle([
        make_receipt('R-prod', branches=('main',)),
        make_receipt('R-test', branches=('maintenance/1.x',), is_test=True),
    ])
    journal = ClosureJournal()
    v1 = journal.record(evaluate(bundle_v1))
    v2 = journal.record(evaluate(bundle_v1.revoke('R-test')))
    return journal, v1, v2


class TestAuditorRevocationFlow:
    def test_both_branches_closed_before_revocation(self):
        journal, v1, _ = build_journal()
        report = journal.report(v1)

        assert report.closed_branches(FINGERPRINT) == ['main', 'maintenance/1.x']
        assert report.open_branches(FINGERPRINT) == []

    def test_revocation_reopens_only_the_test_covered_branch(self):
        journal, v1, v2 = build_journal()

        assert journal.reopened(v1, v2) == [(FINGERPRINT, 'maintenance/1.x')]
        assert journal.still_closed(v1, v2) == [(FINGERPRINT, 'main')]

    def test_diff_attributes_original_decision_to_evidence_version(self):
        journal, v1, v2 = build_journal()
        diff = journal.diff(v1, v2)

        assert diff['from'] == v1
        assert diff['to'] == v2
        assert diff['reopened'] == [
            {
                'fingerprint': FINGERPRINT,
                'branch': 'maintenance/1.x',
                'previously_closed_under': v1,
            },
        ]
        assert diff['still_closed'] == [
            {'fingerprint': FINGERPRINT, 'branch': 'main'},
        ]
        assert diff['newly_closed'] == []

    def test_decision_history_tracks_status_per_version(self):
        journal, v1, v2 = build_journal()

        assert journal.decision_history(FINGERPRINT, 'maintenance/1.x') == [
            (v1, 'closed'),
            (v2, 'open'),
        ]
        assert journal.decision_history(FINGERPRINT, 'main') == [
            (v1, 'closed'),
            (v2, 'closed'),
        ]

    def test_versions_are_distinct(self):
        journal, v1, v2 = build_journal()

        assert v1 != v2
        assert journal.versions == [v1, v2]


class TestClosureJournal:
    def test_recording_same_report_twice_keeps_one_version(self):
        journal = ClosureJournal()
        report = evaluate(make_bundle([make_receipt('R-prod', ('main',))]))

        assert journal.record(report) == journal.record(report)
        assert len(journal.versions) == 1

    def test_report_serializes_to_jsonable_dict(self):
        journal, v1, _ = build_journal()
        output = journal.report(v1).to_dict()

        assert output['evidence_version'] == v1
        assert output['decisions'][FINGERPRINT]['main']['status'] == 'closed'
        assert output['decisions'][FINGERPRINT]['main']['justification'] == ['R-prod']
