import json
from datetime import datetime
from datetime import timedelta
from datetime import timezone

import pytest

from detect_secrets.closure import EvidenceBundle
from detect_secrets.closure import FrozenBranchScope
from detect_secrets.closure import load_fingerprints_from_baseline
from detect_secrets.closure import RotationReceipt


AS_OF = datetime(2026, 11, 22, tzinfo=timezone.utc)


def make_bundle(receipts=()):
    return EvidenceBundle(
        fingerprints=frozenset({'fp-1'}),
        branch_scope=FrozenBranchScope(
            branches=frozenset({'main'}),
            frozen_at=AS_OF,
        ),
        receipts=tuple(receipts),
        environment='production',
        as_of=AS_OF,
    )


def make_receipt(receipt_id='R-1', **overrides):
    kwargs = {
        'receipt_id': receipt_id,
        'fingerprints': frozenset({'fp-1'}),
        'branches': frozenset({'main'}),
        'environment': 'production',
        'not_before': AS_OF - timedelta(days=1),
        'not_after': AS_OF + timedelta(days=1),
    }
    kwargs.update(overrides)
    return RotationReceipt(**kwargs)


class TestEvidenceVersion:
    def test_version_is_stable_for_same_evidence(self):
        assert make_bundle([make_receipt()]).version == make_bundle([make_receipt()]).version

    def test_version_has_ev_prefix(self):
        assert make_bundle().version.startswith('ev-')

    def test_version_changes_when_receipt_revoked(self):
        bundle = make_bundle([make_receipt()])
        assert bundle.revoke('R-1').version != bundle.version

    def test_version_changes_with_branch_scope(self):
        other = EvidenceBundle(
            fingerprints=frozenset({'fp-1'}),
            branch_scope=FrozenBranchScope(
                branches=frozenset({'main', 'maintenance/1.x'}),
                frozen_at=AS_OF,
            ),
            receipts=(),
            environment='production',
            as_of=AS_OF,
        )
        assert other.version != make_bundle().version


class TestRevoke:
    def test_revoke_marks_receipt_without_mutating_original(self):
        bundle = make_bundle([make_receipt()])
        revoked = bundle.revoke('R-1')

        assert revoked.receipts[0].is_revoked is True
        assert bundle.receipts[0].is_revoked is False

    def test_revoke_unknown_receipt_raises(self):
        with pytest.raises(KeyError):
            make_bundle().revoke('R-nope')


class TestLoadFingerprintsFromBaseline:
    def test_collects_hashed_secrets_only(self, tmp_path):
        baseline = {
            'version': '1.5.0',
            'results': {
                'a.py': [
                    {'type': 'Secret Keyword', 'hashed_secret': 'abc123', 'line_number': 1},
                ],
                'b.py': [
                    {'type': 'Base64 High Entropy String', 'hashed_secret': 'def456'},
                    {'type': 'Base64 High Entropy String', 'hashed_secret': 'abc123'},
                ],
            },
        }
        path = tmp_path / '.secrets.baseline'
        path.write_text(json.dumps(baseline))

        assert load_fingerprints_from_baseline(str(path)) == {'abc123', 'def456'}

    def test_empty_results(self, tmp_path):
        path = tmp_path / '.secrets.baseline'
        path.write_text(json.dumps({'version': '1.5.0', 'results': {}}))

        assert load_fingerprints_from_baseline(str(path)) == set()
