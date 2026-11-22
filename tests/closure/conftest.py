from datetime import datetime
from datetime import timedelta

import pytest

from detect_secrets.closure.model import BranchScope
from detect_secrets.closure.model import EvidenceBundle
from detect_secrets.closure.model import RotationReceipt
from detect_secrets.closure.model import RotationWindow


FINGERPRINT = 'a' * 40
OTHER_FINGERPRINT = 'b' * 64
AS_OF = datetime(2026, 11, 23, 12, 0, 0)


def make_window(**overrides):
    values = {
        'opens_at': AS_OF - timedelta(days=7),
        'closes_at': AS_OF + timedelta(days=7),
    }
    values.update(overrides)
    return RotationWindow(**values)


def make_receipt(receipt_id='RT-1', **overrides):
    values = {
        'receipt_id': receipt_id,
        'fingerprint': FINGERPRINT,
        'window': make_window(),
        'environment': 'prod',
        'revocation_scope': frozenset({'main'}),
    }
    values.update(overrides)
    return RotationReceipt(**values)


def make_scope(**overrides):
    values = {
        'name': 'release-freeze',
        'branches': frozenset({'main', 'maint/1.x'}),
        'frozen_at': '2026-11-20T00:00:00',
    }
    values.update(overrides)
    return BranchScope(**values)


def make_bundle(receipts=None, **overrides):
    values = {
        'version': 1,
        'fingerprint': FINGERPRINT,
        'environment': 'prod',
        'evaluated_at': AS_OF,
        'scope': make_scope(),
        'receipts': tuple(receipts if receipts is not None else [make_receipt()]),
    }
    values.update(overrides)
    return EvidenceBundle(**values)


@pytest.fixture
def bundle():
    return make_bundle()
