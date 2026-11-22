import json

from detect_secrets.closure.engine import ClosureEngine
from detect_secrets.closure.engine import diff_reports
from detect_secrets.closure.io import diff_to_dict
from detect_secrets.closure.io import fingerprints_from_baseline
from detect_secrets.closure.io import load_case
from detect_secrets.closure.io import parse_datetime
from detect_secrets.closure.io import report_to_dict
from detect_secrets.closure.io import save_case
from detect_secrets.closure.model import ReceiptKind
from detect_secrets.closure.model import ReceiptStatus
from tests.closure.conftest import AS_OF
from tests.closure.conftest import FINGERPRINT
from tests.closure.conftest import make_bundle
from tests.closure.conftest import make_receipt


def test_parse_datetime_accepts_z_suffix():
    assert parse_datetime('2026-11-23T12:00:00Z').isoformat() == '2026-11-23T12:00:00+00:00'


def test_case_round_trip(tmp_path):
    bundle = make_bundle(receipts=[
        make_receipt('RT-1'),
        make_receipt(
            'RT-2',
            kind=ReceiptKind.TEST,
            revocation_scope=frozenset({'maint/1.x'}),
            based_on='RT-1',
        ),
    ])
    path = str(tmp_path / 'case.json')
    save_case(bundle, path)

    loaded = load_case(path)
    assert loaded == bundle
    assert loaded.receipts[1].kind is ReceiptKind.TEST
    assert loaded.receipts[1].based_on == 'RT-1'


def test_revoked_status_survives_round_trip(tmp_path):
    bundle = make_bundle().with_revocation('RT-1')
    path = str(tmp_path / 'case.json')
    save_case(bundle, path)

    loaded = load_case(path)
    assert loaded.version == 2
    assert loaded.receipts[0].status is ReceiptStatus.REVOKED


def test_report_and_diff_serialize_to_json():
    engine = ClosureEngine(make_bundle())
    original = engine.evaluate()
    engine.revoke('RT-1')
    current = engine.evaluate()

    json.dumps(report_to_dict(original))
    payload = json.loads(json.dumps(diff_to_dict(diff_reports(original, current))))
    assert payload['reopened'] == ['main']
    assert payload['original_evidence_version'] == 1
    assert payload['current_evidence_version'] == 2


def test_fingerprints_from_baseline_reads_only_hashes(tmp_path):
    baseline = {
        'version': '1.5.0',
        'results': {
            'a.py': [
                {'hashed_secret': FINGERPRINT, 'type': 'Secret Keyword'},
                {'hashed_secret': 'b' * 40, 'type': 'Secret Keyword'},
            ],
            'b.py': [
                {'hashed_secret': FINGERPRINT, 'type': 'Secret Keyword'},
            ],
        },
    }
    path = tmp_path / '.secrets.baseline'
    path.write_text(json.dumps(baseline))

    assert fingerprints_from_baseline(str(path)) == sorted({FINGERPRINT, 'b' * 40})


def test_fingerprints_from_empty_baseline(tmp_path):
    path = tmp_path / '.secrets.baseline'
    path.write_text(json.dumps({'version': '1.5.0', 'results': {}}))
    assert fingerprints_from_baseline(str(path)) == []


def test_loaded_bundle_evaluates(tmp_path):
    path = str(tmp_path / 'case.json')
    save_case(make_bundle(), path)

    report = ClosureEngine(load_case(path)).evaluate()
    assert report.evaluated_at == AS_OF
    assert report.closable_branches == ('main',)
