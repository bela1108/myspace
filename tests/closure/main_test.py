import json

from detect_secrets.closure.__main__ import main
from detect_secrets.closure.io import load_case
from detect_secrets.closure.io import save_case
from detect_secrets.closure.model import ReceiptKind
from tests.closure.conftest import FINGERPRINT
from tests.closure.conftest import make_bundle
from tests.closure.conftest import make_receipt
from tests.closure.conftest import make_scope


def write_case(tmp_path, bundle=None):
    path = str(tmp_path / 'case.json')
    save_case(bundle or make_bundle(), path)
    return path


def test_evaluate_text_output(tmp_path, capsys):
    assert main(['evaluate', write_case(tmp_path)]) == 0

    out = capsys.readouterr().out
    assert 'fingerprint: {}'.format(FINGERPRINT) in out
    assert 'evidence version: 1' in out
    assert 'branch main: CLOSABLE' in out
    assert 'branch maint/1.x: OPEN' in out
    assert 'no receipt revokes the identifier on this branch' in out


def test_evaluate_json_output(tmp_path, capsys):
    assert main(['evaluate', write_case(tmp_path), '--json']) == 0

    payload = json.loads(capsys.readouterr().out)
    assert payload['closable_branches'] == ['main']
    assert payload['open_branches'] == ['maint/1.x']
    assert payload['evidence_version'] == 1


def test_evaluate_as_of_override(tmp_path, capsys):
    assert main(['evaluate', write_case(tmp_path), '--as-of', '2030-01-01T00:00:00']) == 0

    out = capsys.readouterr().out
    assert 'branch main: OPEN' in out
    assert 'window' in out


def test_revoke_reopens_branch_and_persists_version(tmp_path, capsys):
    bundle = make_bundle(
        version=3,
        receipts=[
            make_receipt('RT-1'),
            make_receipt(
                'RT-TEST',
                kind=ReceiptKind.TEST,
                revocation_scope=frozenset({'maint/1.x'}),
            ),
        ],
    )
    path = write_case(tmp_path, bundle)

    assert main(['revoke', path, 'RT-TEST']) == 0

    out = capsys.readouterr().out
    assert 'original decision held under evidence version 3' in out
    assert 'current evidence version: 4' in out
    assert 'reopened branches: maint/1.x' in out
    assert 'still closable: main' in out

    persisted = load_case(path)
    assert persisted.version == 4


def test_revoke_json_output(tmp_path, capsys):
    path = write_case(tmp_path)
    assert main(['revoke', path, 'RT-1', '--json']) == 0

    payload = json.loads(capsys.readouterr().out)
    assert payload['reopened'] == ['main']
    assert payload['still_open'] == ['maint/1.x']


def test_revoke_to_separate_output_file(tmp_path, capsys):
    path = write_case(tmp_path)
    out_path = str(tmp_path / 'updated.json')
    assert main(['revoke', path, 'RT-1', '--out', out_path]) == 0

    assert load_case(path).version == 1
    assert load_case(out_path).version == 2


def test_revoke_unknown_receipt_fails(tmp_path, capsys):
    assert main(['revoke', write_case(tmp_path), 'RT-404']) == 1
    assert 'RT-404' in capsys.readouterr().err


def test_fingerprints_lists_baseline_hashes(tmp_path, capsys):
    baseline = {
        'version': '1.5.0',
        'results': {'a.py': [{'hashed_secret': FINGERPRINT, 'type': 'Secret Keyword'}]},
    }
    path = tmp_path / '.secrets.baseline'
    path.write_text(json.dumps(baseline))

    assert main(['fingerprints', str(path)]) == 0
    assert capsys.readouterr().out.strip() == FINGERPRINT

    assert main(['fingerprints', str(path), '--json']) == 0
    assert json.loads(capsys.readouterr().out) == [FINGERPRINT]


def test_frozen_scope_is_respected(tmp_path, capsys):
    # a receipt claiming a branch outside the frozen scope must not close it
    bundle = make_bundle(
        scope=make_scope(branches=frozenset({'main'})),
        receipts=[make_receipt(revocation_scope=frozenset({'main', 'maint/1.x'}))],
    )
    assert main(['evaluate', write_case(tmp_path, bundle)]) == 0

    out = capsys.readouterr().out
    assert 'branch main: OPEN' in out
    assert 'outside the frozen scope' in out
