import json
from pathlib import Path

from generate_plan import build_findings
from generate_plan import evidence_alias
from generate_plan import main


DATA_DIR = Path(__file__).parent / 'data'


def run_plan(tmp_path):
    output_dir = tmp_path / 'out'
    assert main([
        '--baseline', str(DATA_DIR / 'baseline.json'),
        '--roster', str(DATA_DIR / 'roster.json'),
        '--output-dir', str(output_dir),
    ]) == 0
    return output_dir


def load(output_dir, name):
    with open(output_dir / name) as f:
        return json.load(f)


def test_two_seats_per_assigned_finding(tmp_path):
    internal = load(run_plan(tmp_path), 'plan_internal.json')
    assert len(internal['assignments']) == 3
    for assignment in internal['assignments']:
        assert len(assignment['reviewers']) == 2
        assert len(set(assignment['reviewers'])) == 2


def test_unassigned_finding_is_explainable(tmp_path):
    internal = load(run_plan(tmp_path), 'plan_internal.json')
    assert len(internal['unassigned']) == 1
    entry = internal['unassigned'][0]
    assert entry['candidate_id'] == 'FND-004'
    assert entry['seats_filled'] < entry['seats_required']
    reasons = '\n'.join(entry['explanations'])
    assert 'absent' in reasons
    assert 'recent author' in reasons
    assert 'clearance' in reasons


def test_substitute_only_covers_within_boundary(tmp_path):
    internal = load(run_plan(tmp_path), 'plan_internal.json')
    seat_directory = internal['seat_directory']
    erin_seat = {v: k for k, v in seat_directory.items()}['erin']
    erin_findings = [
        a for a in internal['assignments'] if erin_seat in a['seats']
    ]
    assert len(erin_findings) == 1
    assert not erin_findings[0]['filename'].startswith('tests/')


def test_external_manifest_hides_paths_and_reasons(tmp_path):
    output_dir = run_plan(tmp_path)
    manifest = load(output_dir, 'distribution_manifest.json')
    raw = json.dumps(manifest)
    for item in manifest['seats'].values():
        for entry in item:
            assert set(entry.keys()) == {'candidate_id', 'evidence_alias'}
    for forbidden in ('src/', 'tests/', 'hashed_secret', 'absent', 'author'):
        assert forbidden not in raw
    assert 'FND-004' not in raw


def test_seat_files_only_contain_own_materials(tmp_path):
    output_dir = run_plan(tmp_path)
    manifest = load(output_dir, 'distribution_manifest.json')
    for token, items in manifest['seats'].items():
        seat_file = load(output_dir / 'seats', '{}.json'.format(token))
        assert seat_file['seat'] == token
        assert seat_file['items'] == items


def test_evidence_alias_is_deterministic_and_one_way(tmp_path):
    baseline = json.loads((DATA_DIR / 'baseline.json').read_text())
    findings = build_findings(baseline)
    first = findings[0]
    alias_a = evidence_alias(
        first['candidate_id'], first['filename'], first['hashed_secret'],
    )
    alias_b = evidence_alias(
        first['candidate_id'], first['filename'], first['hashed_secret'],
    )
    assert alias_a == alias_b
    assert first['filename'] not in alias_a
    assert first['hashed_secret'] not in alias_a
