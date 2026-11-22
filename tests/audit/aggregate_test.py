import json

from detect_secrets.audit import aggregate
from detect_secrets.main import main


def _alerts(counts):
    output = []
    for group, count in counts.items():
        for index in range(count):
            output.append({
                'id': '%s-%s' % (group, index),
                'person': '%s-person-%s' % (group, index),
                'group': group,
                'is_secret': True,
            })
    return {'alerts': output}


BOUNDARIES = {
    'teams': {
        'team-a': ['team-a-person-%s' % i for i in range(6)],
        'team-b': ['team-b-person-%s' % i for i in range(6)],
    },
    'minimum_group_size': 5,
}


def test_release_sequence_blocks_then_approves_merged_group():
    first = aggregate.aggregate(
        _alerts({'team-a': 5, 'team-b': 5}),
        team_boundaries=BOUNDARIES,
        report_id='report-1',
    )
    assert first['approved'] is True
    assert first['external']['group_counts'] == {'team-a': 5, 'team-b': 5}

    second = aggregate.aggregate(
        _alerts({'team-a': 6, 'team-b': 5}),
        team_boundaries=BOUNDARIES,
        report_id='report-2',
        history=[first],
    )
    assert second['approved'] is False
    assert second['external']['group_counts'] == {'team-b': 5}
    assert second['receipt']['restricted_groups'][0]['group'] == 'team-a'
    assert second['receipt']['restricted_groups'][0]['history_report_ids'] == ['report-1']
    assert second['receipt']['history_report_ids'] == ['report-1']

    merged = aggregate.aggregate(
        _alerts({'team-a': 6, 'team-b': 5}),
        team_boundaries=BOUNDARIES,
        report_id='report-3',
        history=[first],
        merge_groups={'team-a': 'merged', 'team-b': 'merged'},
    )
    assert merged['approved'] is True
    assert merged['external']['group_counts'] == {'merged': 11}
    assert merged['receipt']['restricted_groups'] == []


def test_historical_baseline_path_is_checked():
    result = aggregate.aggregate(
        _alerts({'team-a': 5}),
        team_boundaries=BOUNDARIES,
        report_id='only-current',
        history=[{'report_id': 'checked-out-v1', 'groups': {'team-a': 4}}],
    )
    assert result['approved'] is False
    assert result['receipt']['history_report_ids'] == ['checked-out-v1']


def test_external_report_contains_only_approved_groups():
    result = aggregate.aggregate(
        _alerts({'team-a': 5, 'team-b': 1}),
        team_boundaries=BOUNDARIES,
        report_id='partial',
    )
    assert result['approved'] is True
    assert result['external']['group_counts'] == {'team-a': 5}
    assert result['external']['groups'] == [
        {'group': 'team-a', 'count': 5, 'contributors': 5},
    ]
    assert result['receipt']['restricted_groups'][0]['group'] == 'team-b'
    assert result['receipt']['restricted_groups'][0]['reasons'][0]['code'] == 'below_minimum_group_size'



def test_cli_entry_points_use_the_same_review(tmp_path, printer):
    current = tmp_path / 'current.json'
    current.write_text(json.dumps(_alerts({'team-a': 5, 'team-b': 5})))

    teams = tmp_path / 'teams.json'
    teams.write_text(json.dumps(BOUNDARIES))

    main([
        'aggregate',
        str(current),
        '--team-boundaries', str(teams),
        '--report-id', 'cli-1',
    ])
    first = json.loads(printer.message)
    assert first['approved'] is True
    printer.clear()

    history = tmp_path / 'history.json'
    history.write_text(json.dumps(first['external']))

    next_report = tmp_path / 'next.json'
    next_report.write_text(json.dumps(_alerts({'team-a': 6, 'team-b': 5})))

    main([
        'audit',
        '--aggregate',
        str(next_report),
        '--team-boundaries', str(teams),
        '--history', str(history),
        '--report-id', 'cli-2',
    ])
    second = json.loads(printer.message)
    assert second['approved'] is False
    assert second['receipt']['history_report_ids'] == ['cli-1']
