import json

import pytest

from detect_secrets.audit import scheduler
from detect_secrets.audit.scheduler import ReviewCandidate
from detect_secrets.audit.scheduler import ReviewerGroup
from detect_secrets.core import baseline
from detect_secrets.core.potential_secret import PotentialSecret
from detect_secrets.core.secrets_collection import SecretsCollection
from detect_secrets.main import main
from testing.factories import potential_secret_factory
from testing.mocks import mock_named_temporary_file


def make_baseline(secrets):
    collection = SecretsCollection()
    for index, secret in enumerate(secrets):
        collection[f'file{index}'].add(secret)
    return collection


def make_groups():
    return [
        ReviewerGroup(name='team-a', weekly_hours=1.0, projects=frozenset({'projA'})),
        ReviewerGroup(
            name='team-shared',
            weekly_hours=1.0,
            projects=frozenset({'projA', 'projB'}),
        ),
    ]


class TestCandidateCollection:
    def test_shared_candidate_is_merged_across_projects(self):
        baselines = {
            'projA': make_baseline([potential_secret_factory(secret='shared')]),
            'projB': make_baseline([potential_secret_factory(secret='shared')]),
        }

        candidates = scheduler.collect_candidates(baselines)

        assert len(candidates) == 1
        assert candidates[0].projects == {'projA', 'projB'}

    def test_labelled_secrets_are_not_candidates(self):
        baselines = {
            'projA': make_baseline([
                potential_secret_factory(secret='real', is_secret=True),
                potential_secret_factory(secret='false', is_secret=False),
            ]),
        }

        assert scheduler.collect_candidates(baselines) == []


class TestGreedyScheduling:
    def test_shared_candidate_consumes_review_time_once(self):
        baselines = {
            'projA': make_baseline([potential_secret_factory(secret='shared')]),
            'projB': make_baseline([potential_secret_factory(secret='shared')]),
        }
        candidates = scheduler.collect_candidates(baselines)

        schedule = scheduler.schedule_review(candidates, make_groups())
        output = schedule.json()

        assert len(output['tasks']) == 1
        assert output['tasks'][0]['group'] == 'team-shared'
        assert output['capacity']['team-shared']['assigned_hours'] == 0.5
        assert output['capacity']['team-a']['assigned_hours'] == 0.0
        assert output['gaps']['unscheduled_tasks'] == 0

    def test_shared_candidate_requires_permission_for_every_project(self):
        groups = [
            # This group has plenty of capacity, but may not receive projB.
            ReviewerGroup(name='team-a', weekly_hours=10.0, projects=frozenset({'projA'})),
            ReviewerGroup(
                name='team-shared',
                weekly_hours=0.5,
                projects=frozenset({'projA', 'projB'}),
            ),
        ]
        candidates = scheduler.collect_candidates({
            'projA': make_baseline([potential_secret_factory(secret='shared')]),
            'projB': make_baseline([potential_secret_factory(secret='shared')]),
        })

        schedule = scheduler.schedule_review(candidates, groups)

        assert len(schedule.assignments) == 1
        assert schedule.assignments[0][1].name == 'team-shared'

    def test_weekly_hour_cap_is_enforced_and_gap_is_reported(self):
        groups = [
            ReviewerGroup(name='team-a', weekly_hours=0.5, projects=frozenset({'projA'})),
        ]
        candidates = scheduler.collect_candidates({
            'projA': make_baseline([
                potential_secret_factory(secret='one'),
                potential_secret_factory(secret='two'),
            ]),
        })

        output = scheduler.schedule_review(candidates, groups).json()

        assert len(output['tasks']) == 1
        assert output['capacity']['team-a']['remaining_hours'] == 0.0
        assert output['gaps']['unscheduled_tasks'] == 1
        assert output['gaps']['unscheduled_hours'] == 0.5
        assert output['gaps']['projects'] == {
            'projA': {'unscheduled_tasks': 1, 'unscheduled_hours': 0.5},
        }

    def test_no_eligible_group_means_gap(self):
        candidates = scheduler.collect_candidates({
            'projC': make_baseline([potential_secret_factory(secret='one')]),
        })

        output = scheduler.schedule_review(candidates, make_groups()).json()

        assert output['tasks'] == []
        assert output['gaps']['unscheduled_tasks'] == 1


class TestOutputPrivacy:
    def test_task_ids_are_randomized_per_run(self):
        candidates = scheduler.collect_candidates({
            'projA': make_baseline([potential_secret_factory(secret='one')]),
        })

        first = scheduler.schedule_review(candidates, make_groups()).json()
        second = scheduler.schedule_review(candidates, make_groups()).json()

        assert first['tasks'][0]['task_id'] != second['tasks'][0]['task_id']

    def test_output_has_no_content_or_stable_fingerprint(self):
        secret = potential_secret_factory(secret='s3cr3t-value')
        candidates = scheduler.collect_candidates({
            'projA': make_baseline([secret]),
        })

        serialized = json.dumps(scheduler.schedule_review(candidates, make_groups()).json())

        assert 's3cr3t-value' not in serialized
        assert secret.secret_hash not in serialized
        assert PotentialSecret.hash_secret('s3cr3t-value') not in serialized


class TestExhaustiveComparison:
    def test_greedy_matches_exhaustive_on_small_baseline(self):
        baselines = {
            'projA': make_baseline([
                potential_secret_factory(secret='shared'),
                potential_secret_factory(secret='a1'),
                potential_secret_factory(secret='a2'),
            ]),
            'projB': make_baseline([
                potential_secret_factory(secret='shared'),
                potential_secret_factory(secret='b1'),
            ]),
        }
        candidates = scheduler.collect_candidates(baselines)
        groups = make_groups()

        greedy = scheduler.schedule_review(candidates, groups)
        optimal = scheduler.exhaustive_schedule(candidates, groups)

        assert greedy.unscheduled_hours == pytest.approx(optimal.unscheduled_hours)
        assert greedy.json()['gaps'] == optimal.json()['gaps']

    def test_worst_branch_is_bounded_by_exhaustive_optimum(self):
        # A known bad case for the greedy scheduler: placing the {B, C}
        # candidate first (it is the most constrained) consumes the only
        # capacity that could have taken the {A, B} candidate.
        groups = [
            ReviewerGroup(name='G0', weekly_hours=1.0, projects=frozenset({'A', 'B'})),
            ReviewerGroup(name='G1', weekly_hours=0.5, projects=frozenset({'A', 'B', 'C'})),
        ]
        candidates = [
            ReviewCandidate(key=('type', 's0'), projects={'B'}, hours=0.5),
            ReviewCandidate(key=('type', 's1'), projects={'A', 'B'}, hours=0.5),
            ReviewCandidate(key=('type', 's2'), projects={'B', 'C'}, hours=0.3),
            ReviewCandidate(key=('type', 's3'), projects={'B'}, hours=0.5),
        ]

        greedy = scheduler.schedule_review(candidates, groups)
        optimal = scheduler.exhaustive_schedule(candidates, groups)

        # The exhaustive solver finds a better branch than the greedy one.
        assert greedy.unscheduled_hours == pytest.approx(0.5)
        assert optimal.unscheduled_hours == pytest.approx(0.3)
        assert optimal.unscheduled_hours <= greedy.unscheduled_hours

        # ... and the greedy schedule still honestly reports its own gap.
        gaps = greedy.json()['gaps']
        assert gaps['unscheduled_tasks'] == 1
        assert gaps['unscheduled_hours'] == pytest.approx(0.5)

    def test_exhaustive_search_refuses_large_inputs(self):
        candidates = [
            ReviewCandidate(key=('type', f's{index}'), projects={'A'}, hours=0.5)
            for index in range(scheduler.EXHAUSTIVE_SEARCH_LIMIT + 1)
        ]

        with pytest.raises(ValueError):
            scheduler.exhaustive_schedule(candidates, make_groups())


class TestGroupLoading:
    def test_load_groups_from_file(self):
        with mock_named_temporary_file(mode='w', suffix='.json') as f:
            json.dump(
                [{'name': 'team-a', 'weekly_hours': 2.0, 'projects': ['projA']}],
                f,
            )
            f.seek(0)

            groups = scheduler.load_groups_from_file(f.name)

        assert groups == [
            ReviewerGroup(name='team-a', weekly_hours=2.0, projects=frozenset({'projA'})),
        ]

    @pytest.mark.parametrize(
        'spec',
        (
            [{'weekly_hours': 2.0, 'projects': ['projA']}],      # missing name
            [{'name': 'team-a', 'weekly_hours': -1.0, 'projects': []}],
            [{'name': 'dup', 'weekly_hours': 1.0, 'projects': []}] * 2,
            [],                                                   # no groups at all
        ),
    )
    def test_load_groups_from_file_rejects_invalid_specs(self, spec):
        with mock_named_temporary_file(mode='w', suffix='.json') as f:
            json.dump(spec, f)
            f.seek(0)

            with pytest.raises(ValueError):
                scheduler.load_groups_from_file(f.name)


class TestMain:
    def test_schedule_end_to_end(self, printer):
        with mock_named_temporary_file() as baseline_a, \
                mock_named_temporary_file() as baseline_b, \
                mock_named_temporary_file(mode='w', suffix='.json') as groups_file:
            baseline.save_to_file(
                make_baseline([
                    potential_secret_factory(secret='shared'),
                    potential_secret_factory(secret='only-a'),
                ]),
                baseline_a.name,
            )
            baseline.save_to_file(
                make_baseline([potential_secret_factory(secret='shared')]),
                baseline_b.name,
            )
            json.dump(
                [
                    {
                        'name': 'team-shared',
                        'weekly_hours': 0.5,
                        'projects': [baseline_a.name, baseline_b.name],
                    },
                    {
                        'name': 'team-a',
                        'weekly_hours': 0.5,
                        'projects': [baseline_a.name],
                    },
                ],
                groups_file,
            )
            groups_file.seek(0)

            main([
                'audit', baseline_a.name, baseline_b.name,
                '--schedule', '--groups', groups_file.name,
            ])

        output = json.loads(printer.message)
        assert len(output['tasks']) == 2
        assert output['gaps']['unscheduled_tasks'] == 0
        assert output['capacity']['team-shared']['assigned_hours'] == 0.5
        assert output['capacity']['team-a']['assigned_hours'] == 0.5

        shared_task = [
            task
            for task in output['tasks']
            if len(task['projects']) == 2
        ]
        assert len(shared_task) == 1
        assert shared_task[0]['group'] == 'team-shared'

    def test_schedule_requires_groups(self):
        with pytest.raises(SystemExit):
            main(['audit', 'baseline.json', '--schedule'])
