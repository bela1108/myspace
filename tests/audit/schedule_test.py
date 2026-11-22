import itertools
import json
import random

import pytest

from detect_secrets import main as main_module
from detect_secrets.audit import schedule


def make_plan(
    groups=None,
    candidates=None,
    projects=None,
    tags=None,
    weeks=None,
):
    data = {
        'groups': groups if groups is not None else [
            {'name': 'general', 'hours': 4, 'capabilities': ['general']},
        ],
        'candidates': candidates if candidates is not None else [],
    }
    if projects is not None:
        data['projects'] = projects
    if tags is not None:
        data['tags'] = tags
    if weeks is not None:
        data['weeks'] = weeks
    return schedule.parse_plan(data)


def eligible_indices(plan, candidate):
    eligible = {group.name for group in plan.eligible_groups(candidate)}
    return [
        index
        for index, group in enumerate(plan.groups)
        if group.name in eligible
    ]


def brute_force_coverage(plan):
    candidates = plan.candidates
    capacities = [
        schedule._scale(group.hours) * plan.weeks
        for group in plan.groups
    ]
    eligible = [eligible_indices(plan, candidate) for candidate in candidates]
    choices = [
        list(group_indices) + [len(plan.groups)]
        for group_indices in eligible
    ]

    best = (0, 0, 0, 0)
    for assignment in itertools.product(*choices):
        loads = [0 for _ in capacities]
        weight = 0
        priority = 0
        hours = 0
        count = 0
        feasible = True
        for index, group_number in enumerate(assignment):
            if group_number == len(plan.groups):
                continue
            item_hours = schedule._scale(candidates[index].hours)
            loads[group_number] += item_hours
            if loads[group_number] > capacities[group_number]:
                feasible = False
                break
            weight += schedule._scale(candidates[index].weight)
            priority += schedule._scale(candidates[index].priority)
            hours += item_hours
            count += 1
        if not feasible:
            continue
        score = (weight, priority, -hours, count)
        if score > best:
            best = score
    return best


def brute_force_min_overflow(plan):
    candidates = [
        candidate
        for candidate in plan.candidates
        if eligible_indices(plan, candidate)
    ]
    capacities = [
        schedule._scale(group.hours) * plan.weeks
        for group in plan.groups
    ]
    eligible = [eligible_indices(plan, candidate) for candidate in candidates]

    if not candidates:
        return 0

    best = None
    for assignment in itertools.product(*eligible):
        loads = [0 for _ in capacities]
        for index, group_number in enumerate(assignment):
            loads[group_number] += schedule._scale(candidates[index].hours)
        overflow = sum(
            max(0, load - capacity)
            for load, capacity in zip(loads, capacities)
        )
        if best is None or overflow < best:
            best = overflow
    return best


def random_plan(rng, candidate_count, group_count):
    groups = [
        {
            'name': f'g{index}',
            'hours': rng.choice([1, 1.5, 2, 3]),
            'capabilities': ['general'],
        }
        for index in range(group_count)
    ]
    projects = [
        {
            'name': f'p{index}',
            'allowed_groups': [
                group['name']
                for group in groups
                if rng.random() < 0.75
            ],
        }
        for index in range(2)
    ]
    candidates = []
    for index in range(candidate_count):
        project_count = rng.choice([1, 1, 2])
        candidates.append(
            {
                'id': f'c{index}',
                'hours': rng.choice([0.5, 1, 1.5, 2]),
                'projects': [
                    f'p{project_index}'
                    for project_index in rng.sample(range(2), project_count)
                ],
                'capabilities': ['general'],
            },
        )
    return schedule.parse_plan(
        {
            'groups': groups,
            'projects': projects,
            'candidates': candidates,
        },
    )


class TestSharedCandidates:
    @staticmethod
    def test_shared_candidate_is_reviewed_once_and_covers_both_projects():
        plan = make_plan(
            groups=[{'name': 'g', 'hours': 1.5, 'capabilities': ['net']}],
            projects=[
                {'name': 'p1', 'allowed_groups': ['g']},
                {'name': 'p2', 'allowed_groups': ['g']},
            ],
            candidates=[
                {
                    'id': 'shared',
                    'hours': 1,
                    'projects': ['p1', 'p2'],
                    'capabilities': ['net'],
                },
            ],
        )

        result = schedule.build_schedule(plan, seed=1)

        assert len(result.tasks) == 1
        assert result.tasks[0].start == 0
        assert result.tasks[0].end == 1
        assert result.covered_weight == 2
        assert result.scheduled_hours == 1
        assert result.gap is None

    @staticmethod
    def test_shared_candidate_needs_a_reviewer_every_project_accepts():
        plan = make_plan(
            groups=[
                {'name': 'g1', 'hours': 3},
                {'name': 'g2', 'hours': 3},
            ],
            projects=[
                {'name': 'p1', 'allowed_groups': ['g1']},
                {'name': 'p2', 'allowed_groups': ['g2']},
            ],
            candidates=[
                {'id': 'shared', 'hours': 1, 'projects': ['p1', 'p2']},
            ],
        )

        result = schedule.build_schedule(plan, seed=1)

        assert not result.tasks
        assert result.gap is not None
        assert result.gap.minimum_extra_hours == 0
        assert result.gap.structural_gaps == [
            {
                'candidate': 'shared',
                'reason': 'permission',
                'projects': ['p1', 'p2'],
                'capable_groups': ['g1', 'g2'],
                'project_allowed_groups': {'p1': ['g1'], 'p2': ['g2']},
                'required_capabilities': [],
                'detail': 'No single group is authorized by every associated project.',
            },
        ]

    @staticmethod
    def test_separate_candidates_can_still_cover_the_projects():
        plan = make_plan(
            groups=[
                {'name': 'g1', 'hours': 3},
                {'name': 'g2', 'hours': 3},
            ],
            projects=[
                {'name': 'p1', 'allowed_groups': ['g1']},
                {'name': 'p2', 'allowed_groups': ['g2']},
            ],
            candidates=[
                {'id': 'a', 'hours': 1, 'projects': ['p1']},
                {'id': 'b', 'hours': 1, 'projects': ['p2']},
            ],
        )

        result = schedule.build_schedule(plan, seed=1)

        assert {task.candidate.id for task in result.tasks} == {'a', 'b'}
        assert result.gap is None


class TestPermissionsAndTags:
    @staticmethod
    def test_candidate_tag_requires_capability():
        plan = make_plan(
            groups=[
                {'name': 'general', 'hours': 2, 'capabilities': ['general']},
                {'name': 'oncall', 'hours': 2, 'capabilities': ['general', 'oncall']},
            ],
            tags={'oncall': {'capabilities': ['oncall'], 'priority': 5}},
            candidates=[
                {'id': 'c', 'hours': 1, 'tags': ['oncall']},
            ],
        )

        result = schedule.build_schedule(plan, seed=1)

        assert [task.group for task in result.tasks] == ['oncall']
        assert result.tasks[0].required_capabilities == ('oncall',)
        assert result.tasks[0].candidate.priority == 5

    @staticmethod
    def test_project_capability_restricts_reviewer_pool():
        plan = make_plan(
            groups=[
                {'name': 'general', 'hours': 2, 'capabilities': ['general']},
                {'name': 'oncall', 'hours': 2, 'capabilities': ['general', 'oncall']},
            ],
            projects=[
                {
                    'name': 'infra',
                    'allowed_groups': ['general', 'oncall'],
                    'required_capabilities': ['oncall'],
                },
            ],
            candidates=[
                {'id': 'c', 'hours': 1, 'projects': ['infra']},
            ],
        )

        result = schedule.build_schedule(plan, seed=1)

        assert [task.group for task in result.tasks] == ['oncall']
        assert result.tasks[0].required_capabilities == ('oncall',)

    @staticmethod
    def test_candidate_visibility_can_be_restricted():
        plan = make_plan(
            groups=[
                {'name': 'general', 'hours': 2},
                {'name': 'expert', 'hours': 2},
            ],
            candidates=[
                {'id': 'c', 'hours': 1, 'visible_to': ['expert']},
            ],
        )

        result = schedule.build_schedule(plan, seed=1)

        assert [task.group for task in result.tasks] == ['expert']

    @staticmethod
    def test_missing_capability_is_reported_as_structural_gap():
        plan = make_plan(
            groups=[{'name': 'g', 'hours': 2, 'capabilities': ['general']}],
            candidates=[{'id': 'c', 'hours': 1, 'capabilities': ['oncall']}],
        )

        result = schedule.build_schedule(plan, seed=1)

        assert result.gap is not None
        assert result.gap.structural_gaps[0]['reason'] == 'capability'
        assert result.gap.structural_gaps[0]['missing_capabilities'] == ['oncall']


class TestCapacityGap:
    @staticmethod
    def test_gap_accounts_for_indivisible_tasks():
        plan = make_plan(
            groups=[{'name': 'g', 'hours': 10}],
            candidates=[
                {'id': 'a', 'hours': 6},
                {'id': 'b', 'hours': 6},
            ],
        )

        result = schedule.build_schedule(plan, seed=1)

        assert len(result.tasks) == 1
        assert result.gap is not None
        assert result.gap.minimum_extra_hours == 2
        assert result.gap.extra_by_group == {'g': 2}
        assert result.gap.binding_groups == ['g']

    @staticmethod
    def test_gap_uses_slack_before_adding_hours():
        plan = make_plan(
            groups=[{'name': 'g', 'hours': 3}],
            candidates=[
                {'id': 'a', 'hours': 2},
                {'id': 'b', 'hours': 2},
            ],
        )

        result = schedule.build_schedule(plan, seed=1)

        assert result.gap is not None
        assert result.gap.minimum_extra_hours == 1

    @staticmethod
    def test_weeks_multiply_capacity():
        plan = make_plan(
            groups=[{'name': 'g', 'hours': 3}],
            candidates=[
                {'id': 'a', 'hours': 2},
                {'id': 'b', 'hours': 2},
            ],
            weeks=2,
        )

        result = schedule.build_schedule(plan, seed=1)

        assert len(result.tasks) == 2
        assert result.gap is None

    @staticmethod
    def test_priority_controls_order_inside_a_group():
        plan = make_plan(
            groups=[{'name': 'g', 'hours': 10}],
            candidates=[
                {'id': 'low', 'hours': 1, 'priority': 1},
                {'id': 'high', 'hours': 1, 'priority': 10},
            ],
        )

        result = schedule.build_schedule(plan, seed=1)

        assert [task.candidate.id for task in result.tasks] == ['high', 'low']
        assert [task.group_order for task in result.tasks] == [1, 2]
        assert [task.start for task in result.tasks] == [0, 1]


class TestExport:
    @staticmethod
    def test_export_contains_only_random_id_order_and_capabilities():
        plan = make_plan(
            groups=[{'name': 'g', 'hours': 4, 'capabilities': ['net']}],
            candidates=[
                {
                    'id': 'secret-candidate',
                    'hours': 1,
                    'projects': ['payments'],
                    'capabilities': ['net'],
                },
            ],
        )

        result = schedule.build_schedule(plan, seed=7)
        exported = schedule.export_schedule(result)

        assert exported == [
            {
                'task_id': result.tasks[0].task_id,
                'order': 1,
                'capabilities': ['net'],
            },
        ]
        assert set(exported[0]) == {'task_id', 'order', 'capabilities'}
        serialized = json.dumps(exported)
        assert 'secret-candidate' not in serialized
        assert 'payments' not in serialized
        assert 'g"' not in serialized

    @staticmethod
    def test_task_ids_are_reproducible_with_a_seed():
        plan = make_plan(
            groups=[{'name': 'g', 'hours': 4}],
            candidates=[{'id': 'a', 'hours': 1}, {'id': 'b', 'hours': 1}],
        )

        first = schedule.export_schedule(schedule.build_schedule(plan, seed='seed'))
        second = schedule.export_schedule(schedule.build_schedule(plan, seed='seed'))
        third = schedule.export_schedule(schedule.build_schedule(plan, seed='other'))

        assert first == second
        assert first != third

    @staticmethod
    def test_write_export(tmp_path):
        plan = make_plan(candidates=[{'id': 'a', 'hours': 1}])
        result = schedule.build_schedule(plan, seed=1)
        path = tmp_path / 'schedule.json'

        schedule.write_export(result, str(path))

        assert json.loads(path.read_text()) == schedule.export_schedule(result)


class TestOptimalityAgainstBruteForce:
    @staticmethod
    @pytest.mark.parametrize('seed', range(12))
    def test_coverage_and_schedule_match_brute_force(seed):
        rng = random.Random(seed)
        plan = random_plan(
            rng,
            candidate_count=rng.randint(1, 6),
            group_count=rng.randint(1, 3),
        )

        result = schedule.build_schedule(plan, seed=seed)
        (
            brute_weight,
            brute_priority,
            brute_negative_hours,
            brute_count,
        ) = brute_force_coverage(plan)

        assert result.optimal
        assert schedule._scale(result.covered_weight) == brute_weight
        assert schedule._scale(result.covered_priority) == brute_priority
        assert -schedule._scale(result.scheduled_hours) == brute_negative_hours
        assert len(result.tasks) == brute_count

    @staticmethod
    @pytest.mark.parametrize('seed', range(12))
    def test_gap_matches_brute_force(seed):
        rng = random.Random(seed + 1000)
        plan = random_plan(
            rng,
            candidate_count=rng.randint(1, 6),
            group_count=rng.randint(1, 3),
        )

        result = schedule.build_schedule(plan, seed=seed)
        brute_overflow = brute_force_min_overflow(plan)

        if result.gap is None:
            assert brute_overflow == 0
        else:
            assert result.gap.optimal
            assert schedule._scale(result.gap.minimum_extra_hours) == brute_overflow


class TestPlanParsing:
    @staticmethod
    def test_yaml_and_json_load(tmp_path):
        data = {
            'groups': [{'name': 'g', 'hours': 2}],
            'candidates': [{'id': 'a', 'hours': 1}],
        }
        yaml_path = tmp_path / 'plan.yaml'
        json_path = tmp_path / 'plan.json'
        yaml_path.write_text(
            'groups:\n'
            '  - name: g\n'
            '    hours: 2\n'
            'candidates:\n'
            '  - id: a\n'
            '    hours: 1\n',
        )
        json_path.write_text(json.dumps(data))

        assert schedule.load_plan_data(str(yaml_path)) == data
        assert schedule.load_plan_data(str(json_path)) == data

    @staticmethod
    def test_merge_separate_input_files(tmp_path):
        base = {
            'groups': [{'name': 'g1', 'hours': 1}],
            'candidates': [{'id': 'a', 'hours': 1}],
        }
        work_hours = {'g1': 3, 'g2': 2}
        tags = {'oncall': {'capabilities': ['oncall']}}
        permissions = {'p1': ['g1', 'g2']}
        candidates = [{'id': 'b', 'hours': 1}]

        merged = schedule.merge_plan_data(
            base,
            work_hours=work_hours,
            tags=tags,
            permissions=permissions,
            candidates={'candidates': candidates},
        )
        plan = schedule.parse_plan(merged)

        assert {group.name: group.hours for group in plan.groups} == {'g1': 3, 'g2': 2}
        assert plan.tags['oncall'].capabilities == {'oncall'}
        assert plan.projects['p1'].allowed_groups == {'g1', 'g2'}
        assert {candidate.id for candidate in plan.candidates} == {'a', 'b'}

    @staticmethod
    def test_groups_can_be_a_mapping():
        plan = schedule.parse_plan(
            {
                'groups': {'g1': 2, 'g2': {'hours': 3, 'capabilities': ['x']}},
                'candidates': [],
            },
        )

        assert plan.groups[0].name == 'g1'
        assert plan.groups[0].hours == 2
        assert plan.groups[1].capabilities == {'x'}

    @staticmethod
    @pytest.mark.parametrize(
        'data,fragment',
        [
            ({'groups': [], 'candidates': []}, 'at least one review group'),
            (
                {
                    'groups': [{'name': 'g', 'hours': 1}],
                    'candidates': [
                        {'id': 'a', 'hours': 1},
                        {'id': 'a', 'hours': 1},
                    ],
                },
                'Duplicate candidate id',
            ),
            (
                {
                    'groups': [{'name': 'g', 'hours': 1}],
                    'projects': [{'name': 'p', 'allowed_groups': ['missing']}],
                    'candidates': [],
                },
                'unknown group',
            ),
            (
                {
                    'groups': [{'name': 'g', 'hours': 1}],
                    'candidates': [{'id': 'a', 'hours': -1}],
                },
                'negative hours',
            ),
            (
                {
                    'groups': [{'name': 'g', 'hours': 1}],
                    'candidates': [{'id': 'a', 'hours': 1, 'visible_to': ['missing']}],
                },
                'unknown group',
            ),
        ],
    )
    def test_rejects_invalid_plans(data, fragment):
        with pytest.raises(schedule.ScheduleError, match=fragment):
            schedule.parse_plan(data)


class TestCli:
    @staticmethod
    def test_schedule_mode_writes_export(tmp_path, printer):
        plan_path = tmp_path / 'plan.yaml'
        export_path = tmp_path / 'export.json'
        plan_path.write_text(
            'groups:\n'
            '  - name: g\n'
            '    hours: 2\n'
            'candidates:\n'
            '  - id: a\n'
            '    hours: 1\n',
        )

        assert main_module.main([
            'audit',
            '--schedule',
            str(plan_path),
            '--export',
            str(export_path),
            '--seed',
            '7',
        ]) == 0

        exported = json.loads(export_path.read_text())
        assert set(exported[0]) == {'task_id', 'order', 'capabilities'}
        assert 'Weekly audit worklist' in printer.message

    @staticmethod
    def test_schedule_mode_can_export_to_stdout(tmp_path, printer):
        plan_path = tmp_path / 'plan.json'
        plan_path.write_text(
            json.dumps({
                'groups': [{'name': 'g', 'hours': 2}],
                'candidates': [{'id': 'a', 'hours': 1}],
            }),
        )

        main_module.main([
            'audit',
            '--schedule',
            str(plan_path),
            '--export',
            '-',
            '--seed',
            '7',
        ])

        exported = json.loads(printer.message)
        assert set(exported[0]) == {'task_id', 'order', 'capabilities'}

    @staticmethod
    def test_schedule_mode_json_includes_gap(tmp_path, printer):
        plan_path = tmp_path / 'plan.json'
        plan_path.write_text(
            json.dumps({
                'groups': [{'name': 'g', 'hours': 1}],
                'candidates': [
                    {'id': 'a', 'hours': 1},
                    {'id': 'b', 'hours': 1},
                ],
            }),
        )

        main_module.main([
            'audit',
            '--schedule',
            str(plan_path),
            '--json',
            '--seed',
            '7',
        ])

        output = json.loads(printer.message)
        assert output['feasible'] is False
        assert output['gap']['minimum_extra_hours'] == 1

    @staticmethod
    def test_schedule_mode_accepts_separate_inputs(tmp_path, printer):
        plan_path = tmp_path / 'plan.json'
        hours_path = tmp_path / 'hours.json'
        tags_path = tmp_path / 'tags.json'
        permissions_path = tmp_path / 'permissions.json'
        candidates_path = tmp_path / 'candidates.json'

        plan_path.write_text('{}')
        hours_path.write_text(json.dumps({'g': {'hours': 2, 'capabilities': ['oncall']}}))
        tags_path.write_text(json.dumps({'oncall': {'capabilities': ['oncall']}}))
        permissions_path.write_text(json.dumps({'p': ['g']}))
        candidates_path.write_text(
            json.dumps([{'id': 'a', 'hours': 1, 'projects': ['p'], 'tags': ['oncall']}]),
        )

        main_module.main([
            'audit',
            '--schedule',
            str(plan_path),
            '--work-hours',
            str(hours_path),
            '--tags',
            str(tags_path),
            '--permissions',
            str(permissions_path),
            '--candidates',
            str(candidates_path),
            '--json',
            '--seed',
            '7',
        ])

        output = json.loads(printer.message)
        assert output['schedule'][0]['capabilities'] == ['oncall']

    @staticmethod
    def test_schedule_mode_reports_bad_plan(tmp_path, mock_log):
        plan_path = tmp_path / 'plan.json'
        plan_path.write_text('{"groups": [], "candidates": []}')

        main_module.main(['audit', '--schedule', str(plan_path)])

        assert 'at least one review group' in mock_log.error_messages


def test_schedule_mode_rejects_multiple_plan_files():
    from detect_secrets.core.usage import ParserBuilder

    with pytest.raises(SystemExit):
        ParserBuilder().add_console_use_arguments().parse_args(
            ['audit', '--schedule', 'a.json', 'b.json'],
        )

# Edge-case tests are appended below.



class TestEdgeCases:
    @staticmethod
    def test_allowed_groups_none_allows_everyone():
        plan = make_plan(
            groups=[{'name': 'g', 'hours': 2}],
            projects=[{'name': 'p'}],
            candidates=[{'id': 'c', 'hours': 1, 'projects': ['p']}],
        )

        result = schedule.build_schedule(plan, seed=1)

        assert [task.group for task in result.tasks] == ['g']

    @staticmethod
    def test_empty_solvers():
        solver = schedule._Solver([], [], None)

        assert solver.solve_coverage() == ([], True)
        assert solver.solve_min_overflow() == ([], True)

    @staticmethod
    def test_max_nodes_marks_schedule_non_optimal():
        plan = make_plan(
            groups=[{'name': 'g', 'hours': 1}],
            candidates=[
                {'id': 'a', 'hours': 1},
                {'id': 'b', 'hours': 1},
            ],
        )

        result = schedule.build_schedule(plan, seed=1, max_nodes=0)

        assert result.optimal is False
        assert result.gap is not None
        assert result.gap.optimal is False

    @staticmethod
    def test_zero_hour_candidate_is_scheduled_for_free():
        plan = make_plan(
            groups=[{'name': 'g', 'hours': 0}],
            candidates=[{'id': 'a', 'hours': 0}],
        )

        result = schedule.build_schedule(plan, seed=1)

        assert len(result.tasks) == 1
        assert result.gap is None

    @staticmethod
    def test_render_worklist_shows_empty_group_and_structural_gap():
        plan = make_plan(
            groups=[
                {'name': 'idle', 'hours': 2},
                {'name': 'busy', 'hours': 1, 'capabilities': ['x']},
            ],
            candidates=[{'id': 'c', 'hours': 1, 'capabilities': ['missing']}],
        )
        result = schedule.build_schedule(plan, seed=1)

        rendered = schedule.render_worklist(result)

        assert '(nothing scheduled)' in rendered
        assert 'Structurally unassignable candidates:' in rendered
        assert 'c: capability' in rendered

    @staticmethod
    def test_render_worklist_shows_capacity_gap():
        plan = make_plan(
            groups=[{'name': 'g', 'hours': 1}],
            candidates=[
                {'id': 'a', 'hours': 1},
                {'id': 'b', 'hours': 1},
            ],
        )
        result = schedule.build_schedule(plan, seed=1)

        rendered = schedule.render_worklist(result)

        assert 'Gap' in rendered
        assert 'Minimum additional hours: 1.00' in rendered
        assert 'g: +1.00h' in rendered

    @staticmethod
    def test_load_plan_from_stdin(monkeypatch):
        monkeypatch.setattr(schedule.sys, 'stdin', __import__('io').StringIO(''))
        assert schedule.load_plan_data() == {}

        monkeypatch.setattr(
            schedule.sys,
            'stdin',
            __import__('io').StringIO('groups: []'),
        )
        assert schedule.load_plan_data('-') == {'groups': []}

    @staticmethod
    def test_load_plan_rejects_bad_yaml(tmp_path):
        path = tmp_path / 'bad.yaml'
        path.write_text('groups: [')

        with pytest.raises(schedule.ScheduleError, match='Unable to parse plan'):
            schedule.load_plan_data(str(path))

    @staticmethod
    def test_load_plan_sequence_requires_opt_in(tmp_path):
        path = tmp_path / 'list.json'
        path.write_text('[]')

        with pytest.raises(schedule.ScheduleError):
            schedule.load_plan_data(str(path))
        assert schedule.load_plan_data(str(path), allow_sequence=True) == []

    @staticmethod
    def test_parse_plan_rejects_non_mapping():
        with pytest.raises(schedule.ScheduleError):
            schedule.parse_plan([])

    @staticmethod
    def test_with_weeks():
        plan = make_plan(
            groups=[{'name': 'g', 'hours': 1}],
            candidates=[{'id': 'a', 'hours': 1}],
        )

        expanded = schedule.with_weeks(plan, 3)

        assert expanded.weeks == 3
        assert expanded.candidates == plan.candidates

    @staticmethod
    def test_merge_work_hours_groups_shape():
        merged = schedule.merge_plan_data(
            {'groups': [{'name': 'g1', 'hours': 1}]},
            work_hours={'groups': [{'name': 'g2', 'hours': 2, 'capabilities': ['x']}]},
        )

        plan = schedule.parse_plan(merged)
        assert {group.name: group.hours for group in plan.groups} == {'g1': 1, 'g2': 2}
        assert plan.groups[1].capabilities == {'x'}

    @staticmethod
    def test_merge_tags_full_plan_shape():
        merged = schedule.merge_plan_data(
            {'groups': [{'name': 'g', 'hours': 1}], 'candidates': []},
            tags={'tags': {'x': {'capabilities': ['x']}}},
        )

        assert schedule.parse_plan(merged).tags['x'].capabilities == {'x'}

    @staticmethod
    def test_merge_permissions_project_shapes():
        base = {
            'groups': [{'name': 'g', 'hours': 1}],
            'candidates': [],
        }

        merged = schedule.merge_plan_data(
            base,
            permissions={'projects': [{'name': 'p1', 'allowed_groups': ['g']}]},
        )
        assert schedule.parse_plan(merged).projects['p1'].allowed_groups == {'g'}

        merged = schedule.merge_plan_data(
            base,
            permissions={'permissions': {'p2': ['g']}},
        )
        assert schedule.parse_plan(merged).projects['p2'].allowed_groups == {'g'}

        merged = schedule.merge_plan_data(
            base,
            permissions=[{'name': 'p3', 'allowed_groups': ['g']}],
        )
        assert schedule.parse_plan(merged).projects['p3'].allowed_groups == {'g'}

    @staticmethod
    def test_merge_candidates_mapping_shape():
        merged = schedule.merge_plan_data(
            {
                'groups': [{'name': 'g', 'hours': 1}],
                'candidates': [{'id': 'a', 'hours': 1}],
            },
            candidates={'b': {'hours': 1}},
        )

        assert {candidate.id for candidate in schedule.parse_plan(merged).candidates} == {
            'a', 'b',
        }

    @staticmethod
    def test_group_parsing_errors():
        with pytest.raises(schedule.ScheduleError, match='negative hours'):
            schedule.parse_plan(
                {'groups': [{'name': 'g', 'hours': -1}], 'candidates': []},
            )
        with pytest.raises(schedule.ScheduleError, match='needs a name'):
            schedule.parse_plan({'groups': [{'hours': 1}], 'candidates': []})
        with pytest.raises(schedule.ScheduleError, match='mapping or a list'):
            schedule.parse_plan({'groups': 4, 'candidates': []})

    @staticmethod
    def test_project_list_and_mapping_shapes():
        plan = schedule.parse_plan(
            {
                'groups': [{'name': 'g', 'hours': 1}],
                'projects': {
                    'p1': ['g'],
                    'p2': {'allowed_groups': ['g'], 'required_capabilities': ['x']},
                },
                'candidates': [],
            },
        )

        assert plan.projects['p1'].allowed_groups == {'g'}
        assert plan.projects['p2'].required_capabilities == {'x'}

    @staticmethod
    def test_tag_definition_shapes():
        plan = schedule.parse_plan(
            {
                'groups': [{'name': 'g', 'hours': 1}],
                'tags': {
                    'a': 'x',
                    'b': ['y'],
                    'c': 3,
                    'd': {'capabilities': ['z'], 'priority': 2},
                    'e': None,
                },
                'candidates': [],
            },
        )

        assert plan.tags['a'].capabilities == {'x'}
        assert plan.tags['b'].capabilities == {'y'}
        assert plan.tags['c'].priority == 3
        assert plan.tags['d'].capabilities == {'z'}
        assert plan.tags['e'].capabilities == set()

    @staticmethod
    def test_tag_list_with_names():
        plan = schedule.parse_plan(
            {
                'groups': [{'name': 'g', 'hours': 1}],
                'tags': [{'name': 'x', 'capabilities': ['x']}],
                'candidates': [],
            },
        )

        assert plan.tags['x'].capabilities == {'x'}

    @staticmethod
    def test_invalid_tag_definition():
        with pytest.raises(schedule.ScheduleError, match='Invalid definition'):
            schedule.parse_plan(
                {
                    'groups': [{'name': 'g', 'hours': 1}],
                    'tags': {'x': object()},
                    'candidates': [],
                },
            )

    @staticmethod
    def test_candidate_shapes_and_aliases():
        plan = schedule.parse_plan(
            {
                'groups': [{'name': 'g', 'hours': 2}],
                'tags': {'t': {'capabilities': ['x'], 'priority': 5}},
                'candidates': {
                    'a': {
                        'time': 1,
                        'project': 'p',
                        'tags': ['t'],
                        'weight': 3,
                        'visible_to': ['g'],
                    },
                },
            },
        )
        candidate = plan.candidates[0]

        assert candidate.id == 'a'
        assert candidate.hours == 1
        assert candidate.projects == ('p',)
        assert candidate.required_capabilities == {'x'}
        assert candidate.priority == 5
        assert candidate.weight == 3
        assert candidate.allowed_groups == {'g'}

    @staticmethod
    def test_candidate_list_of_strings_and_invalid_entry():
        plan = schedule.parse_plan(
            {
                'groups': [{'name': 'g', 'hours': 1}],
                'candidates': ['a'],
            },
        )
        assert plan.candidates[0].id == 'a'

        with pytest.raises(schedule.ScheduleError, match='candidate must be a mapping'):
            schedule.parse_plan(
                {'groups': [{'name': 'g', 'hours': 1}], 'candidates': [4]},
            )

    @staticmethod
    def test_permission_errors():
        with pytest.raises(schedule.ScheduleError, match='Permissions must be'):
            schedule.parse_plan(
                {
                    'groups': [{'name': 'g', 'hours': 1}],
                    'permissions': 4,
                    'candidates': [],
                },
            )
        with pytest.raises(schedule.ScheduleError, match='needs a project name'):
            schedule.parse_plan(
                {
                    'groups': [{'name': 'g', 'hours': 1}],
                    'permissions': [{'allowed_groups': ['g']}],
                    'candidates': [],
                },
            )

    @staticmethod
    def test_work_hours_errors():
        with pytest.raises(schedule.ScheduleError, match='mapping or a list'):
            schedule.parse_plan(
                {'work_hours': 'bad', 'candidates': []},
            )
        with pytest.raises(schedule.ScheduleError, match='needs a group name'):
            schedule.parse_plan(
                {'work_hours': [{'hours': 2}], 'candidates': []},
            )
        with pytest.raises(schedule.ScheduleError, match='number or a mapping'):
            schedule.parse_plan(
                {'work_hours': {'g': 'bad'}, 'candidates': []},
            )

    @staticmethod
    def test_float_and_week_errors():
        with pytest.raises(schedule.ScheduleError, match='must be a number'):
            schedule.parse_plan(
                {'groups': [{'name': 'g', 'hours': 'bad'}], 'candidates': []},
            )
        with pytest.raises(schedule.ScheduleError, match='positive integer'):
            schedule.parse_plan(
                {
                    'groups': [{'name': 'g', 'hours': 1}],
                    'candidates': [],
                    'weeks': 0,
                },
            )

    @staticmethod
    def test_sequence_errors():
        with pytest.raises(schedule.ScheduleError, match='list or a single value'):
            schedule.parse_plan(
                {
                    'groups': [{'name': 'g', 'hours': 1}],
                    'candidates': [{'id': 'a', 'hours': 1, 'tags': 4}],
                },
            )

    @staticmethod
    def test_candidate_mapping_merge_keeps_existing_order():
        merged = schedule.merge_plan_data(
            {
                'groups': [{'name': 'g', 'hours': 1}],
                'candidates': {'a': {'hours': 1}},
            },
            candidates={'b': {'hours': 1}},
        )

        assert [candidate.id for candidate in schedule.parse_plan(merged).candidates] == [
            'a', 'b',
        ]



class TestParserBranches:
    @staticmethod
    def test_comment_only_plan_is_empty(tmp_path):
        path = tmp_path / 'comment.yaml'
        path.write_text('# nothing here')

        assert schedule.load_plan_data(str(path)) == {}

    @staticmethod
    def test_duplicate_group_names_are_merged():
        plan = schedule.parse_plan(
            {
                'groups': [
                    {'name': 'g', 'hours': 1},
                    {'name': 'g', 'capabilities': ['x']},
                ],
                'candidates': [],
            },
        )

        assert len(plan.groups) == 1
        assert plan.groups[0].capabilities == {'x'}

    @staticmethod
    def test_group_entry_must_be_a_mapping():
        with pytest.raises(schedule.ScheduleError, match='Each review group'):
            schedule.parse_plan({'groups': ['g'], 'candidates': []})

    @staticmethod
    def test_nested_work_hours_shapes():
        plan = schedule.parse_plan(
            {'work_hours': {'work_hours': {'g': 1}}, 'candidates': []},
        )
        assert plan.groups[0].hours == 1

        plan = schedule.parse_plan(
            {
                'work_hours': {'groups': [{'name': 'g', 'hours': 2}]},
                'candidates': [],
            },
        )
        assert plan.groups[0].hours == 2

    @staticmethod
    def test_work_hours_list_entry_must_be_a_mapping():
        with pytest.raises(schedule.ScheduleError, match='mapping or a list'):
            schedule.parse_plan({'work_hours': [4], 'candidates': []})

    @staticmethod
    def test_project_string_and_invalid_shapes():
        plan = schedule.parse_plan(
            {
                'groups': [{'name': 'g', 'hours': 1}],
                'projects': {'p': 'g'},
                'candidates': [],
            },
        )
        assert plan.projects['p'].allowed_groups == {'g'}

        with pytest.raises(schedule.ScheduleError, match='Each project'):
            schedule.parse_plan(
                {
                    'groups': [{'name': 'g', 'hours': 1}],
                    'projects': [4],
                    'candidates': [],
                },
            )

        with pytest.raises(schedule.ScheduleError, match='needs a name'):
            schedule.parse_plan(
                {
                    'groups': [{'name': 'g', 'hours': 1}],
                    'projects': [{'allowed_groups': ['g']}],
                    'candidates': [],
                },
            )

    @staticmethod
    def test_tag_sequence_shapes():
        plan = schedule.parse_plan(
            {
                'groups': [{'name': 'g', 'hours': 1}],
                'tags': ['x'],
                'candidates': [],
            },
        )
        assert plan.tags['x'].capabilities == set()

        with pytest.raises(schedule.ScheduleError, match='needs a name'):
            schedule.parse_plan(
                {
                    'groups': [{'name': 'g', 'hours': 1}],
                    'tags': [{'capabilities': ['x']}],
                    'candidates': [],
                },
            )

        with pytest.raises(schedule.ScheduleError, match='needs a name'):
            schedule.parse_plan(
                {
                    'groups': [{'name': 'g', 'hours': 1}],
                    'tags': [4],
                    'candidates': [],
                },
            )

    @staticmethod
    def test_candidate_missing_id_and_negative_weight():
        plan = schedule.parse_plan(
            {
                'groups': [{'name': 'g', 'hours': 1}],
                'candidates': [{'hours': 1}],
            },
        )
        assert plan.candidates[0].id == 'candidate-1'

        with pytest.raises(schedule.ScheduleError, match='negative weight'):
            schedule.parse_plan(
                {
                    'groups': [{'name': 'g', 'hours': 1}],
                    'candidates': [{'id': 'a', 'hours': 1, 'weight': -1}],
                },
            )

    @staticmethod
    def test_permission_mapping_value_object():
        plan = schedule.parse_plan(
            {
                'groups': [{'name': 'g', 'hours': 1}],
                'permissions': {'p': {'allowed_groups': ['g']}},
                'candidates': [],
            },
        )

        assert plan.projects['p'].allowed_groups == {'g'}

    @staticmethod
    def test_permission_list_errors():
        with pytest.raises(schedule.ScheduleError, match='Permissions must be'):
            schedule.parse_plan(
                {
                    'groups': [{'name': 'g', 'hours': 1}],
                    'permissions': [4],
                    'candidates': [],
                },
            )

        with pytest.raises(schedule.ScheduleError, match='needs a project name'):
            schedule.parse_plan(
                {
                    'groups': [{'name': 'g', 'hours': 1}],
                    'permissions': [{'allowed_groups': ['g']}],
                    'candidates': [],
                },
            )

    @staticmethod
    def test_merge_mapping_section_branches():
        target = {}
        schedule._merge_mapping_section(target, 'x', None)
        assert target == {}

        with pytest.raises(schedule.ScheduleError, match='mapping/object'):
            schedule._merge_mapping_section({}, 'x', 5)

        target = {'x': ['a']}
        schedule._merge_mapping_section(target, 'x', {'b': 1})
        assert target['x']['b'] == 1

    @staticmethod
    def test_extract_work_hours_branches():
        assert schedule._extract_work_hours({'work_hours': {'g': 1}}) == {'g': 1}
        assert schedule._extract_work_hours({'groups': []}) == []
        assert schedule._extract_work_hours({'x': 1}) == {'x': 1}

    @staticmethod
    def test_named_to_dict_handles_anonymous_entries():
        assert 'candidates-1' in schedule._named_to_dict(
            [{'hours': 1}],
            'candidates',
        )
        assert 'tags-1' in schedule._named_to_dict(['x'], 'tags')

    @staticmethod
    def test_normalise_section_entry_branches():
        assert schedule._normalise_section_entry('groups', 'g', 2)['hours'] == 2
        assert schedule._normalise_section_entry(
            'groups', 'g', {'hours': 1},
        )['name'] == 'g'
        assert schedule._normalise_section_entry(
            'projects', 'p', ['g'],
        )['allowed_groups'] == ['g']
        assert schedule._normalise_section_entry(
            'projects', 'p', 'g',
        )['allowed_groups'] == ['g']
        assert schedule._normalise_section_entry(
            'projects', 'p', {'allowed_groups': ['g']},
        )['name'] == 'p'
        assert schedule._normalise_section_entry(
            'candidates', None, 'a',
        )['id'] == 'a'
        assert schedule._normalise_section_entry(
            'candidates', 'a', {'hours': 1},
        )['id'] == 'a'

    @staticmethod
    def test_merge_named_section_none_is_noop():
        target = {'x': []}
        schedule._merge_named_section(target, 'x', None)

        assert target == {'x': []}

    @staticmethod
    def test_scalar_helpers():
        assert schedule._as_sequence(None, 'x') == []
        assert schedule._as_sequence(b'abc', 'x') == ['abc']

        with pytest.raises(schedule.ScheduleError, match='finite'):
            schedule._as_float(float('nan'), 'x')

        with pytest.raises(schedule.ScheduleError, match='positive integer'):
            schedule._parse_weeks('bad')



def test_permissions_list_valid():
    plan = schedule.parse_plan(
        {
            'groups': [{'name': 'g', 'hours': 1}],
            'permissions': [{'name': 'p', 'allowed_groups': ['g']}],
            'candidates': [],
        },
    )

    assert plan.projects['p'].allowed_groups == {'g'}


def test_unknown_candidate_tag_is_ignored():
    plan = make_plan(
        groups=[{'name': 'g', 'hours': 1}],
        candidates=[{'id': 'a', 'hours': 1, 'tags': ['unknown']}],
    )

    result = schedule.build_schedule(plan, seed=1)

    assert len(result.tasks) == 1



def test_single_object_sections():
    plan = schedule.parse_plan(
        {
            'groups': {'name': 'g', 'hours': 2},
            'projects': {
                'name': 'p',
                'allowed_groups': ['g'],
            },
            'tags': {'name': 't', 'capabilities': ['x']},
            'candidates': {
                'id': 'a',
                'hours': 1,
                'projects': ['p'],
                'tags': ['t'],
            },
        },
    )

    assert len(plan.groups) == 1
    assert plan.projects['p'].allowed_groups == {'g'}
    assert plan.tags['t'].capabilities == {'x'}
    assert plan.candidates[0].id == 'a'


def test_single_work_hours_object():
    plan = schedule.parse_plan(
        {
            'work_hours': {'name': 'g', 'hours': 2},
            'candidates': [],
        },
    )

    assert plan.groups[0].name == 'g'
    assert plan.groups[0].hours == 2



def test_tag_matching_a_group_capability_is_required():
    plan = make_plan(
        groups=[
            {'name': 'general', 'hours': 2, 'tags': ['general']},
            {'name': 'oncall', 'hours': 2, 'tags': ['general', 'oncall']},
        ],
        candidates=[{'id': 'a', 'hours': 1, 'tags': ['oncall']}],
    )

    result = schedule.build_schedule(plan, seed=1)

    assert [task.group for task in result.tasks] == ['oncall']



def test_priority_breaks_capacity_ties():
    plan = make_plan(
        groups=[{'name': 'g', 'hours': 1}],
        candidates=[
            {'id': 'low', 'hours': 1, 'priority': 1},
            {'id': 'high', 'hours': 1, 'priority': 10},
        ],
    )

    result = schedule.build_schedule(plan, seed=1)

    assert [task.candidate.id for task in result.tasks] == ['high']



def test_input_aliases():
    plan = schedule.parse_plan(
        {
            'local_hours': {'g': 2},
            'labels': {'x': {'capabilities': ['x']}},
            'findings': [{'id': 'a', 'hours': 1, 'tags': ['x']}],
        },
    )

    assert plan.groups[0].hours == 2
    assert plan.tags['x'].capabilities == {'x'}
    assert plan.candidates[0].id == 'a'
