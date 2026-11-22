"""Build a weekly manual-review worklist for audit candidates.

The scheduler is intentionally independent from the baseline format.  It only
needs a small plan describing:

* the review groups and their local weekly capacity,
* the projects and which groups may review their findings,
* candidate tags, and
* the candidates themselves.

A candidate may reference more than one project.  Such a candidate is reviewed
once, and the single conclusion covers every project that accepts the reviewer.
Consequently a shared candidate can only be scheduled when one group is
authorized by *all* of its projects.

When the plan does not fit, :func:`build_schedule` reports the minimum number of
additional hours needed to cover every structurally assignable candidate.  The
calculation is exact (not a simple ``demand - capacity`` estimate), because
review tasks are indivisible and may leave unusable slack.

The public export deliberately contains no candidate names, project names,
groups, or hours.  It only contains a random task id, the processing order, and
the capabilities required to perform the task.
"""
import json
import math
import random
import sys
from dataclasses import dataclass
from dataclasses import replace
from typing import Any
from typing import Dict
from typing import FrozenSet
from typing import List
from typing import Mapping
from typing import Optional
from typing import Sequence
from typing import Set
from typing import Tuple
from typing import Union

import yaml

# Hours are scaled to integers so that capacity arithmetic is exact.  The
# granularity (one micro-hour) is far below anything a human review can measure.
HOURS_SCALE = 1_000_000


class ScheduleError(ValueError):
    """Raised when a scheduling plan is malformed."""


@dataclass(frozen=True)
class ReviewGroup:
    """A group (or on-duty expert) that can perform reviews."""

    name: str
    hours: float
    capabilities: FrozenSet[str] = frozenset()


@dataclass(frozen=True)
class ProjectPolicy:
    """Authorization and capability rules for one project."""

    name: str
    allowed_groups: Optional[FrozenSet[str]] = None
    required_capabilities: FrozenSet[str] = frozenset()

    def allows(self, group_name: str) -> bool:
        if self.allowed_groups is None:
            return True
        return group_name in self.allowed_groups


@dataclass(frozen=True)
class TagRule:
    """Capabilities and priority implied by a candidate tag."""

    name: str
    capabilities: FrozenSet[str] = frozenset()
    priority: float = 0


@dataclass(frozen=True)
class Candidate:
    """One audit candidate (for example, a secret or a finding)."""

    id: str
    hours: float
    projects: Tuple[str, ...] = ()
    required_capabilities: FrozenSet[str] = frozenset()
    tags: Tuple[str, ...] = ()
    priority: float = 0
    weight: float = 1
    allowed_groups: Optional[FrozenSet[str]] = None
    index: int = 0


@dataclass
class SchedulePlan:
    """Normalized input for the scheduler."""

    groups: List[ReviewGroup]
    candidates: List[Candidate]
    projects: Dict[str, ProjectPolicy]
    tags: Dict[str, TagRule]
    weeks: int = 1
    source: Optional[str] = None

    def required_capabilities(self, candidate: Candidate) -> FrozenSet[str]:
        required: Set[str] = set(candidate.required_capabilities)
        for project_name in candidate.projects:
            policy = self.projects.get(project_name)
            if policy:
                required.update(policy.required_capabilities)
        return frozenset(required)

    def eligible_groups(self, candidate: Candidate) -> List[ReviewGroup]:
        required = self.required_capabilities(candidate)
        eligible = []
        for group in self.groups:
            if not required.issubset(group.capabilities):
                continue
            if (
                candidate.allowed_groups is not None and
                group.name not in candidate.allowed_groups
            ):
                continue
            if any(
                not self.projects[project_name].allows(group.name)
                for project_name in candidate.projects
                if project_name in self.projects
            ):
                continue
            eligible.append(group)
        return eligible


@dataclass(frozen=True)
class ScheduledTask:
    """A candidate placed into one group's weekly queue."""

    task_id: str
    candidate: Candidate
    group: str
    order: int
    group_order: int
    start: float
    end: float
    required_capabilities: Tuple[str, ...]


@dataclass
class Gap:
    """The tightest capacity gap for a plan that does not fit."""

    minimum_extra_hours: float
    maximum_group_extra: float
    extra_by_group: Dict[str, float]
    binding_groups: List[str]
    uncovered_candidates: List[str]
    structural_gaps: List[Dict[str, Any]]
    optimal: bool = True

    @property
    def feasible(self) -> bool:
        return self.minimum_extra_hours <= 0 and not self.structural_gaps

    def export(self) -> List[Dict[str, Any]]:
        return export_schedule(self)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'feasible': self.feasible,
            'minimum_extra_hours': _round_hours(self.minimum_extra_hours),
            'maximum_group_extra': _round_hours(self.maximum_group_extra),
            'extra_by_group': {
                group: _round_hours(hours)
                for group, hours in self.extra_by_group.items()
            },
            'binding_groups': list(self.binding_groups),
            'uncovered_candidates': list(self.uncovered_candidates),
            'structural_gaps': list(self.structural_gaps),
            'optimal': self.optimal,
        }


@dataclass
class ScheduleResult:
    """A complete scheduling result."""

    plan: SchedulePlan
    tasks: List[ScheduledTask]
    unscheduled: List[Candidate]
    gap: Optional[Gap]
    optimal: bool

    @property
    def covered_weight(self) -> float:
        return sum(task.candidate.weight for task in self.tasks)

    @property
    def covered_priority(self) -> float:
        return sum(task.candidate.priority for task in self.tasks)

    @property
    def scheduled_hours(self) -> float:
        return sum(task.candidate.hours for task in self.tasks)

    @property
    def uncovered_candidate_ids(self) -> List[str]:
        uncovered = [candidate.id for candidate in self.unscheduled]
        if self.gap:
            uncovered.extend(gap['candidate'] for gap in self.gap.structural_gaps)
        return uncovered

    @property
    def feasible(self) -> bool:
        return not self.unscheduled and (self.gap is None or self.gap.feasible)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'feasible': self.feasible,
            'optimal': self.optimal,
            'schedule': export_schedule(self),
            'uncovered_candidates': self.uncovered_candidate_ids,
            'gap': self.gap.to_dict() if self.gap else None,
        }


def load_plan_data(
    path: Optional[str] = None,
    allow_sequence: bool = False,
) -> Any:
    """Load a JSON or YAML plan file.

    ``None`` and ``-`` read from standard input.  An empty file is treated as
    an empty mapping, which is convenient when all inputs come from the
    individual ``--work-hours``/``--tags``/... flags.
    """
    if path is None or path == '-':
        content = sys.stdin.read()
    else:
        with open(path, encoding='utf-8') as file_object:
            content = file_object.read()

    if not content.strip():
        return {}

    try:
        data = yaml.safe_load(content)
    except yaml.YAMLError as error:
        raise ScheduleError(f'Unable to parse plan {path or "<stdin>"}: {error}')

    if data is None:
        return {}
    if isinstance(data, Mapping):
        return dict(data)
    if allow_sequence and isinstance(data, Sequence) and not isinstance(data, (str, bytes)):
        return list(data)
    raise ScheduleError('The scheduling plan must be a mapping/object.')


def merge_plan_data(
    base: Mapping[str, Any],
    work_hours: Optional[Any] = None,
    tags: Optional[Any] = None,
    permissions: Optional[Any] = None,
    candidates: Optional[Any] = None,
) -> Dict[str, Any]:
    """Overlay the separate CLI input files on top of a base plan."""
    merged = dict(base)

    if work_hours is not None:
        _merge_mapping_section(
            merged,
            'work_hours',
            _normalise_work_hours(_extract_work_hours(work_hours)),
        )

    if tags is not None:
        _merge_mapping_section(
            merged, 'tags', _extract_section(tags, 'tags', 'labels'),
        )

    if permissions is not None:
        if isinstance(permissions, Mapping) and 'projects' in permissions:
            _merge_named_section(merged, 'projects', permissions['projects'])
        elif isinstance(permissions, Mapping) and 'permissions' in permissions:
            _merge_mapping_section(merged, 'permissions', permissions['permissions'])
        elif isinstance(permissions, Mapping):
            _merge_mapping_section(merged, 'permissions', permissions)
        else:
            _merge_named_section(merged, 'projects', permissions)

    if candidates is not None:
        extra = _extract_section(candidates, 'candidates', 'findings')
        existing = _as_raw_entries(merged.get('candidates'), 'candidates')
        incoming = _as_raw_entries(extra, 'candidates')
        merged['candidates'] = existing + incoming

    return merged


def parse_plan(data: Mapping[str, Any], source: Optional[str] = None) -> SchedulePlan:
    """Normalize and validate a scheduling plan."""
    if not isinstance(data, Mapping):
        raise ScheduleError('The scheduling plan must be a mapping/object.')

    groups = _parse_groups(data)
    group_names = {group.name for group in groups}
    tags = _parse_tags(data.get('tags', data.get('labels')))
    projects = _parse_projects(data, group_names)
    group_capabilities: Set[str] = set()
    for group in groups:
        group_capabilities.update(group.capabilities)
    candidates = _parse_candidates(
        data.get('candidates', data.get('findings')),
        tags, group_names, group_capabilities,
    )
    weeks = _parse_weeks(data.get('weeks', data.get('horizon_weeks', 1)))

    return SchedulePlan(
        groups=groups,
        candidates=candidates,
        projects=projects,
        tags=tags,
        weeks=weeks,
        source=source,
    )


def with_weeks(plan: SchedulePlan, weeks: int) -> SchedulePlan:
    """Return a copy of ``plan`` with a different planning horizon."""
    return replace(plan, weeks=_parse_weeks(weeks))


def build_schedule(
    plan: Union[SchedulePlan, Mapping[str, Any]],
    seed: Optional[Union[int, str]] = None,
    max_nodes: Optional[int] = None,
) -> ScheduleResult:
    """Build the optimal candidate worklist for ``plan``.

    The coverage objective is lexicographic:

    1. maximize the total weight of covered candidates (by default, the number
       of project associations),
    2. maximize the total priority (tags can raise priority),
    3. minimize scheduled hours (so a shared review is preferred over two
       separate reviews),
    4. maximize the number of candidates that were scheduled.

    When not every candidate can be scheduled, :func:`build_schedule` also
    computes the tightest capacity gap: the minimum total number of additional
    hours that would make every structurally assignable candidate fit.
    """
    if not isinstance(plan, SchedulePlan):
        plan = parse_plan(plan)

    group_index = {group.name: index for index, group in enumerate(plan.groups)}
    capacities = [
        _scale(group.hours) * plan.weeks
        for group in plan.groups
    ]

    items: List[_Item] = []
    structural_gaps: List[Dict[str, Any]] = []
    for candidate in plan.candidates:
        eligible = tuple(
            group_index[group.name]
            for group in plan.eligible_groups(candidate)
        )
        if not eligible:
            structural_gaps.append(_explain_structural_gap(candidate, plan))
            continue
        items.append(
            _Item(
                candidate=candidate,
                eligible=eligible,
                hours=_scale(candidate.hours),
                weight=_scale(candidate.weight),
                priority=_scale(candidate.priority),
            ),
        )

    solver = _Solver(items, capacities, max_nodes=max_nodes)
    assignment, coverage_optimal = solver.solve_coverage()

    task_ids = _generate_task_ids(plan.candidates, seed)
    tasks, unscheduled = _build_tasks(plan, items, assignment, task_ids)

    gap = None
    gap_optimal = True
    if unscheduled or structural_gaps:
        overflow_solver = _Solver(items, capacities, max_nodes=max_nodes)
        overflow_assignment, gap_optimal = overflow_solver.solve_min_overflow()
        loads = [0 for _ in capacities]
        for item, group_number in zip(items, overflow_assignment):
            if group_number >= 0:
                loads[group_number] += item.hours

        extra_by_group: Dict[str, float] = {}
        for index, group in enumerate(plan.groups):
            extra = max(0, loads[index] - capacities[index])
            if extra:
                extra_by_group[group.name] = _unscale(extra)

        unscheduled_items = [
            item
            for item, group_number in zip(items, assignment)
            if group_number < 0
        ]
        binding_groups = _binding_groups(
            plan,
            unscheduled_items,
            capacities,
            loads,
        )
        per_group_extra = [
            max(0, loads[index] - capacities[index])
            for index in range(len(loads))
        ]
        gap = Gap(
            minimum_extra_hours=_unscale(sum(per_group_extra)),
            maximum_group_extra=_unscale(max(per_group_extra) if per_group_extra else 0),
            extra_by_group=extra_by_group,
            binding_groups=binding_groups,
            uncovered_candidates=(
                [candidate.id for candidate in unscheduled] +
                [gap['candidate'] for gap in structural_gaps]
            ),
            structural_gaps=structural_gaps,
            optimal=gap_optimal,
        )

    return ScheduleResult(
        plan=plan,
        tasks=tasks,
        unscheduled=unscheduled,
        gap=gap,
        optimal=coverage_optimal and gap_optimal,
    )


def export_schedule(result: ScheduleResult) -> List[Dict[str, Any]]:
    """Return the privacy-preserving schedule.

    Each row contains exactly three keys: ``task_id``, ``order``, and
    ``capabilities``.  Candidate/project/group names and durations never leave
    the local scheduler.
    """
    return [
        {
            'task_id': task.task_id,
            'order': task.order,
            'capabilities': list(task.required_capabilities),
        }
        for task in sorted(result.tasks, key=lambda item: item.order)
    ]


def write_export(result: ScheduleResult, path: str) -> None:
    """Write the privacy-preserving schedule as JSON."""
    with open(path, 'w', encoding='utf-8') as file_object:
        json.dump(
            export_schedule(result),
            file_object,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        file_object.write('\n')


def render_worklist(result: ScheduleResult) -> str:
    """Render the internal, human-readable worklist."""
    lines = [
        'Weekly audit worklist',
        '=====================',
    ]

    tasks_by_group: Dict[str, List[ScheduledTask]] = {
        group.name: []
        for group in result.plan.groups
    }
    for task in result.tasks:
        tasks_by_group[task.group].append(task)

    for group in result.plan.groups:
        group_tasks = sorted(tasks_by_group[group.name], key=lambda task: task.group_order)
        used = sum(task.candidate.hours for task in group_tasks)
        capacity = group.hours * result.plan.weeks
        lines.append(
            f'[{group.name}] {used:.2f}h / {capacity:.2f}h, {len(group_tasks)} task(s)',
        )
        if not group_tasks:
            lines.append('  (nothing scheduled)')
        for task in group_tasks:
            candidate = task.candidate
            projects = ','.join(candidate.projects) or '-'
            capabilities = ','.join(task.required_capabilities) or '-'
            lines.append(
                '  {order:>3}. {task_id}  {candidate:<24} {hours:>5.2f}h  '
                'projects={projects}  capabilities={capabilities}'.format(
                    order=task.group_order,
                    task_id=task.task_id,
                    candidate=candidate.id,
                    hours=candidate.hours,
                    projects=projects,
                    capabilities=capabilities,
                ),
            )
        lines.append('')

    if result.gap:
        lines.append('Gap')
        lines.append('---')
        lines.append(
            'Minimum additional hours: '
            f'{result.gap.minimum_extra_hours:.2f}',
        )
        for group, hours in sorted(result.gap.extra_by_group.items()):
            lines.append(f'  {group}: +{hours:.2f}h')
        if result.gap.structural_gaps:
            lines.append('Structurally unassignable candidates:')
            for gap in result.gap.structural_gaps:
                lines.append(
                    '  {candidate}: {reason}'.format(
                        candidate=gap['candidate'],
                        reason=gap['reason'],
                    ),
                )
    else:
        lines.append('All candidates fit.  No capacity gap.')

    return '\n'.join(lines).rstrip()


@dataclass(frozen=True)
class _Item:
    candidate: Candidate
    eligible: Tuple[int, ...]
    hours: int
    weight: int
    priority: int


class _SearchLimitExceeded(Exception):
    pass


class _Solver:
    """Exact branch-and-bound solvers for the small audit-plan instances."""

    def __init__(
        self,
        items: Sequence[_Item],
        capacities: Sequence[int],
        max_nodes: Optional[int] = None,
    ) -> None:
        self.items = list(items)
        self.capacities = list(capacities)
        self.max_nodes = max_nodes
        self.nodes = 0
        self.stop = False

        self.best_assignment: List[int] = []
        self.best_score: Tuple[Any, ...] = (0, 0, 0, 0)
        self.best_loads: List[int] = []

        self.suffix_weight: List[int] = [0 for _ in self.items]
        self.suffix_hours: List[int] = [0 for _ in self.items]
        self.suffix_priority: List[int] = [0 for _ in self.items]
        for index in range(len(self.items) - 1, -1, -1):
            item = self.items[index]
            self.suffix_weight[index] = item.weight + (
                self.suffix_weight[index + 1]
                if index + 1 < len(self.items)
                else 0
            )
            self.suffix_hours[index] = item.hours + (
                self.suffix_hours[index + 1]
                if index + 1 < len(self.items)
                else 0
            )
            self.suffix_priority[index] = item.priority + (
                self.suffix_priority[index + 1]
                if index + 1 < len(self.items)
                else 0
            )

        self.total_weight = sum(item.weight for item in self.items)
        self.total_hours = sum(item.hours for item in self.items)

    def solve_coverage(self) -> Tuple[List[int], bool]:
        if not self.items:
            return [], True

        assignment = self._greedy_coverage()
        self.best_assignment = assignment
        self.best_score = self._coverage_score(assignment)
        remaining = list(self.capacities)
        current = [-1 for _ in self.items]
        self.stop = False

        try:
            self._dfs_coverage(0, remaining, 0, 0, 0, 0, current)
        except _SearchLimitExceeded:
            return list(self.best_assignment), False

        return list(self.best_assignment), True

    def solve_min_overflow(self) -> Tuple[List[int], bool]:
        if not self.items:
            return [], True

        assignment, loads = self._greedy_overflow()
        self.best_assignment = assignment
        self.best_loads = loads
        self.best_score = self._overflow_score(loads)
        current = [-1 for _ in self.items]
        self.stop = False

        try:
            self._dfs_overflow(
                0,
                [0 for _ in self.capacities],
                0,
                current,
            )
        except _SearchLimitExceeded:
            return list(self.best_assignment), False

        return list(self.best_assignment), True

    def _check_node(self) -> None:
        self.nodes += 1
        if self.max_nodes is not None and self.nodes > self.max_nodes:
            raise _SearchLimitExceeded

    def _coverage_score(self, assignment: Sequence[int]) -> Tuple[int, int, int, int]:
        weight = 0
        priority = 0
        hours = 0
        count = 0
        for item, group_number in zip(self.items, assignment):
            if group_number < 0:
                continue
            weight += item.weight
            priority += item.priority
            hours += item.hours
            count += 1
        return weight, priority, -hours, count

    def _greedy_coverage(self) -> List[int]:
        assignment = [-1 for _ in self.items]
        remaining = list(self.capacities)
        order = sorted(
            range(len(self.items)),
            key=lambda index: self._coverage_order_key(index),
        )
        for index in order:
            item = self.items[index]
            group_number = self._best_fit(item, remaining)
            if group_number >= 0:
                assignment[index] = group_number
                remaining[group_number] -= item.hours
        return assignment

    def _coverage_order_key(self, index: int) -> Tuple[Any, ...]:
        item = self.items[index]
        density = item.weight / item.hours if item.hours else float('inf')
        return (
            len(item.eligible),
            -density,
            -item.priority,
            -item.hours,
            item.candidate.index,
            item.candidate.id,
        )

    def _best_fit(self, item: _Item, remaining: Sequence[int]) -> int:
        best_group = -1
        best_left = 0
        for group_number in item.eligible:
            if remaining[group_number] < item.hours:
                continue
            left = remaining[group_number] - item.hours
            if best_group < 0 or left < best_left:
                best_group = group_number
                best_left = left
        return best_group

    def _capacity_weight_bound(self, start: int, capacity: int) -> int:
        zero_hour_weight = 0
        max_density = 0.0
        for index in range(start, len(self.items)):
            item = self.items[index]
            if item.hours == 0:
                zero_hour_weight += item.weight
            else:
                max_density = max(max_density, item.weight / item.hours)
        return zero_hour_weight + int(math.ceil(capacity * max_density))

    def _dfs_coverage(
        self,
        index: int,
        remaining: List[int],
        weight: int,
        priority: int,
        hours: int,
        count: int,
        current: List[int],
    ) -> None:
        self._check_node()
        if self.stop:
            return

        if index == len(self.items):
            score = (weight, priority, -hours, count)
            if score > self.best_score:
                self.best_score = score
                self.best_assignment = list(current)
            if weight == self.total_weight and count == len(self.items):
                self.stop = True
            return

        capacity_bound = self._capacity_weight_bound(index, sum(remaining))
        upper_weight = weight + min(self.suffix_weight[index], capacity_bound)
        if upper_weight < self.best_score[0]:
            return
        if upper_weight == self.best_score[0]:
            upper_priority = priority + self.suffix_priority[index]
            max_count = count + (len(self.items) - index)
            if (upper_weight, upper_priority, -hours, max_count) < self.best_score:
                return

        item = self.items[index]
        for group_number in sorted(
            item.eligible,
            key=lambda candidate: (
                remaining[candidate] - item.hours,
                candidate,
            ),
        ):
            if remaining[group_number] < item.hours:
                continue
            remaining[group_number] -= item.hours
            current[index] = group_number
            self._dfs_coverage(
                index + 1,
                remaining,
                weight + item.weight,
                priority + item.priority,
                hours + item.hours,
                count + 1,
                current,
            )
            current[index] = -1
            remaining[group_number] += item.hours
            if self.stop:
                return

        self._dfs_coverage(index + 1, remaining, weight, priority, hours, count, current)

    def _overflow_score(self, loads: Sequence[int]) -> Tuple[int, int, Tuple[int, ...]]:
        extras = [
            max(0, load - capacity)
            for load, capacity in zip(loads, self.capacities)
        ]
        return sum(extras), max(extras) if extras else 0, tuple(sorted(extras, reverse=True))

    def _greedy_overflow(self) -> Tuple[List[int], List[int]]:
        assignment = [-1 for _ in self.items]
        loads = [0 for _ in self.capacities]
        order = sorted(
            range(len(self.items)),
            key=lambda index: (
                -self.items[index].hours,
                len(self.items[index].eligible),
                -self.items[index].weight,
                self.items[index].candidate.index,
                self.items[index].candidate.id,
            ),
        )
        for index in order:
            item = self.items[index]
            group_number = self._overflow_fit(item, loads)
            assignment[index] = group_number
            loads[group_number] += item.hours
        return assignment, loads

    def _overflow_fit(self, item: _Item, loads: Sequence[int]) -> int:
        best_group = -1
        best_key: Optional[Tuple[int, int, int]] = None
        for group_number in item.eligible:
            left = self.capacities[group_number] - loads[group_number]
            overflow = max(0, item.hours - left)
            key = (
                overflow,
                left if overflow == 0 else -left,
                group_number,
            )
            if best_key is None or key < best_key:
                best_key = key
                best_group = group_number
        return best_group

    def _overflow_lower_bound(
        self,
        start: int,
        loads: Sequence[int],
        current_overflow: int,
    ) -> int:
        forced = [0 for _ in self.capacities]
        flexible_hours = 0
        for index in range(start, len(self.items)):
            item = self.items[index]
            if len(item.eligible) == 1:
                forced[item.eligible[0]] += item.hours
            else:
                flexible_hours += item.hours

        lower_bound = current_overflow
        available = 0
        for group_number, capacity in enumerate(self.capacities):
            before = max(0, loads[group_number] - capacity)
            after = max(0, loads[group_number] + forced[group_number] - capacity)
            lower_bound += after - before
            if loads[group_number] + forced[group_number] < capacity:
                available += capacity - loads[group_number] - forced[group_number]

        lower_bound += max(0, flexible_hours - available)
        return lower_bound

    def _dfs_overflow(
        self,
        index: int,
        loads: List[int],
        overflow: int,
        current: List[int],
    ) -> None:
        self._check_node()
        if self.stop:
            return

        if index == len(self.items):
            score = self._overflow_score(loads)
            if score < self.best_score:
                self.best_score = score
                self.best_assignment = list(current)
                self.best_loads = list(loads)
            if score[0] == 0:
                self.stop = True
            return

        if self._overflow_lower_bound(index, loads, overflow) > self.best_score[0]:
            return

        item = self.items[index]
        for group_number in sorted(
            item.eligible,
            key=lambda candidate: (
                max(
                    0,
                    item.hours - (self.capacities[candidate] - loads[candidate]),
                ),
                loads[candidate],
                candidate,
            ),
        ):
            before = max(0, loads[group_number] - self.capacities[group_number])
            loads[group_number] += item.hours
            after = max(0, loads[group_number] - self.capacities[group_number])
            current[index] = group_number
            self._dfs_overflow(
                index + 1,
                loads,
                overflow + after - before,
                current,
            )
            current[index] = -1
            loads[group_number] -= item.hours
            if self.stop:
                return


def _build_tasks(
    plan: SchedulePlan,
    items: Sequence[_Item],
    assignment: Sequence[int],
    task_ids: Mapping[str, str],
) -> Tuple[List[ScheduledTask], List[Candidate]]:
    tasks_by_group: Dict[int, List[_Item]] = {
        index: []
        for index in range(len(plan.groups))
    }
    unscheduled = []
    for item, group_number in zip(items, assignment):
        if group_number < 0:
            unscheduled.append(item.candidate)
        else:
            tasks_by_group[group_number].append(item)

    tasks: List[ScheduledTask] = []
    order = 0
    for group_number, group in enumerate(plan.groups):
        group_items = sorted(
            tasks_by_group[group_number],
            key=lambda item: (
                -item.candidate.priority,
                -item.candidate.weight,
                item.candidate.index,
                item.candidate.id,
            ),
        )
        start = 0.0
        for group_order, item in enumerate(group_items, start=1):
            order += 1
            end = start + item.candidate.hours
            tasks.append(
                ScheduledTask(
                    task_id=task_ids[item.candidate.id],
                    candidate=item.candidate,
                    group=group.name,
                    order=order,
                    group_order=group_order,
                    start=start,
                    end=end,
                    required_capabilities=tuple(
                        sorted(plan.required_capabilities(item.candidate)),
                    ),
                ),
            )
            start = end

    return tasks, unscheduled


def _binding_groups(
    plan: SchedulePlan,
    unscheduled: Sequence[_Item],
    capacities: Sequence[int],
    loads: Sequence[int],
) -> List[str]:
    binding: List[str] = []
    for index, group in enumerate(plan.groups):
        if any(
            index in item.eligible
            for item in unscheduled
        ) and loads[index] >= capacities[index]:
            binding.append(group.name)
    for index, group in enumerate(plan.groups):
        if loads[index] > capacities[index] and group.name not in binding:
            binding.append(group.name)
    return binding


def _explain_structural_gap(
    candidate: Candidate,
    plan: SchedulePlan,
) -> Dict[str, Any]:
    required = plan.required_capabilities(candidate)
    capable = [
        group
        for group in plan.groups
        if required.issubset(group.capabilities)
    ]
    if not capable:
        available: Set[str] = set()
        for group in plan.groups:
            available.update(group.capabilities)
        return {
            'candidate': candidate.id,
            'reason': 'capability',
            'projects': list(candidate.projects),
            'missing_capabilities': sorted(required - available),
            'required_capabilities': sorted(required),
        }

    project_allowed_groups = {}
    for project_name in candidate.projects:
        policy = plan.projects.get(project_name)
        project_allowed_groups[project_name] = sorted(
            group.name
            for group in capable
            if (
                candidate.allowed_groups is None or
                group.name in candidate.allowed_groups
            ) and (policy is None or policy.allows(group.name))
        )

    return {
        'candidate': candidate.id,
        'reason': 'permission',
        'projects': list(candidate.projects),
        'capable_groups': sorted(group.name for group in capable),
        'project_allowed_groups': project_allowed_groups,
        'required_capabilities': sorted(required),
        'detail': (
            'No single group is authorized by every associated project.'
        ),
    }


def _generate_task_ids(
    candidates: Sequence[Candidate],
    seed: Optional[Union[int, str]],
) -> Dict[str, str]:
    rng = random.Random(seed)
    used: Set[str] = set()
    result: Dict[str, str] = {}
    for candidate in sorted(candidates, key=lambda item: (item.index, item.id)):
        while True:
            token = 'T' + format(rng.getrandbits(48), '012x')
            if token not in used:
                break
        used.add(token)
        result[candidate.id] = token
    return result


def _parse_groups(data: Mapping[str, Any]) -> List[ReviewGroup]:
    entries = _collect_named(data.get('groups'), 'groups')
    by_name: Dict[str, Dict[str, Any]] = {}
    order: List[str] = []

    for key, value in entries:
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            value = {'hours': value}
        if not isinstance(value, Mapping):
            raise ScheduleError('Each review group must be a mapping/object.')
        value = dict(value)
        name = _get_value(value, 'name', 'id', 'group', default=key)
        if name is None:
            raise ScheduleError('Every review group needs a name.')
        name = str(name)
        value['name'] = name
        if name in by_name:
            by_name[name].update(value)
        else:
            by_name[name] = value
            order.append(name)

    work_hours = _normalise_work_hours(
        data.get('work_hours', data.get('local_hours')),
    )
    for name, details in work_hours.items():
        if name in by_name:
            by_name[name].update(details)
        else:
            by_name[name] = {'name': name, **details}
            order.append(name)

    groups: List[ReviewGroup] = []
    for name in order:
        details = by_name[name]
        hours = _as_float(
            _get_value(details, 'hours', 'capacity', 'work_hours', 'weekly_hours', default=0),
            f'hours for group {name}',
        )
        if hours < 0:
            raise ScheduleError(f'Group {name} has negative hours.')
        capabilities = _as_string_set(
            _get_value(details, 'capabilities', 'skills', 'tags', 'requires', default=[]),
            f'capabilities for group {name}',
        )
        groups.append(
            ReviewGroup(
                name=name,
                hours=hours,
                capabilities=capabilities,
            ),
        )

    if not groups:
        raise ScheduleError('A scheduling plan needs at least one review group.')
    return groups


def _normalise_work_hours(value: Any) -> Dict[str, Dict[str, Any]]:
    if value is None:
        return {}
    if isinstance(value, Mapping):
        if 'work_hours' in value:
            return _normalise_work_hours(value['work_hours'])
        if 'groups' in value:
            return _normalise_work_hours(value['groups'])
        if _looks_like_named_entry(value, 'groups'):
            name = _get_value(value, 'name', 'id', 'group')
            if name is None:
                raise ScheduleError('Every work-hours entry needs a group name.')
            return {str(name): dict(value)}
        result: Dict[str, Dict[str, Any]] = {}
        for name, details in value.items():
            if isinstance(details, (int, float)) and not isinstance(details, bool):
                result[str(name)] = {
                    'hours': _as_float(details, f'hours for group {name}'),
                }
            elif isinstance(details, Mapping):
                result[str(name)] = dict(details)
            elif isinstance(details, str):
                try:
                    hours = _as_float(details, f'hours for group {name}')
                except ScheduleError:
                    raise ScheduleError(
                        f'Work hours for group {name} must be a number or a mapping.',
                    )
                result[str(name)] = {'hours': hours}
            else:
                raise ScheduleError(
                    f'Work hours for group {name} must be a number or a mapping.',
                )
        return result
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        result: Dict[str, Dict[str, Any]] = {}
        for item in value:
            if not isinstance(item, Mapping):
                raise ScheduleError('Work hours must be a mapping or a list of mappings.')
            name = _get_value(item, 'name', 'id', 'group')
            if name is None:
                raise ScheduleError('Every work-hours entry needs a group name.')
            result[str(name)] = dict(item)
        return result
    raise ScheduleError('Work hours must be a mapping or a list of mappings.')


def _parse_projects(
    data: Mapping[str, Any],
    group_names: Set[str],
) -> Dict[str, ProjectPolicy]:
    by_name: Dict[str, Dict[str, Any]] = {}

    for key, value in _collect_named(data.get('projects'), 'projects'):
        if isinstance(value, (list, tuple, set, frozenset)):
            value = {'allowed_groups': list(value)}
        elif isinstance(value, str):
            value = {'allowed_groups': [value]}
        if not isinstance(value, Mapping):
            raise ScheduleError('Each project must be a mapping/object.')
        value = dict(value)
        name = _get_value(value, 'name', 'id', 'project', default=key)
        if name is None:
            raise ScheduleError('Every project needs a name.')
        value['name'] = str(name)
        by_name[str(name)] = value

    for name, allowed in _collect_permissions(data.get('permissions')):
        value = by_name.get(name, {'name': name})
        value['allowed_groups'] = allowed
        by_name[name] = value

    projects: Dict[str, ProjectPolicy] = {}
    for name, details in by_name.items():
        allowed_groups = _get_value(
            details,
            'allowed_groups',
            'reviewers',
            'groups',
            'allowed',
            'can_review',
            default=None,
        )
        allowed: Optional[FrozenSet[str]] = None
        if allowed_groups is not None:
            allowed = _as_string_set(
                allowed_groups,
                f'allowed groups for project {name}',
            )
            unknown = allowed - group_names
            if unknown:
                raise ScheduleError(
                    f'Project {name} references unknown group(s): '
                    f'{", ".join(sorted(unknown))}',
                )
        required = _as_string_set(
            _get_value(
                details,
                'required_capabilities',
                'capabilities',
                'skills',
                'requires',
                default=[],
            ),
            f'required capabilities for project {name}',
        )
        projects[name] = ProjectPolicy(
            name=name,
            allowed_groups=allowed,
            required_capabilities=required,
        )
    return projects


def _parse_tags(raw: Any) -> Dict[str, TagRule]:
    rules: Dict[str, TagRule] = {}
    for key, value in _collect_named(raw, 'tags'):
        name = str(key) if key is not None else None
        if name is None:
            if isinstance(value, str):
                name = value
                value = None
            elif isinstance(value, Mapping):
                name = _get_value(value, 'name', 'tag', 'id')
                if name is None:
                    raise ScheduleError('Every tag needs a name.')
                name = str(name)
                value = dict(value)
            else:
                raise ScheduleError('Every tag needs a name.')
            name = str(name)

        if value is None:
            rules[name] = TagRule(name=name)
        elif isinstance(value, str):
            rules[name] = TagRule(name=name, capabilities=frozenset([value]))
        elif isinstance(value, (int, float)) and not isinstance(value, bool):
            rules[name] = TagRule(name=name, priority=float(value))
        elif isinstance(value, (list, tuple, set, frozenset)):
            rules[name] = TagRule(
                name=name,
                capabilities=_as_string_set(value, f'capabilities for tag {name}'),
            )
        elif isinstance(value, Mapping):
            rules[name] = TagRule(
                name=name,
                capabilities=_as_string_set(
                    _get_value(value, 'capabilities', 'skills', 'requires', default=[]),
                    f'capabilities for tag {name}',
                ),
                priority=_as_float(
                    _get_value(value, 'priority', default=0),
                    f'priority for tag {name}',
                ),
            )
        else:
            raise ScheduleError(f'Invalid definition for tag {name}.')
    return rules


def _parse_candidates(
    raw: Any,
    tags: Mapping[str, TagRule],
    group_names: Set[str],
    group_capabilities: Set[str],
) -> List[Candidate]:
    candidates: List[Candidate] = []
    seen: Set[str] = set()
    for index, (key, value) in enumerate(_collect_named(raw, 'candidates')):
        if isinstance(value, str):
            value = {'id': value}
        if not isinstance(value, Mapping):
            raise ScheduleError('Each candidate must be a mapping/object.')
        value = dict(value)

        candidate_id = _get_value(value, 'id', 'name', 'key', default=key)
        if candidate_id is None:
            candidate_id = f'candidate-{index + 1}'
        candidate_id = str(candidate_id)
        if candidate_id in seen:
            raise ScheduleError(f'Duplicate candidate id: {candidate_id}')
        seen.add(candidate_id)

        hours = _as_float(
            _get_value(value, 'hours', 'time', 'duration', 'cost', 'estimate', default=0),
            f'hours for candidate {candidate_id}',
        )
        if hours < 0:
            raise ScheduleError(f'Candidate {candidate_id} has negative hours.')

        projects = tuple(
            str(project)
            for project in _as_sequence(
                _get_value(value, 'projects', 'project', 'apps', 'applications', default=[]),
                f'projects for candidate {candidate_id}',
            )
        )
        candidate_tags = tuple(
            str(tag)
            for tag in _as_sequence(
                _get_value(value, 'tags', default=[]),
                f'tags for candidate {candidate_id}',
            )
        )

        required = set(
            _as_string_set(
                _get_value(
                    value,
                    'required_capabilities',
                    'capabilities',
                    'skills',
                    'requires',
                    default=[],
                ),
                f'required capabilities for candidate {candidate_id}',
            ),
        )
        tag_priority = 0.0
        for tag in candidate_tags:
            tag_rule = tags.get(tag)
            if tag_rule:
                required.update(tag_rule.capabilities)
                tag_priority = max(tag_priority, tag_rule.priority)
            elif tag in group_capabilities:
                required.add(tag)

        priority = _as_float(
            _get_value(value, 'priority', default=tag_priority),
            f'priority for candidate {candidate_id}',
        )

        default_weight = max(1, len(projects))
        weight = _as_float(
            _get_value(value, 'weight', 'value', default=default_weight),
            f'weight for candidate {candidate_id}',
        )
        if weight < 0:
            raise ScheduleError(f'Candidate {candidate_id} has negative weight.')

        allowed_groups_value = _get_value(
            value,
            'allowed_groups',
            'visible_to',
            'reviewers',
            'groups',
            'permitted',
            default=None,
        )
        allowed_groups: Optional[FrozenSet[str]] = None
        if allowed_groups_value is not None:
            allowed_groups = _as_string_set(
                allowed_groups_value,
                f'allowed groups for candidate {candidate_id}',
            )
            unknown = allowed_groups - group_names
            if unknown:
                raise ScheduleError(
                    f'Candidate {candidate_id} references unknown group(s): '
                    f'{", ".join(sorted(unknown))}',
                )

        candidates.append(
            Candidate(
                id=candidate_id,
                hours=hours,
                projects=projects,
                required_capabilities=frozenset(required),
                tags=candidate_tags,
                priority=priority,
                weight=weight,
                allowed_groups=allowed_groups,
                index=index,
            ),
        )
    return candidates


def _looks_like_named_entry(raw: Mapping[str, Any], section: str) -> bool:
    name_keys = {
        'groups': ('name', 'id', 'group'),
        'projects': ('name', 'id', 'project'),
        'candidates': ('id', 'name', 'key'),
        'tags': ('name', 'tag', 'id'),
    }.get(section, ('name', 'id'))
    payload_keys = {
        'groups': (
            'hours', 'capacity', 'work_hours', 'weekly_hours',
            'capabilities', 'skills', 'tags',
        ),
        'projects': (
            'allowed_groups', 'reviewers', 'groups', 'allowed', 'can_review',
            'required_capabilities', 'capabilities', 'skills',
        ),
        'candidates': (
            'hours', 'time', 'duration', 'cost', 'estimate', 'projects',
            'project', 'tags', 'capabilities', 'skills', 'weight', 'value',
            'visible_to', 'allowed_groups',
        ),
        'tags': ('capabilities', 'skills', 'requires', 'priority'),
    }.get(section, ())
    return any(key in raw for key in name_keys) and any(key in raw for key in payload_keys)


def _collect_named(raw: Any, what: str) -> List[Tuple[Optional[str], Any]]:
    if raw is None:
        return []
    if isinstance(raw, Mapping):
        if _looks_like_named_entry(raw, what):
            return [(None, raw)]
        return list(raw.items())
    if isinstance(raw, Sequence) and not isinstance(raw, (str, bytes)):
        return [(None, item) for item in raw]
    raise ScheduleError(f'{what} must be a mapping or a list.')


def _entry_name(entry: Any, section: str) -> Optional[str]:
    if not isinstance(entry, Mapping):
        return None

    keys = {
        'groups': ('name', 'id', 'group'),
        'projects': ('name', 'id', 'project'),
        'candidates': ('id', 'name', 'key'),
    }.get(section, ('name', 'id'))
    name = _get_value(entry, *keys)
    return str(name) if name is not None else None


def _normalise_section_entry(section: str, key: Optional[str], value: Any) -> Any:
    if section == 'groups':
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return {
                'name': str(key) if key is not None else None,
                'hours': value,
            }
        if isinstance(value, Mapping):
            entry = dict(value)
            if key is not None:
                entry.setdefault('name', str(key))
            return entry
    elif section == 'projects':
        if isinstance(value, (list, tuple, set, frozenset)):
            return {
                'name': str(key) if key is not None else None,
                'allowed_groups': list(value),
            }
        if isinstance(value, str):
            return {
                'name': str(key) if key is not None else value,
                'allowed_groups': [value],
            }
        if isinstance(value, Mapping):
            entry = dict(value)
            if key is not None:
                entry.setdefault('name', str(key))
            return entry
    elif section == 'candidates':
        if isinstance(value, str):
            return {'id': value if key is None else str(key)}
        if isinstance(value, Mapping):
            entry = dict(value)
            if key is not None:
                entry.setdefault('id', str(key))
            return entry
    return value


def _named_to_dict(raw: Any, section: str) -> Dict[str, Any]:
    if raw is None:
        return {}

    result: Dict[str, Any] = {}
    for index, (key, value) in enumerate(_collect_named(raw, section)):
        entry = _normalise_section_entry(section, key, value)
        name = str(key) if key is not None else _entry_name(entry, section)
        if name is None:
            name = f'{section}-{index + 1}'
        result[name] = entry
    return result


def _as_raw_entries(raw: Any, what: str) -> List[Any]:
    return list(_named_to_dict(raw, what).values())


def _merge_named_section(target: Dict[str, Any], key: str, extra: Any) -> None:
    if extra is None:
        return

    merged = _named_to_dict(target.get(key), key)
    incoming = _named_to_dict(extra, key)
    merged.update(incoming)
    target[key] = list(merged.values())


def _collect_permissions(raw: Any) -> List[Tuple[str, List[str]]]:
    if raw is None:
        return []
    result: List[Tuple[str, List[str]]] = []
    if isinstance(raw, Mapping):
        if _looks_like_named_entry(raw, 'projects'):
            raw = [raw]
        for name, value in raw.items():
            if isinstance(value, Mapping):
                allowed = _get_value(
                    value,
                    'allowed_groups',
                    'reviewers',
                    'groups',
                    'allowed',
                    default=[],
                )
            else:
                allowed = value
            result.append((
                str(name),
                [str(item) for item in _as_sequence(allowed, f'allowed groups for {name}')],
            ))
        return result
    if isinstance(raw, Sequence) and not isinstance(raw, (str, bytes)):
        for item in raw:
            if not isinstance(item, Mapping):
                raise ScheduleError('Permissions must be a mapping or a list of mappings.')
            name = _get_value(item, 'project', 'name', 'id')
            if name is None:
                raise ScheduleError('Every permission entry needs a project name.')
            allowed = _get_value(
                item,
                'allowed_groups',
                'reviewers',
                'groups',
                'allowed',
                default=[],
            )
            result.append((
                str(name),
                [str(item) for item in _as_sequence(allowed, f'allowed groups for {name}')],
            ))
        return result
    raise ScheduleError('Permissions must be a mapping or a list of mappings.')


def _merge_mapping_section(
    target: Dict[str, Any],
    key: str,
    extra: Any,
) -> None:
    if extra is None:
        return
    if not isinstance(extra, Mapping):
        raise ScheduleError(f'{key} must be a mapping/object.')
    existing = target.get(key)
    if existing is None:
        existing = {}
    if not isinstance(existing, Mapping):
        existing = _named_to_dict(existing, key)
    merged = dict(existing)
    merged.update(extra)
    target[key] = merged


def _extract_section(data: Mapping[str, Any], key: str, alias: Optional[str] = None) -> Any:
    if key in data:
        return data[key]
    if alias is not None and alias in data:
        return data[alias]
    return data


def _extract_work_hours(data: Mapping[str, Any]) -> Any:
    if 'work_hours' in data:
        return data['work_hours']
    if 'local_hours' in data:
        return data['local_hours']
    if 'groups' in data:
        return data['groups']
    return data


def _get_value(
    mapping: Mapping[str, Any],
    *keys: str,
    default: Any = None,
) -> Any:
    for key in keys:
        if key in mapping and mapping[key] is not None:
            return mapping[key]
    return default


def _as_sequence(value: Any, what: str) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, bytes):
        return [value.decode('utf-8')]
    if isinstance(value, (list, tuple, set, frozenset)):
        return list(value)
    raise ScheduleError(f'{what} must be a list or a single value.')


def _as_string_set(value: Any, what: str) -> FrozenSet[str]:
    return frozenset(str(item) for item in _as_sequence(value, what))


def _as_float(value: Any, what: str) -> float:
    try:
        result = float(value)
    except (TypeError, ValueError):
        raise ScheduleError(f'{what} must be a number.')
    if math.isnan(result) or math.isinf(result):
        raise ScheduleError(f'{what} must be a finite number.')
    return result


def _parse_weeks(value: Any) -> int:
    try:
        weeks = int(value)
    except (TypeError, ValueError):
        raise ScheduleError('weeks must be a positive integer.')
    if weeks < 1:
        raise ScheduleError('weeks must be a positive integer.')
    return weeks


def _scale(value: float) -> int:
    return int(round(value * HOURS_SCALE))


def _unscale(value: int) -> float:
    return value / HOURS_SCALE


def _round_hours(value: float) -> float:
    return round(value, 6)
