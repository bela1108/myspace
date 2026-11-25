"""
The scheduler module distributes pending manual review work across reviewer
groups, entirely offline.

Each reviewer group has a weekly hour budget, and a set of projects it is
permitted to receive findings for. A candidate that appears in multiple
projects (a *shared* candidate) is only reviewed once -- it consumes review
time from a single group -- but that group must be permitted to receive
*every* project the candidate appears in.

Privacy note: this module never persists secret values, nor any stable
fingerprint of them (e.g. the baseline's hashed secrets). Scheduled work is
identified by randomly generated task IDs, so repeated runs cannot be
correlated with each other, or with the baseline itself.
"""
import json
import uuid
from typing import Any
from typing import Dict
from typing import FrozenSet
from typing import List
from typing import Mapping
from typing import NamedTuple
from typing import Optional
from typing import Set
from typing import Tuple

from ..core.secrets_collection import SecretsCollection
from .common import get_baseline_from_file


DEFAULT_REVIEW_HOURS_PER_SECRET = 0.5

# The exhaustive solver is only meant to validate the greedy scheduler on
# small inputs. Beyond this many candidates, the branch space is too large
# to enumerate responsibly.
EXHAUSTIVE_SEARCH_LIMIT = 12

# Tolerance for float comparisons of hour budgets.
_EPSILON = 1e-9


class ReviewerGroup(NamedTuple):
    name: str
    weekly_hours: float
    projects: FrozenSet[str]

    @staticmethod
    def from_json(data: Dict[str, Any]) -> 'ReviewerGroup':
        """
        :raises: ValueError
        """
        try:
            group = ReviewerGroup(
                name=str(data['name']),
                weekly_hours=float(data['weekly_hours']),
                projects=frozenset(str(project) for project in data['projects']),
            )
        except (KeyError, TypeError, ValueError):
            raise ValueError(f'Invalid reviewer group specification: {data!r}')

        if not group.name or group.weekly_hours < 0:
            raise ValueError(f'Invalid reviewer group specification: {data!r}')

        return group


def load_groups_from_file(filename: str) -> List[ReviewerGroup]:
    """
    :raises: ValueError
    """
    with open(filename) as f:
        data = json.load(f)

    if not isinstance(data, list) or not data:
        raise ValueError('Reviewer group specification must be a non-empty JSON array.')

    groups = [ReviewerGroup.from_json(item) for item in data]
    names = [group.name for group in groups]
    if len(set(names)) != len(names):
        raise ValueError('Reviewer group names must be unique.')

    return groups


class ReviewCandidate:
    """A unit of pending manual review work.

    This is an in-memory only representation: the dedupe key is a stable
    fingerprint of the finding, used solely to merge shared candidates
    across projects. It is never serialized.
    """

    def __init__(self, key: Tuple[str, str], projects: Set[str], hours: float) -> None:
        self.key = key
        self.projects = projects
        self.hours = hours


def collect_candidates(
    baselines: Mapping[str, SecretsCollection],
    review_hours_per_secret: float = DEFAULT_REVIEW_HOURS_PER_SECRET,
) -> List[ReviewCandidate]:
    """Gathers unlabelled secrets from each project's baseline, merging
    findings that are shared across projects into a single candidate."""
    candidates: Dict[Tuple[str, str], ReviewCandidate] = {}
    for project, secrets in baselines.items():
        for _, secret in secrets:
            if secret.is_secret is not None:
                continue

            key = (secret.type, secret.secret_hash)
            if key not in candidates:
                candidates[key] = ReviewCandidate(
                    key=key,
                    projects={project},
                    hours=review_hours_per_secret,
                )
            else:
                candidates[key].projects.add(project)

    return list(candidates.values())


def collect_candidates_from_files(
    filenames: List[str],
    review_hours_per_secret: float = DEFAULT_REVIEW_HOURS_PER_SECRET,
) -> List[ReviewCandidate]:
    """
    :raises: InvalidBaselineError
    """
    return collect_candidates(
        {
            filename: get_baseline_from_file(filename)
            for filename in filenames
        },
        review_hours_per_secret=review_hours_per_secret,
    )


class Schedule:
    def __init__(
        self,
        assignments: List[Tuple[ReviewCandidate, ReviewerGroup]],
        unscheduled: List[ReviewCandidate],
        groups: List[ReviewerGroup],
    ) -> None:
        self.assignments = assignments
        self.unscheduled = unscheduled
        self.groups = groups

    @property
    def unscheduled_hours(self) -> float:
        return sum(candidate.hours for candidate in self.unscheduled)

    def json(self) -> Dict[str, Any]:
        assigned_hours: Dict[str, float] = {group.name: 0.0 for group in self.groups}
        tasks = []
        for candidate, group in self.assignments:
            assigned_hours[group.name] += candidate.hours
            tasks.append({
                # Randomized per run, so output carries no stable fingerprint
                # of the underlying finding.
                'task_id': uuid.uuid4().hex,
                'group': group.name,
                'projects': sorted(candidate.projects),
                'hours': round(candidate.hours, 4),
            })

        capacity = {
            group.name: {
                'weekly_hours': round(group.weekly_hours, 4),
                'assigned_hours': round(assigned_hours[group.name], 4),
                'remaining_hours': round(group.weekly_hours - assigned_hours[group.name], 4),
            }
            for group in self.groups
        }

        gap_projects: Dict[str, Dict[str, Any]] = {}
        for candidate in self.unscheduled:
            for project in sorted(candidate.projects):
                gap_projects.setdefault(
                    project,
                    {'unscheduled_tasks': 0, 'unscheduled_hours': 0.0},
                )
                gap_projects[project]['unscheduled_tasks'] += 1
                gap_projects[project]['unscheduled_hours'] += candidate.hours
        for breakdown in gap_projects.values():
            breakdown['unscheduled_hours'] = round(breakdown['unscheduled_hours'], 4)

        return {
            'tasks': tasks,
            'capacity': capacity,
            'gaps': {
                'unscheduled_tasks': len(self.unscheduled),
                'unscheduled_hours': round(self.unscheduled_hours, 4),
                'projects': gap_projects,
            },
        }


def _get_eligible_groups(
    candidate: ReviewCandidate,
    groups: List[ReviewerGroup],
) -> List[ReviewerGroup]:
    """A group may only receive a candidate if it is permitted to receive
    *every* project the candidate appears in."""
    return [
        group
        for group in groups
        if candidate.projects.issubset(group.projects)
    ]


def schedule_review(
    candidates: List[ReviewCandidate],
    groups: List[ReviewerGroup],
) -> Schedule:
    """Greedily assigns candidates to reviewer groups.

    The most constrained candidates (fewest eligible groups, then largest
    cost) are placed first, each into the eligible group with the most
    remaining weekly hours. Anything that does not fit is reported as a gap.
    """
    remaining = {group.name: group.weekly_hours for group in groups}
    eligible = {
        id(candidate): _get_eligible_groups(candidate, groups)
        for candidate in candidates
    }

    ordered = sorted(
        candidates,
        key=lambda candidate: (
            len(eligible[id(candidate)]),
            -candidate.hours,
            sorted(candidate.projects),
        ),
    )

    assignments = []
    unscheduled = []
    for candidate in ordered:
        fits = [
            group
            for group in eligible[id(candidate)]
            if remaining[group.name] + _EPSILON >= candidate.hours
        ]
        if not fits:
            unscheduled.append(candidate)
            continue

        chosen = max(fits, key=lambda group: (remaining[group.name], group.name))
        remaining[chosen.name] -= candidate.hours
        assignments.append((candidate, chosen))

    return Schedule(assignments, unscheduled, groups)


def exhaustive_schedule(
    candidates: List[ReviewCandidate],
    groups: List[ReviewerGroup],
) -> Schedule:
    """Brute-forces the assignment that minimizes unscheduled review hours
    (then unscheduled task count). Only intended for small inputs, to
    validate the greedy scheduler's worst branch.

    :raises: ValueError
    """
    if len(candidates) > EXHAUSTIVE_SEARCH_LIMIT:
        raise ValueError(
            f'Refusing to exhaustively search {len(candidates)} candidates '
            f'(limit: {EXHAUSTIVE_SEARCH_LIMIT}).',
        )

    ordered = sorted(
        candidates,
        key=lambda candidate: (sorted(candidate.projects), candidate.key),
    )
    eligible = [
        [
            index
            for index, group in enumerate(groups)
            if candidate.projects.issubset(group.projects)
        ]
        for candidate in ordered
    ]

    best_key = (float('inf'), float('inf'))
    best_assignment: Optional[List[Optional[int]]] = None
    current: List[Optional[int]] = [None] * len(ordered)
    remaining = [group.weekly_hours for group in groups]

    def search(index: int, unscheduled_hours: float, unscheduled_count: int) -> None:
        nonlocal best_key, best_assignment

        if (unscheduled_hours, unscheduled_count) >= best_key:
            return

        if index == len(ordered):
            best_key = (unscheduled_hours, unscheduled_count)
            best_assignment = list(current)
            return

        candidate = ordered[index]
        for group_index in eligible[index]:
            if remaining[group_index] + _EPSILON >= candidate.hours:
                remaining[group_index] -= candidate.hours
                current[index] = group_index
                search(index + 1, unscheduled_hours, unscheduled_count)
                remaining[group_index] += candidate.hours

        current[index] = None
        search(index + 1, unscheduled_hours + candidate.hours, unscheduled_count + 1)
        current[index] = None

    search(0, 0.0, 0)

    assert best_assignment is not None
    assignments = []
    unscheduled = []
    for candidate, group_index in zip(ordered, best_assignment):
        if group_index is None:
            unscheduled.append(candidate)
        else:
            assignments.append((candidate, groups[group_index]))

    return Schedule(assignments, unscheduled, groups)


def schedule_from_files(
    filenames: List[str],
    groups: List[ReviewerGroup],
    review_hours_per_secret: float = DEFAULT_REVIEW_HOURS_PER_SECRET,
) -> Schedule:
    """
    :raises: InvalidBaselineError
    """
    return schedule_review(
        collect_candidates_from_files(
            filenames,
            review_hours_per_secret=review_hours_per_secret,
        ),
        groups,
    )

