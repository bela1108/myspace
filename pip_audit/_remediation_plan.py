"""
Offline planning for sequenced dependency remediations.
"""

from __future__ import annotations

from collections.abc import Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass


@dataclass(frozen=True, order=True)
class MaintenanceWindow:
    """
    An inclusive, discrete set of execution slots available for a change.
    """

    start: int
    end: int

    def __post_init__(self) -> None:
        if self.start > self.end:
            raise ValueError("maintenance window must not start after it ends")

    def contains(self, slot: int) -> bool:
        """
        Return whether `slot` is inside this window.
        """
        return self.start <= slot <= self.end

    def intersects(self, other: MaintenanceWindow) -> bool:
        """
        Return whether this window shares at least one slot with `other`.
        """
        return self.start <= other.end and other.start <= self.end


@dataclass(frozen=True, order=True)
class RemediationCandidate:
    """
    A concrete, offline dependency resolution that may be scheduled.
    """

    resolution_id: str
    dependency: str
    version: str
    windows: tuple[MaintenanceWindow, ...]
    environments: frozenset[str] = frozenset()

    def __init__(
        self,
        resolution_id: str,
        dependency: str,
        version: str,
        windows: Iterable[MaintenanceWindow],
        environments: Iterable[str] = (),
    ) -> None:
        if not resolution_id:
            raise ValueError("resolution id must not be empty")
        if not dependency:
            raise ValueError("dependency name must not be empty")
        normalized_windows = tuple(sorted(set(windows)))
        if not normalized_windows:
            raise ValueError("candidate must have at least one window")
        object.__setattr__(self, "resolution_id", resolution_id)
        object.__setattr__(self, "dependency", dependency)
        object.__setattr__(self, "version", version)
        object.__setattr__(self, "windows", normalized_windows)
        object.__setattr__(self, "environments", frozenset(environments))


@dataclass(frozen=True, order=True)
class MutexCondition:
    """
    Forbid two candidates from executing in the same slot.
    """

    left_id: str
    right_id: str

    def __post_init__(self) -> None:
        if not self.left_id or not self.right_id:
            raise ValueError("mutex candidate ids must not be empty")
        if self.left_id == self.right_id:
            raise ValueError("mutex condition must reference two different candidates")
        normalized = tuple(sorted((self.left_id, self.right_id)))
        object.__setattr__(self, "left_id", normalized[0])
        object.__setattr__(self, "right_id", normalized[1])


@dataclass(frozen=True, order=True)
class AtMostOneSelectedCondition:
    """
    Require at most one member of a candidate group to be selected.
    """

    condition_id: str
    candidate_ids: frozenset[str]

    def __init__(self, condition_id: str, candidate_ids: Iterable[str]) -> None:
        normalized_ids = frozenset(candidate_ids)
        if not condition_id:
            raise ValueError("condition id must not be empty")
        if len(normalized_ids) < 2:
            raise ValueError("at-most-one condition needs at least two candidates")
        object.__setattr__(self, "condition_id", condition_id)
        object.__setattr__(self, "candidate_ids", normalized_ids)


@dataclass(frozen=True, order=True)
class CandidateWindowCondition:
    """
    Require a selected candidate to use a slot in one of its windows.
    """

    candidate_id: str
    windows: tuple[MaintenanceWindow, ...]


@dataclass(frozen=True, order=True)
class CommonWindowCondition:
    """
    Require every selected candidate to have a slot in a shared window.
    """

    window: MaintenanceWindow


PlanningCondition = (
    AtMostOneSelectedCondition
    | CandidateWindowCondition
    | CommonWindowCondition
    | MutexCondition
)


@dataclass(frozen=True, order=True)
class ScheduledCandidate:
    """
    A candidate assigned to a concrete execution slot.
    """

    slot: int
    candidate: RemediationCandidate


@dataclass(frozen=True)
class RemediationPlan:
    """
    A deterministic execution order for one candidate from each input group.
    """

    schedule: tuple[ScheduledCandidate, ...]

    @property
    def order(self) -> tuple[RemediationCandidate, ...]:
        """
        Return candidates in execution-slot order.
        """
        return tuple(item.candidate for item in self.schedule)


class RemediationPlanningError(Exception):
    """
    Raised when no remediation schedule can satisfy the supplied constraints.
    """

    def __init__(self, conflict_conditions: Sequence[PlanningCondition]) -> None:
        self.conflict_conditions = tuple(conflict_conditions)
        super().__init__("no remediation schedule satisfies the supplied constraints")


def plan_remediation_candidates(
    candidates_by_group: Mapping[str, Collection[RemediationCandidate]],
    mutexes: Iterable[MutexCondition] = (),
    common_window: MaintenanceWindow | None = None,
) -> RemediationPlan:
    """
    Build an offline schedule containing one alternative from every group.

    Candidate input order does not affect the resulting plan or the conflict
    proof returned by `RemediationPlanningError`.
    """

    normalized_groups = _normalize_groups(candidates_by_group)
    candidates = tuple(candidate for group in normalized_groups.values() for candidate in group)
    candidate_by_id = {candidate.resolution_id: candidate for candidate in candidates}
    normalized_mutexes = _normalize_mutexes(mutexes)
    _validate_mutexes(normalized_mutexes, candidate_by_id)

    conditions = list(_candidate_conditions(candidates))
    conditions.extend(_alternative_conditions(normalized_groups))
    conditions.extend(normalized_mutexes)
    if common_window is not None:
        conditions.append(CommonWindowCondition(common_window))
    conditions = _sorted_conditions(conditions)

    schedule = _solve(normalized_groups, candidate_by_id, conditions)
    if schedule is None:
        raise RemediationPlanningError(_minimal_conflict_conditions(normalized_groups, conditions))
    return RemediationPlan(schedule=tuple(sorted(schedule)))

def plan_all_candidates(
    candidates: Iterable[RemediationCandidate],
    mutexes: Iterable[MutexCondition] = (),
    common_window: MaintenanceWindow | None = None,
) -> RemediationPlan:
    """
    Build an offline schedule that includes every supplied candidate.
    """

    indexed_candidates = tuple(sorted(candidates))
    groups = {candidate.resolution_id: (candidate,) for candidate in indexed_candidates}
    return plan_remediation_candidates(groups, mutexes, common_window)

def _normalize_groups(
    candidates_by_group: Mapping[str, Collection[RemediationCandidate]],
) -> dict[str, tuple[RemediationCandidate, ...]]:
    if not candidates_by_group:
        raise ValueError("at least one candidate group is required")

    seen_ids: set[str] = set()
    groups: dict[str, tuple[RemediationCandidate, ...]] = {}
    for group_key in sorted(candidates_by_group):
        if not group_key:
            raise ValueError("group key must not be empty")
        group = tuple(
            sorted(candidates_by_group[group_key], key=lambda candidate: candidate.resolution_id)
        )
        if not group:
            raise ValueError(f"candidate group {group_key} must not be empty")
        for candidate in group:
            if candidate.resolution_id in seen_ids:
                raise ValueError(f"duplicate candidate id: {candidate.resolution_id}")
            seen_ids.add(candidate.resolution_id)
        groups[group_key] = group
    return groups

def _validate_mutexes(
    mutexes: Collection[MutexCondition], candidate_by_id: Mapping[str, RemediationCandidate]
) -> None:
    if len(set(mutexes)) != len(tuple(mutexes)):
        raise ValueError("duplicate mutex conditions are not allowed")
    for mutex in mutexes:
        for candidate_id in (mutex.left_id, mutex.right_id):
            if candidate_id not in candidate_by_id:
                raise ValueError(f"unknown mutex candidate id: {candidate_id}")

def _normalize_mutexes(mutexes: Iterable[MutexCondition]) -> tuple[MutexCondition, ...]:
    return tuple(sorted(set(mutexes)))

def _candidate_conditions(
    candidates: Iterable[RemediationCandidate],
) -> Iterable[CandidateWindowCondition]:
    return (
        CandidateWindowCondition(candidate.resolution_id, candidate.windows)
        for candidate in candidates
    )

def _alternative_conditions(
    groups: Mapping[str, tuple[RemediationCandidate, ...]],
) -> tuple[AtMostOneSelectedCondition, ...]:
    return tuple(
        AtMostOneSelectedCondition(
            f"alternative:{group_key}",
            tuple(candidate.resolution_id for candidate in group),
        )
        for group_key, group in groups.items()
        if len(group) > 1
    )

def _sorted_conditions(conditions: Iterable[PlanningCondition]) -> list[PlanningCondition]:
    return sorted(conditions, key=_condition_key)

def _condition_key(condition: PlanningCondition) -> tuple[str, str]:
    if isinstance(condition, AtMostOneSelectedCondition):
        return ("at_most_one", condition.condition_id)
    if isinstance(condition, CandidateWindowCondition):
        return ("candidate_window", condition.candidate_id)
    if isinstance(condition, CommonWindowCondition):
        return ("common_window", str(condition.window))
    return ("mutex", f"{condition.left_id}:{condition.right_id}")

def _solve(
    groups: Mapping[str, tuple[RemediationCandidate, ...]],
    candidate_by_id: Mapping[str, RemediationCandidate],
    conditions: Sequence[PlanningCondition],
) -> list[ScheduledCandidate] | None:
    base_slots = _base_slots(candidate_by_id.values(), conditions)
    if not base_slots:
        return None

    def backtrack(
        group_keys: Sequence[str],
        assignments: dict[str, int],
    ) -> list[ScheduledCandidate] | None:
        if not group_keys:
            return [
                ScheduledCandidate(slot, candidate_by_id[candidate_id])
                for candidate_id, slot in assignments.items()
            ]

        group_key = group_keys[0]
        remaining_groups = group_keys[1:]
        for candidate in groups[group_key]:
            for slot in base_slots:
                assignments[candidate.resolution_id] = slot
                if _partial_assignment_is_valid(candidate.resolution_id, slot, assignments, conditions):
                    result = backtrack(remaining_groups, assignments)
                    if result is not None:
                        return result
            assignments.pop(candidate.resolution_id, None)
        return None

    return backtrack(tuple(groups), {})

def _base_slots(
    candidates: Iterable[RemediationCandidate], conditions: Sequence[PlanningCondition]
) -> tuple[int, ...]:
    common_conditions = [
        condition
        for condition in conditions
        if isinstance(condition, CommonWindowCondition)
    ]
    if common_conditions:
        return tuple(slot for condition in common_conditions for slot in range(condition.window.start, condition.window.end + 1))

    slots = {
        slot
        for candidate in candidates
        for window in candidate.windows
        for slot in range(window.start, window.end + 1)
    }
    return tuple(sorted(slots))

def _partial_assignment_is_valid(
    candidate_id: str,
    slot: int,
    assignments: Mapping[str, int],
    conditions: Sequence[PlanningCondition],
) -> bool:
    for condition in conditions:
        if isinstance(condition, AtMostOneSelectedCondition):
            selected = condition.candidate_ids.intersection(assignments)
            if len(selected) > 1:
                return False
        elif isinstance(condition, CandidateWindowCondition):
            if condition.candidate_id == candidate_id and not any(
                window.contains(slot) for window in condition.windows
            ):
                return False
        elif isinstance(condition, CommonWindowCondition):
            if not condition.window.contains(slot):
                return False
        elif condition.left_id == candidate_id or condition.right_id == candidate_id:
            other_id = (
                condition.right_id if condition.left_id == candidate_id else condition.left_id
            )
            if assignments.get(other_id) == slot:
                return False
    return True

def _minimal_conflict_conditions(
    groups: Mapping[str, tuple[RemediationCandidate, ...]],
    conditions: Sequence[PlanningCondition],
) -> tuple[PlanningCondition, ...]:
    core = list(conditions)
    for condition in conditions:
        reduced = [item for item in core if item != condition]
        if _solve(groups, _candidate_by_id(groups), reduced) is None:
            core = reduced
    return tuple(core)

def _candidate_by_id(
    groups: Mapping[str, tuple[RemediationCandidate, ...]],
) -> dict[str, RemediationCandidate]:
    return {
        candidate.resolution_id: candidate
        for group in groups.values()
        for candidate in group
    }
