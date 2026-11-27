from __future__ import annotations

import pytest

from pip_audit._remediation_plan import (
    CandidateWindowCondition,
    CommonWindowCondition,
    MaintenanceWindow,
    MutexCondition,
    RemediationCandidate,
    RemediationPlanningError,
    plan_all_candidates,
    plan_remediation_candidates,
)


def _candidate(
    resolution_id: str,
    dependency: str,
    version: str,
    *windows: MaintenanceWindow,
    environments: tuple[str, ...] = (),
) -> RemediationCandidate:
    return RemediationCandidate(
        resolution_id=resolution_id,
        dependency=dependency,
        version=version,
        windows=windows,
        environments=environments,
    )


def test_plan_all_candidates_orders_by_deterministic_slot():
    first = _candidate("first", "foo", "1.0.0", MaintenanceWindow(1, 2))
    second = _candidate("second", "bar", "2.0.0", MaintenanceWindow(2, 3))

    plan = plan_all_candidates(
        [second, first],
        mutexes=[MutexCondition("first", "second")],
    )

    assert [item.candidate.resolution_id for item in plan.schedule] == ["first", "second"]
    assert [item.slot for item in plan.schedule] == [1, 2]
    assert [candidate.resolution_id for candidate in plan.order] == ["first", "second"]


def test_alternative_candidate_order_does_not_change_plan():
    first = _candidate("foo-a", "foo", "1.0.0", MaintenanceWindow(1, 1))
    second = _candidate("foo-b", "foo", "2.0.0", MaintenanceWindow(2, 2))

    forward = plan_remediation_candidates({"foo": [first, second]})
    reversed_plan = plan_remediation_candidates({"foo": [second, first]})

    assert reversed_plan == forward
    assert forward.order == (first,)
    assert forward.schedule[0].slot == 1


def test_common_window_and_mutexes_select_cross_environment_resolutions():
    foo_a = _candidate(
        "foo-a", "foo", "1.0.0", MaintenanceWindow(1, 1), environments=("env-a",)
    )
    foo_b = _candidate(
        "foo-b", "foo", "1.1.0", MaintenanceWindow(2, 2), environments=("env-b",)
    )
    bar_a = _candidate(
        "bar-a", "bar", "3.0.0", MaintenanceWindow(1, 1), environments=("env-a",)
    )
    bar_b = _candidate(
        "bar-b", "bar", "3.1.0", MaintenanceWindow(2, 2), environments=("env-b",)
    )

    mutexes = [
        MutexCondition("bar-a", "foo-a"),
        MutexCondition("foo-b", "bar-b"),
    ]
    plan = plan_remediation_candidates(
        {"bar": [bar_b, bar_a], "foo": [foo_b, foo_a]},
        mutexes=mutexes,
        common_window=MaintenanceWindow(1, 2),
    )
    reversed_plan = plan_remediation_candidates(
        {"bar": [bar_a, bar_b], "foo": [foo_a, foo_b]},
        mutexes=list(reversed(mutexes)),
        common_window=MaintenanceWindow(1, 2),
    )

    assert reversed_plan == plan
    assert len(plan.schedule) == 2
    assert {item.slot for item in plan.schedule} == {1, 2}
    occupied_slots = {item.candidate.resolution_id: item.slot for item in plan.schedule}
    for mutex in mutexes:
        assert occupied_slots.get(mutex.left_id) != occupied_slots.get(mutex.right_id)


def test_conflict_proof_is_minimal_and_order_insensitive():
    foo_a = _candidate("foo-a", "foo", "1.0.0", MaintenanceWindow(1, 1))
    foo_b = _candidate("foo-b", "foo", "1.1.0", MaintenanceWindow(1, 1))
    bar_a = _candidate("bar-a", "bar", "3.0.0", MaintenanceWindow(1, 1))
    bar_b = _candidate("bar-b", "bar", "3.1.0", MaintenanceWindow(1, 1))
    mutexes = [
        MutexCondition("bar-b", "foo-b"),
        MutexCondition("bar-a", "foo-b"),
        MutexCondition("bar-b", "foo-a"),
        MutexCondition("bar-a", "foo-a"),
    ]

    with pytest.raises(RemediationPlanningError) as forward_error:
        plan_remediation_candidates(
            {"foo": [foo_a, foo_b], "bar": [bar_a, bar_b]},
            mutexes=mutexes,
        )
    with pytest.raises(RemediationPlanningError) as reversed_error:
        plan_remediation_candidates(
            {"bar": [bar_b, bar_a], "foo": [foo_b, foo_a]},
            mutexes=list(reversed(mutexes)),
        )

    expected = tuple(sorted(mutexes))
    assert forward_error.value.conflict_conditions == expected
    assert reversed_error.value.conflict_conditions == expected
    for condition in expected:
        reduced = [item for item in expected if item != condition]
        reduced_plan = plan_remediation_candidates(
            {"foo": [foo_a, foo_b], "bar": [bar_a, bar_b]},
            mutexes=reduced,
        )
        assert len(reduced_plan.schedule) == 2


def test_common_window_conflict_includes_window_evidence():
    candidate = _candidate("foo-a", "foo", "1.0.0", MaintenanceWindow(1, 1))

    with pytest.raises(RemediationPlanningError) as error:
        plan_all_candidates([candidate], common_window=MaintenanceWindow(2, 2))

    assert error.value.conflict_conditions == (
        CandidateWindowCondition("foo-a", (MaintenanceWindow(1, 1),)),
        CommonWindowCondition(MaintenanceWindow(2, 2)),
    )


def test_candidate_without_common_window_intersection_reports_both_conditions():
    candidate = _candidate("foo-a", "foo", "1.0.0", MaintenanceWindow(1, 1))

    with pytest.raises(RemediationPlanningError) as error:
        plan_remediation_candidates(
            {"foo": [candidate]}, common_window=MaintenanceWindow(2, 2)
        )

    assert error.value.conflict_conditions == (
        CandidateWindowCondition("foo-a", (MaintenanceWindow(1, 1),)),
        CommonWindowCondition(MaintenanceWindow(2, 2)),
    )


def test_invalid_candidate_and_mutex_inputs():
    candidate = _candidate("foo-a", "foo", "1.0.0", MaintenanceWindow(1, 1))

    with pytest.raises(ValueError, match="unknown mutex candidate"):
        plan_all_candidates([candidate], mutexes=[MutexCondition("foo-a", "missing")])

    duplicate = _candidate("foo-a", "foo", "2.0.0", MaintenanceWindow(1, 1))
    with pytest.raises(ValueError, match="duplicate candidate id"):
        plan_remediation_candidates({"foo": [candidate, duplicate]})


def test_mutex_iterable_is_consumed_after_validation():
    first = _candidate("first", "foo", "1.0.0", MaintenanceWindow(1, 1))
    second = _candidate("second", "bar", "2.0.0", MaintenanceWindow(1, 2))

    plan = plan_all_candidates(
        [first, second],
        mutexes=iter([MutexCondition("first", "second")]),
    )

    assert plan.order == (first, second)
    assert [item.slot for item in plan.schedule] == [1, 2]


def test_maintenance_window_validates_bounds():
    with pytest.raises(ValueError, match="must not start after it ends"):
        MaintenanceWindow(2, 1)
