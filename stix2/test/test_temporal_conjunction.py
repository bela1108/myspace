import datetime as dt

import pytest

import stix2
from stix2 import Filter
from stix2.temporal_conjunction import (
    ConjunctionStatus,
    ConjunctionContractError,
    evidence_from_stix,
    local_conjunctive_query,
    select_object_versions,
    week_window,
)


PATTERN = "[ipv4-addr:value = '198.51.100.7']"
INDICATOR_1 = "indicator--11111111-1111-4111-8111-111111111111"
INDICATOR_2 = "indicator--22222222-2222-4222-8222-222222222222"
OBSERVATION_MINUTE = "observed-data--33333333-3333-4333-8333-333333333333"
OBSERVATION_WEEK = "observed-data--44444444-4444-4444-8444-444444444444"
UTC = dt.timezone.utc


def make_indicator(indicator_id, valid_from, valid_until, **kwargs):
    return stix2.v21.Indicator(
        id=indicator_id,
        created="2024-05-01T00:00:00.000Z",
        modified=kwargs.pop("modified", "2024-05-01T00:00:00.000Z"),
        indicator_types=["malicious-activity"],
        pattern=PATTERN,
        pattern_type="stix",
        valid_from=valid_from,
        valid_until=valid_until,
        **kwargs,
    )


def make_observations():
    minute_object = stix2.v21.ObservedData(
        id=OBSERVATION_MINUTE,
        first_observed="2024-05-15T10:30:00Z",
        last_observed="2024-05-15T10:30:00Z",
        number_observed=1,
        object_refs=["ipv4-addr--aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"],
        x_time_precision="minute",
        allow_custom=True,
    )
    week_object = stix2.v21.ObservedData(
        id=OBSERVATION_WEEK,
        first_observed="2024-05-13T00:00:00Z",
        last_observed="2024-05-13T00:00:00Z",
        number_observed=1,
        object_refs=["ipv4-addr--bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"],
        x_time_precision="week",
        allow_custom=True,
    )
    return {
        INDICATOR_1: evidence_from_stix(minute_object, indicator_ref=INDICATOR_1),
        INDICATOR_2: evidence_from_stix(week_object, indicator_ref=INDICATOR_2),
    }


def test_week_and_minute_windows_follow_explicit_utc_contract():
    week = week_window("2024-W20")

    assert week.start == dt.datetime(2024, 5, 13, 0, 0, tzinfo=UTC)
    assert week.end == dt.datetime(2024, 5, 20, 0, 0, tzinfo=UTC)
    assert week.start_inclusive is True
    assert week.end_inclusive is False


def test_acceptance_same_pattern_different_windows_truncates_and_requests_week_time():
    first = make_indicator(
        INDICATOR_1,
        "2024-05-01T00:00:00Z",
        "2024-05-31T00:00:00Z",
    )
    second = make_indicator(
        INDICATOR_2,
        "2024-05-15T00:00:00Z",
        "2024-05-16T12:00:00Z",
        modified="2024-05-10T00:00:00.000Z",
    )

    result = local_conjunctive_query(
        PATTERN,
        [first, second],
        observations=make_observations(),
        spec_version="2.1",
    )
    payload = result.to_dict()

    assert result.status is ConjunctionStatus.SOME_CREDIBLE_COMMON_POINT
    assert payload["status_zh"] == "存在某个可信共同点"
    assert result.credible_common_point is True
    assert result.all_legal_times_support is False
    assert result.observations_needing_time == [OBSERVATION_WEEK]

    first_bounds = result.truncated_boundaries[INDICATOR_1]
    second_bounds = result.truncated_boundaries[INDICATOR_2]
    assert first_bounds["start"] == "2024-05-15T10:30:00Z"
    assert first_bounds["end"] == "2024-05-15T10:31:00Z"
    assert second_bounds["start"] == "2024-05-15T00:00:00Z"
    assert second_bounds["end"] == "2024-05-16T12:00:00Z"

    assert payload["common_boundaries"]["start"] == "2024-05-15T10:30:00Z"
    assert payload["common_boundaries"]["end"] == "2024-05-15T10:31:00Z"
    assert [(f.property, f.op, f.value) for f in result_filter_contract(result)] == [
        ("type", "=", "indicator"),
        ("pattern", "=", PATTERN),
    ]


def result_filter_contract(result):
    return [Filter(prop, op, value) for prop, op, value in result.filter_contract]


def test_all_legal_times_are_supported_when_week_fits_common_validity():
    first = make_indicator(
        INDICATOR_1,
        "2024-05-01T00:00:00Z",
        "2024-06-01T00:00:00Z",
    )
    second = make_indicator(
        INDICATOR_2,
        "2024-05-10T00:00:00Z",
        "2024-05-25T00:00:00Z",
    )

    result = local_conjunctive_query(
        PATTERN,
        [first, second],
        observations=make_observations(),
    )

    assert result.status is ConjunctionStatus.ALL_LEGAL_TIMES_SUPPORT
    assert result.all_legal_times_support is True
    assert result.credible_common_point is True
    assert result.observations_needing_time == []


def test_missing_observation_time_is_insufficient_evidence():
    first = make_indicator(
        INDICATOR_1,
        "2024-05-01T00:00:00Z",
        "2024-05-31T00:00:00Z",
    )
    second = make_indicator(
        INDICATOR_2,
        "2024-05-15T00:00:00Z",
        "2024-05-16T12:00:00Z",
    )

    result = local_conjunctive_query(PATTERN, [first, second])

    assert result.status is ConjunctionStatus.INSUFFICIENT_EVIDENCE
    assert result.insufficient_evidence is True
    assert result.credible_common_point is False
    assert result.common_validity_window is not None
    assert result.common_window is None
    assert set(result.observations_needing_time) == {INDICATOR_1, INDICATOR_2}


def test_known_disjoint_windows_are_no_common_point_not_unknown():
    observations = make_observations()
    first = make_indicator(
        INDICATOR_1,
        "2024-01-01T00:00:00Z",
        "2024-02-01T00:00:00Z",
    )
    second = make_indicator(
        INDICATOR_2,
        "2024-03-01T00:00:00Z",
        "2024-04-01T00:00:00Z",
    )

    result = local_conjunctive_query(
        PATTERN,
        [first, second],
        observations=observations,
    )

    assert result.status is ConjunctionStatus.NO_COMMON_POINT
    assert result.credible_common_point is False


def test_filter_contract_rejects_unknown_pattern_locally():
    indicator = make_indicator(
        INDICATOR_1,
        "2024-05-01T00:00:00Z",
        "2024-05-31T00:00:00Z",
    )

    with pytest.raises(ConjunctionContractError, match="exactly two indicators"):
        local_conjunctive_query(
            "[ipv4-addr:value = '203.0.113.9']",
            [indicator],
        )


def test_stix_20_version_selection_uses_legal_20_objects():
    first = {
        "type": "indicator",
        "id": INDICATOR_1,
        "created": "2024-05-01T00:00:00.000Z",
        "modified": "2024-05-01T00:00:00.000Z",
        "labels": ["malicious-activity"],
        "name": "same text A",
        "pattern": PATTERN,
        "valid_from": "2024-05-01T00:00:00Z",
        "valid_until": "2024-05-31T00:00:00Z",
    }
    second = dict(
        first,
        id=INDICATOR_2,
        valid_from="2024-05-10T00:00:00Z",
        valid_until="2024-05-25T00:00:00Z",
    )

    result = local_conjunctive_query(
        PATTERN,
        [first, second],
        version="2.0",
        observations=make_observations(),
    )

    assert result.spec_version == "2.0"
    assert result.matched_count == 2
    assert all(item.spec_version is None for item in result.indicators)
    assert result.status is ConjunctionStatus.ALL_LEGAL_TIMES_SUPPORT


def test_latest_version_selection_groups_same_stix_id():
    old = make_indicator(
        INDICATOR_1,
        "2024-05-01T00:00:00Z",
        "2024-05-10T00:00:00Z",
        modified="2024-05-02T00:00:00.000Z",
    )
    new = make_indicator(
        INDICATOR_1,
        "2024-05-10T00:00:00Z",
        "2024-05-31T00:00:00Z",
        modified="2024-05-03T00:00:00.000Z",
    )

    selected = select_object_versions([old, new], policy="latest")

    assert len(selected) == 1
    assert selected[0].modified == new.modified
