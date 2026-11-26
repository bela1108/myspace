#!/usr/bin/env python
"""Acceptance demo for a local STIX temporal conjunction query.

Run from the repository root with::

    python examples/temporal_conjunction_query.py
"""

import json

import stix2
from stix2.temporal_conjunction import evidence_from_stix, local_conjunctive_query


PATTERN = "[ipv4-addr:value = '198.51.100.7']"
INDICATOR_1 = "indicator--11111111-1111-4111-8111-111111111111"
INDICATOR_2 = "indicator--22222222-2222-4222-8222-222222222222"
OBSERVATION_MINUTE = "observed-data--33333333-3333-4333-8333-333333333333"
OBSERVATION_WEEK = "observed-data--44444444-4444-4444-8444-444444444444"


def build_indicators():
    common = {
        "created": "2024-05-01T00:00:00.000Z",
        "indicator_types": ["malicious-activity"],
        "pattern": PATTERN,
        "pattern_type": "stix",
    }
    return [
        stix2.v21.Indicator(
            id=INDICATOR_1,
            modified="2024-05-01T00:00:00.000Z",
            valid_from="2024-05-01T00:00:00Z",
            valid_until="2024-05-31T00:00:00Z",
            **common,
        ),
        stix2.v21.Indicator(
            id=INDICATOR_2,
            modified="2024-05-10T00:00:00.000Z",
            valid_from="2024-05-15T00:00:00Z",
            valid_until="2024-05-16T12:00:00Z",
            **common,
        ),
    ]


def build_observations():
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


def main():
    result = local_conjunctive_query(
        PATTERN,
        build_indicators(),
        observations=build_observations(),
        spec_version="2.1",
    )
    report = {
        "status": result.status.value,
        "status_zh": result.to_dict()["status_zh"],
        "version_selection": result.spec_version,
        "filter_contract": result.to_dict()["filter_contract"],
        "credible_common_point": result.credible_common_point,
        "all_legal_times_support": result.all_legal_times_support,
        "common_boundaries": result.to_dict()["common_boundaries"],
        "truncated_boundaries": result.truncated_boundaries,
        "observations_needing_time": result.observations_needing_time,
        "refinement_requests": result.refinement_requests,
    }
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
