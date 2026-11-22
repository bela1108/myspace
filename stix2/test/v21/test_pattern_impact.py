"""
Tests for the time-qualifier impact comparison API.

These tests use a deliberately small synthetic event domain and enumerate it
directly, so the synthesized shortest witness can be checked against every
sequence that actually distinguishes the two patterns.
"""

import datetime
import itertools

import pytest
import pytz

from stix2.equivalence.pattern import (
    ImpactStatus, SyntheticEvent, UnsupportedImpactPattern,
    compare_pattern_impact, matches_event_sequence,
)
from stix2.utils import format_datetime

_UTC = pytz.utc
_ONE_US = datetime.timedelta(microseconds=1)
_ONE_SECOND = datetime.timedelta(seconds=1)

_COND_A = "a:b = 1"
_COND_B = "a:c = 2"

_PAT_A = "[a:b=1]"
_PAT_B = "[a:c=2]"


_BASE_TIME = datetime.datetime(2020, 1, 1, tzinfo=_UTC)


def _time(second, microsecond=0):
    return _BASE_TIME + datetime.timedelta(
        seconds=second, microseconds=microsecond,
    )


def _window_pattern(condition, start, stop):
    return "{} START t'{}' STOP t'{}'".format(
        condition, format_datetime(start), format_datetime(stop),
    )


def _event(timestamp, condition):
    return SyntheticEvent(timestamp, frozenset((condition,)))


def _enumerate_sequences(domain, length):
    for sequence in itertools.product(domain, repeat=length):
        if all(
            left.timestamp <= right.timestamp
            for left, right in zip(sequence, sequence[1:])
        ):
            yield sequence


def _matches(pattern, sequence):
    return matches_event_sequence(pattern, sequence, stix_version="2.1")


def _witness_key(sequence):
    return (
        len(sequence),
        sequence[-1].timestamp - sequence[0].timestamp,
        tuple(event.timestamp for event in sequence),
    )


def test_start_boundary_is_inclusive():
    start = _time(0)
    stop = _time(60)

    old = _window_pattern(_PAT_A, start, stop)
    new = _window_pattern(_PAT_A, start + _ONE_US, stop)

    result = compare_pattern_impact(old, new, stix_version="2.1")
    assert result.status is ImpactStatus.LOST_MATCHES

    witness = result.lost_match_witness
    assert len(witness) == 1
    assert witness[0].timestamp == start
    assert _matches(old, witness)
    assert not _matches(new, witness)

    # The first instant admitted by the new window is accepted by both.
    both = (_event(start + _ONE_US, _COND_A),)
    assert _matches(old, both)
    assert _matches(new, both)


def test_stop_boundary_is_inclusive():
    start = _time(0)
    stop = _time(60)

    old = _window_pattern(_PAT_A, start, stop)
    new = _window_pattern(_PAT_A, start, stop - _ONE_US)

    result = compare_pattern_impact(old, new, stix_version="2.1")
    assert result.status is ImpactStatus.LOST_MATCHES

    witness = result.lost_match_witness
    assert len(witness) == 1
    assert witness[0].timestamp == stop
    assert _matches(old, witness)
    assert not _matches(new, witness)

    # The last instant admitted by the new window is accepted by both.
    both = (_event(stop - _ONE_US, _COND_A),)
    assert _matches(old, both)
    assert _matches(new, both)


def test_degenerate_start_stop_at_same_instant():
    instant = _time(30)

    old = _window_pattern(_PAT_A, instant, instant)
    new = _window_pattern(
        _PAT_A, instant + _ONE_US, instant + _ONE_US,
    )

    result = compare_pattern_impact(old, new, stix_version="2.1")
    assert result.status is ImpactStatus.LOST_AND_GAINED_MATCHES

    assert len(result.lost_match_witness) == 1
    assert result.lost_match_witness[0].timestamp == instant
    assert _matches(old, result.lost_match_witness)
    assert not _matches(new, result.lost_match_witness)

    assert len(result.gained_match_witness) == 1
    assert result.gained_match_witness[0].timestamp == instant + _ONE_US
    assert _matches(new, result.gained_match_witness)
    assert not _matches(old, result.gained_match_witness)

    # The degenerate window really is a single instant, not an empty window.
    assert result.old_satisfiable is True
    assert result.new_satisfiable is True


def test_followedby_is_strict_at_the_same_instant():
    instant = _time(0)
    sequence = (
        _event(instant, _COND_A),
        _event(instant, _COND_B),
    )

    assert not _matches(
        "{} FOLLOWEDBY {}".format(_PAT_A, _PAT_B), sequence,
    )
    assert not _matches(
        "{} FOLLOWEDBY {}".format(_PAT_B, _PAT_A), sequence,
    )

    # A window with START == STOP is satisfiable for one observation, but
    # not for a strict FOLLOWEDBY pair, which needs two distinct instants.
    old = "({} FOLLOWEDBY {}) START t'{}' STOP t'{}'".format(
        _PAT_A, _PAT_B,
        format_datetime(instant), format_datetime(instant),
    )
    new = "({} FOLLOWEDBY {}) START t'{}' STOP t'{}'".format(
        _PAT_A, _PAT_B,
        format_datetime(instant),
        format_datetime(instant + _ONE_SECOND),
    )

    result = compare_pattern_impact(old, new, stix_version="2.1")
    assert result.old_satisfiable is False
    assert result.new_satisfiable is True
    assert result.status is ImpactStatus.GAINED_MATCHES


def test_within_boundary_is_inclusive():
    old = "({} FOLLOWEDBY {}) WITHIN 10 SECONDS".format(_PAT_A, _PAT_B)
    new = "({} FOLLOWEDBY {}) WITHIN 5 SECONDS".format(_PAT_A, _PAT_B)

    start = _time(0)

    # Exactly at the new WITHIN boundary: both still match.
    at_boundary = (
        _event(start, _COND_A),
        _event(start + 5 * _ONE_SECOND, _COND_B),
    )
    assert _matches(old, at_boundary)
    assert _matches(new, at_boundary)

    result = compare_pattern_impact(old, new, stix_version="2.1")
    assert result.status is ImpactStatus.LOST_MATCHES

    witness = result.lost_match_witness
    assert len(witness) == 2
    gap = witness[1].timestamp - witness[0].timestamp
    assert gap == 5 * _ONE_SECOND + _ONE_US
    assert _matches(old, witness)
    assert not _matches(new, witness)


def test_followedby_order_change_both_directions():
    old = "{} FOLLOWEDBY {}".format(_PAT_A, _PAT_B)
    new = "{} FOLLOWEDBY {}".format(_PAT_B, _PAT_A)

    result = compare_pattern_impact(old, new, stix_version="2.1")
    assert result.status is ImpactStatus.LOST_AND_GAINED_MATCHES

    lost = result.lost_match_witness
    gained = result.gained_match_witness
    assert len(lost) == 2
    assert len(gained) == 2

    assert lost[0].conditions == frozenset((_COND_A,))
    assert lost[1].conditions == frozenset((_COND_B,))
    assert lost[0].timestamp < lost[1].timestamp
    assert _matches(old, lost)
    assert not _matches(new, lost)

    assert gained[0].conditions == frozenset((_COND_B,))
    assert gained[1].conditions == frozenset((_COND_A,))
    assert gained[0].timestamp < gained[1].timestamp
    assert _matches(new, gained)
    assert not _matches(old, gained)


def test_unchanged_time_qualifiers():
    pattern = _window_pattern(_PAT_A, _time(0), _time(60))
    result = compare_pattern_impact(pattern, pattern, stix_version="2.1")

    assert result.status is ImpactStatus.UNCHANGED
    assert result.lost_match_witness is None
    assert result.gained_match_witness is None
    assert result.old_satisfiable is True
    assert result.new_satisfiable is True


def test_small_domain_enumeration_for_window_narrowing():
    start = _time(0)
    stop = _time(60)

    old = _window_pattern(_PAT_A, start, stop)
    new = _window_pattern(_PAT_A, start + _ONE_US, stop)

    domain = [
        _event(timestamp, _COND_A)
        for timestamp in (
            start - _ONE_US,
            start,
            start + _ONE_US,
            stop - _ONE_US,
            stop,
            stop + _ONE_US,
        )
    ]
    sequences = list(_enumerate_sequences(domain, 1))

    distinguishing = [
        sequence for sequence in sequences
        if _matches(old, sequence) and not _matches(new, sequence)
    ]
    assert distinguishing == [(_event(start, _COND_A),)]

    result = compare_pattern_impact(old, new, stix_version="2.1")
    assert result.lost_match_witness == distinguishing[0]


def test_small_domain_enumeration_for_within_narrowing():
    old = "({} FOLLOWEDBY {}) WITHIN 10 SECONDS".format(_PAT_A, _PAT_B)
    new = "({} FOLLOWEDBY {}) WITHIN 5 SECONDS".format(_PAT_A, _PAT_B)

    base = _time(0)
    timestamps = (
        base,
        base + _ONE_US,
        base + 5 * _ONE_SECOND - _ONE_US,
        base + 5 * _ONE_SECOND,
        base + 5 * _ONE_SECOND + _ONE_US,
        base + 10 * _ONE_SECOND,
        base + 10 * _ONE_SECOND + _ONE_US,
    )
    domain = [
        SyntheticEvent(timestamp, frozenset((condition,)))
        for timestamp in timestamps
        for condition in (_COND_A, _COND_B)
    ]

    sequences = list(_enumerate_sequences(domain, 1))
    sequences.extend(_enumerate_sequences(domain, 2))

    distinguishing = [
        sequence for sequence in sequences
        if _matches(old, sequence) and not _matches(new, sequence)
    ]
    assert distinguishing

    shortest_key = min(_witness_key(sequence) for sequence in distinguishing)
    assert shortest_key[0] == 2
    assert shortest_key[1] == 5 * _ONE_SECOND + _ONE_US

    result = compare_pattern_impact(old, new, stix_version="2.1")
    witness = result.lost_match_witness
    assert len(witness) == shortest_key[0]
    assert (
        witness[-1].timestamp - witness[0].timestamp
    ) == shortest_key[1]
    assert _matches(old, witness)
    assert not _matches(new, witness)


@pytest.mark.parametrize(
    "old_pattern, new_pattern, reason_fragment",
    [
        (
            "{} AND {}".format(_PAT_A, _PAT_B),
            _PAT_A,
            "AND/OR",
        ),
        (
            "{} REPEATS 2 TIMES".format(_PAT_A),
            _PAT_A,
            "REPEATS",
        ),
        (
            _PAT_A,
            "[a:b=2]",
            "Non-temporal bracket conditions changed",
        ),
        (
            "this is not a pattern",
            _PAT_A,
            "parsing failed",
        ),
    ],
)
def test_out_of_scope_patterns_go_to_manual_review(
    old_pattern, new_pattern, reason_fragment,
):
    result = compare_pattern_impact(
        old_pattern, new_pattern, stix_version="2.1",
    )

    assert result.status is ImpactStatus.MANUAL_REVIEW
    assert result.requires_manual_review is True
    assert reason_fragment in result.manual_review_reason
    assert result.lost_match_witness is None
    assert result.gained_match_witness is None


def test_matches_event_sequence_rejects_unsupported_syntax():
    sequence = (_event(_time(0), _COND_A),)

    with pytest.raises(UnsupportedImpactPattern):
        _matches("{} AND {}".format(_PAT_A, _PAT_B), sequence)


def test_matches_event_sequence_requires_time_order():
    sequence = (
        _event(_time(1), _COND_A),
        _event(_time(0), _COND_A),
    )

    with pytest.raises(ValueError):
        _matches(_PAT_A, sequence)
