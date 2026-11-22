"""Property tests for the archived measurement type contract.

The archive keeps one column whose Python runtime type is part of the data, not
just its value.  Equality alone is therefore too weak: ``0 == False == 0.0 ==
Decimal("0.00")`` and ``0.0 == -0.0``.  These tests check against an explicit,
business-owned contract instead of against cbor2 implementation details.
"""

from __future__ import annotations

import hashlib
import math
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal
from fractions import Fraction
from types import MappingProxyType
from typing import Any, Final
from uuid import UUID

import pytest
from hypothesis import find, given, settings
from hypothesis import strategies as st
from hypothesis.strategies import DrawFn

from cbor2 import dumps, loads

MAX_NESTING_DEPTH: Final[int] = 8
TARGET_FIELDS: Final[tuple[str, ...]] = ("recorded_at", "value", "payload")

# The contract is intentionally just "input type -> required decoded type".
# It does not mention CBOR major types, tags or encoder internals.
TYPE_CONTRACT: Final[Mapping[type, type]] = MappingProxyType(
    {
        bool: bool,
        int: int,
        float: float,
        Decimal: Decimal,
        Fraction: Fraction,
        str: str,
        bytes: bytes,
        date: date,
        datetime: datetime,
        UUID: UUID,
        type(None): type(None),
        list: list,
        dict: dict,
    }
)

# Fixed whole-minute and second-level offsets.  A positive sub-minute offset is
# covered separately as a known fidelity difference below.
SAFE_UTC_OFFSETS: Final[tuple[timedelta, ...]] = (
    timedelta(0),
    timedelta(minutes=1),
    timedelta(minutes=-1),
    timedelta(minutes=45),
    timedelta(minutes=-45),
    timedelta(hours=5, minutes=30),
    timedelta(hours=-8),
    timedelta(hours=14),
    timedelta(hours=-12),
    timedelta(seconds=90),
    timedelta(seconds=-90),
    timedelta(hours=1, seconds=1),
    timedelta(hours=-1, seconds=-1),
)
SAFE_TIMEZONES: Final[tuple[timezone, ...]] = tuple(
    timezone(offset) for offset in SAFE_UTC_OFFSETS
)

DETERMINISTIC_PROPERTY: Final = settings(
    derandomize=True,
    max_examples=60,
    database=None,
    deadline=None,
)

small_ints = st.integers(min_value=-(2**31), max_value=2**31)
finite_floats = st.one_of(
    st.floats(allow_nan=False, allow_infinity=False),
    st.just(0.0),
    st.just(-0.0),
)
finite_decimals = st.decimals(
    min_value="-1e6",
    max_value="1e6",
    allow_nan=False,
    allow_infinity=False,
)
finite_fractions = st.fractions(
    min_value=-(10**6),
    max_value=10**6,
    max_denominator=10**4,
)
numeric_values = st.one_of(
    st.booleans(),
    small_ints,
    finite_floats,
    finite_decimals,
    finite_fractions,
)

SENSOR_IDS: Final[tuple[str, ...]] = ("sensor-a", "sensor-b", "sensor-c")
UNITS: Final[tuple[str, ...]] = ("C", "kPa", "V", "%")
QUALITIES: Final[tuple[str, ...]] = ("good", "suspect", "bad")
EXTRA_FIELD_NAMES: Final[tuple[str, ...]] = (
    "batch_note",
    "calibration",
    "operator",
    "site",
)


@st.composite
def aware_datetimes(draw: DrawFn) -> datetime:
    value = draw(
        st.datetimes(
            min_value=datetime(1970, 1, 1),
            max_value=datetime(2038, 12, 31, 23, 59, 59, 999999),
        )
    )
    return value.replace(tzinfo=draw(st.sampled_from(SAFE_TIMEZONES)))


def _scalar_strategy() -> st.SearchStrategy[Any]:
    return st.one_of(
        st.none(),
        st.booleans(),
        small_ints,
        finite_floats,
        finite_decimals,
        finite_fractions,
        st.text(max_size=16),
        st.binary(max_size=16),
        aware_datetimes(),
        st.dates(),
        st.uuids(),
    )


finite_nested: st.SearchStrategy[Any] = st.recursive(
    _scalar_strategy(),
    lambda children: st.one_of(
        st.lists(children, max_size=3),
        st.dictionaries(st.text(max_size=8), children, max_size=3),
    ),
    max_leaves=5,
)


@st.composite
def measurement_records(draw: DrawFn) -> dict[str, Any]:
    record: dict[str, Any] = {
        "measurement_id": str(draw(st.uuids())),
        "sensor_id": draw(st.sampled_from(SENSOR_IDS)),
        "recorded_at": draw(aware_datetimes()),
        "value": draw(numeric_values),
        "unit": draw(st.sampled_from(UNITS)),
        "payload": draw(finite_nested),
    }
    if draw(st.booleans()):
        record["quality"] = draw(st.sampled_from(QUALITIES))
    if draw(st.booleans()):
        record["notes"] = draw(st.lists(st.text(max_size=12), max_size=3))
    if draw(st.booleans()):
        record["metadata"] = draw(st.dictionaries(st.text(max_size=8), finite_nested, max_size=3))
    return record


def nesting_depth(value: Any) -> int:
    if type(value) is list:
        return 1 + max((nesting_depth(item) for item in value), default=0)
    if type(value) is dict:
        return 1 + max((nesting_depth(item) for item in value.values()), default=0)
    return 0


def float_sign(value: float) -> int:
    return -1 if math.copysign(1.0, value) < 0 else 1


def roundtrip(value: Any) -> Any:
    """Encode/decode using the archive's offset-preserving, non-sorting defaults."""

    return loads(dumps(value, datetime_as_timestamp=False, canonical=False))


def assert_supported_original(value: Any, path: str, depth: int = 0) -> None:
    assert depth <= MAX_NESTING_DEPTH, f"{path}: nesting exceeds {MAX_NESTING_DEPTH}"
    value_type = type(value)
    if value_type is list:
        for index, item in enumerate(value):
            assert_supported_original(item, f"{path}[{index}]", depth + 1)
    elif value_type is dict:
        for key, item in value.items():
            assert type(key) is str, f"{path}: non-string key {key!r}"
            assert_supported_original(item, f"{path}[{key!r}]", depth + 1)
    else:
        assert value_type in TYPE_CONTRACT, (
            f"{path}: {value_type.__name__} is outside the archive type contract"
        )


def assert_valid_measurement(record: Mapping[str, Any]) -> None:
    for field in TARGET_FIELDS:
        assert field in record, f"missing measurement field {field!r}"
    recorded_at = record["recorded_at"]
    assert type(recorded_at) is datetime, "recorded_at must be a datetime"
    assert recorded_at.tzinfo is not None, "recorded_at must carry a UTC offset"
    assert recorded_at.utcoffset() is not None
    for key, value in record.items():
        assert type(key) is str
        assert_supported_original(value, f"record[{key!r}]")


def assert_type_contract(
    original: Any,
    decoded: Any,
    path: str = "$",
    depth: int = 0,
) -> None:
    assert depth <= MAX_NESTING_DEPTH, f"{path}: nesting exceeds {MAX_NESTING_DEPTH}"
    original_type = type(original)
    expected_type = TYPE_CONTRACT.get(original_type)
    assert expected_type is not None, (
        f"{path}: {original_type.__name__} is outside the archive type contract"
    )
    assert type(decoded) is expected_type, (
        f"{path}: type fidelity lost: expected {expected_type.__name__}, "
        f"got {type(decoded).__name__} for {original!r}"
    )

    if original_type is list:
        assert len(decoded) == len(original), f"{path}: list length changed"
        for index, (original_item, decoded_item) in enumerate(zip(original, decoded, strict=True)):
            assert_type_contract(original_item, decoded_item, f"{path}[{index}]", depth + 1)
    elif original_type is dict:
        assert set(decoded) == set(original), f"{path}: map keys changed"
        for key, original_item in original.items():
            assert_type_contract(original_item, decoded[key], f"{path}[{key!r}]", depth + 1)
    elif original_type is bool:
        assert decoded is original, f"{path}: boolean identity changed"
    elif original_type is int:
        assert decoded == original, f"{path}: integer value changed"
    elif original_type is float:
        assert math.isfinite(original)
        assert decoded == original, f"{path}: float value changed"
        assert float_sign(decoded) == float_sign(original), (
            f"{path}: float sign changed ({float_sign(original)} -> {float_sign(decoded)})"
        )
    elif original_type is Decimal:
        assert decoded.is_finite(), f"{path}: decimal became non-finite"
        if original.is_zero():
            assert decoded.is_zero(), f"{path}: decimal zero changed"
            assert decoded.as_tuple().exponent == original.as_tuple().exponent, (
                f"{path}: decimal zero exponent changed"
            )
        else:
            assert decoded.as_tuple() == original.as_tuple(), (
                f"{path}: decimal value or precision changed"
            )
    elif original_type is Fraction:
        assert decoded == original, f"{path}: rational value changed"
    elif original_type is datetime:
        assert original.tzinfo is not None
        assert decoded.tzinfo is not None, f"{path}: timezone was dropped"
        assert decoded.utcoffset() == original.utcoffset(), (
            f"{path}: UTC offset changed ({original.utcoffset()} -> {decoded.utcoffset()})"
        )
        assert decoded == original, f"{path}: instant changed"
    elif original_type is date:
        assert decoded == original, f"{path}: date value changed"
    else:
        assert decoded == original, f"{path}: value changed"


def assert_target_contract(original: Mapping[str, Any], decoded: Mapping[str, Any]) -> None:
    assert type(decoded) is dict
    for field in TARGET_FIELDS:
        assert field in decoded, f"decoded record lost target field {field!r}"
        assert_type_contract(original[field], decoded[field], f"$.{field}")
    assert nesting_depth(decoded["payload"]) == nesting_depth(original["payload"]), (
        "target payload nesting depth changed"
    )
    assert nesting_depth(decoded) <= MAX_NESTING_DEPTH


@st.composite
def reordered_measurement_cases(
    draw: DrawFn,
) -> tuple[dict[str, Any], dict[str, Any], list[str]]:
    record = draw(measurement_records())
    keys = list(record)
    shift = draw(st.integers(min_value=0, max_value=len(keys) - 1))
    order = keys[shift:] + keys[:shift]
    return record, {key: record[key] for key in order}, order


@st.composite
def unrelated_measurement_cases(
    draw: DrawFn,
) -> tuple[dict[str, Any], dict[str, Any], int]:
    target = draw(measurement_records())
    extra_fields = draw(
        st.dictionaries(st.sampled_from(EXTRA_FIELD_NAMES), finite_nested, max_size=2)
    )
    target_with_extras = {**target, **extra_fields}
    unrelated = draw(st.lists(measurement_records(), max_size=3))
    insert_at = draw(st.integers(min_value=0, max_value=len(unrelated)))
    measurements = [
        *unrelated[:insert_at],
        target_with_extras,
        *unrelated[insert_at:],
    ]
    envelope = {
        "batch_id": str(draw(st.uuids())),
        "measurements": measurements,
        "unrelated": draw(finite_nested),
    }
    return target, envelope, insert_at


@st.composite
def equal_value_alias_pairs(draw: DrawFn) -> tuple[int, Any, str]:
    """Draw two values that are equal but have deliberately different types.

    Both sides are derived from the same base value.  When Hypothesis shrinks
    the example, it shrinks that shared base instead of rewriting one side of
    the equality/type relation independently.
    """

    base = draw(st.integers(min_value=0, max_value=1))
    kind = draw(st.sampled_from(("bool", "float", "decimal", "fraction")))
    if kind == "bool":
        alias: Any = bool(base)
    elif kind == "float":
        alias = float(base)
    elif kind == "decimal":
        alias = Decimal(base)
    else:
        alias = Fraction(base, 1)
    return base, alias, kind


def minimal_measurement(record: Mapping[str, Any]) -> dict[str, Any]:
    """Drop optional fields and sibling measurements, keeping the typed target."""

    return {field: record[field] for field in TARGET_FIELDS}


def _sample_record() -> dict[str, Any]:
    return {
        "measurement_id": "m-0001",
        "sensor_id": "sensor-a",
        "recorded_at": datetime(
            2024,
            6,
            1,
            12,
            30,
            15,
            250000,
            tzinfo=timezone(timedelta(hours=5, minutes=30)),
        ),
        "value": -0.0,
        "unit": "C",
        "payload": {
            "samples": [0, False, Decimal("1.50"), Fraction(1, 3)],
            "nested": {"depth": [1, [2, -0.0]]},
        },
        "quality": "good",
    }


@given(measurement_records())
@DETERMINISTIC_PROPERTY
def test_measurement_record_preserves_type_contract(record: dict[str, Any]) -> None:
    assert_valid_measurement(record)
    decoded = roundtrip(record)
    assert type(decoded) is dict
    assert_target_contract(record, decoded)


@given(reordered_measurement_cases())
@DETERMINISTIC_PROPERTY
def test_type_contract_survives_commutative_field_reordering(
    case: tuple[dict[str, Any], dict[str, Any], list[str]],
) -> None:
    original, reordered, order = case
    assert list(reordered) == order
    decoded = roundtrip(reordered)
    assert list(decoded) == order
    assert_target_contract(original, decoded)


@given(unrelated_measurement_cases())
@DETERMINISTIC_PROPERTY
def test_type_contract_survives_unrelated_measurements(
    case: tuple[dict[str, Any], dict[str, Any], int],
) -> None:
    target, envelope, insert_at = case
    decoded = roundtrip(envelope)
    assert type(decoded) is dict
    measurements = decoded["measurements"]
    assert type(measurements) is list
    assert len(measurements) == len(envelope["measurements"])
    target_decoded = measurements[insert_at]
    assert type(target_decoded) is dict
    assert_target_contract(target, target_decoded)


@given(measurement_records())
@DETERMINISTIC_PROPERTY
def test_shrinking_to_target_fields_keeps_the_typed_witness(
    record: dict[str, Any],
) -> None:
    assert_valid_measurement(record)
    minimal = minimal_measurement(record)
    assert list(minimal) == list(TARGET_FIELDS)
    for field in TARGET_FIELDS:
        assert minimal[field] is record[field]
    decoded = roundtrip(minimal)
    assert_target_contract(minimal, decoded)


@given(equal_value_alias_pairs())
@DETERMINISTIC_PROPERTY
def test_equal_alias_pairs_are_distinguished_after_roundtrip(
    pair: tuple[int, Any, str],
) -> None:
    left, right, _kind = pair
    assert left == right
    assert type(left) is not type(right)
    decoded_left = roundtrip(left)
    decoded_right = roundtrip(right)
    assert decoded_left == decoded_right
    assert type(decoded_left) is not type(decoded_right)


def test_hypothesis_shrinking_keeps_the_alias_relation() -> None:
    left, right, kind = find(
        equal_value_alias_pairs(),
        lambda pair: type(pair[0]) is not type(pair[1]),
        settings=DETERMINISTIC_PROPERTY,
    )
    assert left == right, "shrinking removed the equality that makes the witness interesting"
    assert type(left) is not type(right), "shrinking removed the type difference"
    assert kind in ("bool", "float", "decimal", "fraction")


def test_fixed_field_order_variants_do_not_change_the_target() -> None:
    record = _sample_record()
    orders = (
        list(record),
        list(reversed(record)),
        sorted(record),
    )
    for order in orders:
        reordered = {key: record[key] for key in order}
        decoded = roundtrip(reordered)
        assert list(decoded) == order
        assert_target_contract(record, decoded)


@pytest.mark.xfail(
    strict=True,
    reason=(
        "known fidelity difference: cbor2 replaces '+00:00' inside a positive "
        "sub-minute UTC offset with 'Z', producing an undecodable 'Z:01' suffix"
    ),
)
def test_positive_subminute_timezone_offset_is_preserved() -> None:
    original = datetime(
        2024,
        1,
        2,
        3,
        4,
        5,
        123456,
        tzinfo=timezone(timedelta(seconds=1)),
    )
    decoded = roundtrip(original)
    assert decoded.utcoffset() == original.utcoffset()


@dataclass(frozen=True)
class NormalTypeCombination:
    slug: str
    description: str
    left: Any
    right: Any
    distinction: str


UTC_DATETIME = datetime(2020, 1, 1, 0, 0, tzinfo=timezone.utc)
EST_DATETIME = datetime(2019, 12, 31, 19, 0, tzinfo=timezone(timedelta(hours=-5)))

NORMAL_TYPE_COMBINATIONS: Final[tuple[NormalTypeCombination, ...]] = (
    NormalTypeCombination(
        "int-vs-bool-zero",
        "int(0) vs bool(False)",
        0,
        False,
        "runtime-type",
    ),
    NormalTypeCombination(
        "int-vs-bool-one",
        "int(1) vs bool(True)",
        1,
        True,
        "runtime-type",
    ),
    NormalTypeCombination(
        "int-vs-float",
        "int(0) vs float(0.0)",
        0,
        0.0,
        "runtime-type",
    ),
    NormalTypeCombination(
        "int-vs-decimal",
        "int(0) vs Decimal('0.00')",
        0,
        Decimal("0.00"),
        "runtime-type",
    ),
    NormalTypeCombination(
        "int-vs-fraction",
        "int(1) vs Fraction(1, 1)",
        1,
        Fraction(1, 1),
        "runtime-type",
    ),
    NormalTypeCombination(
        "decimal-vs-int",
        "Decimal('1.0') vs int(1)",
        Decimal("1.0"),
        1,
        "runtime-type",
    ),
    NormalTypeCombination(
        "float-sign",
        "float(0.0) vs float(-0.0)",
        0.0,
        -0.0,
        "float-sign",
    ),
    NormalTypeCombination(
        "datetime-offset",
        "datetime(+00:00) vs datetime(-05:00)",
        UTC_DATETIME,
        EST_DATETIME,
        "time-offset",
    ),
)


@dataclass(frozen=True)
class SavedFidelitySeed:
    """A persisted seed and the normal type combination it is known to select."""

    seed: int
    expected_slug: str


# Saved seeds.  Re-running the same seed always selects the same normal type
# combination, so a reported fidelity difference can be reproduced verbatim.
# The set deliberately covers every combination in NORMAL_TYPE_COMBINATIONS.
SAVED_FIDELITY_SEEDS: Final[tuple[SavedFidelitySeed, ...]] = (
    SavedFidelitySeed(20260006, "int-vs-bool-zero"),
    SavedFidelitySeed(20260001, "int-vs-bool-one"),
    SavedFidelitySeed(20260004, "int-vs-float"),
    SavedFidelitySeed(20260010, "int-vs-decimal"),
    SavedFidelitySeed(20260007, "int-vs-fraction"),
    SavedFidelitySeed(20260000, "decimal-vs-int"),
    SavedFidelitySeed(20260014, "float-sign"),
    SavedFidelitySeed(20260002, "datetime-offset"),
)


def combination_index_for_seed(seed: int) -> int:
    digest = hashlib.sha256(str(seed).encode("ascii")).digest()
    return int.from_bytes(digest[:8], "big") % len(NORMAL_TYPE_COMBINATIONS)


def combination_for_seed(seed: int) -> NormalTypeCombination:
    return NORMAL_TYPE_COMBINATIONS[combination_index_for_seed(seed)]


def saved_seed_id(saved: SavedFidelitySeed) -> str:
    return f"seed-{saved.seed}-{saved.expected_slug}"


def test_saved_seeds_cover_every_normal_type_combination() -> None:
    selected = {combination_for_seed(saved.seed).slug for saved in SAVED_FIDELITY_SEEDS}
    expected = {combination.slug for combination in NORMAL_TYPE_COMBINATIONS}
    assert selected == expected


@pytest.mark.parametrize("saved", SAVED_FIDELITY_SEEDS, ids=saved_seed_id)
def test_saved_seed_replays_the_fidelity_difference(saved: SavedFidelitySeed) -> None:
    combination = combination_for_seed(saved.seed)
    assert combination.slug == saved.expected_slug, (
        f"seed {saved.seed} now selects {combination.slug!r}; "
        f"the saved replay expected {saved.expected_slug!r}"
    )
    assert combination.left == combination.right, (
        f"{combination.description}: values are not equality aliases"
    )

    decoded_left = roundtrip(combination.left)
    decoded_right = roundtrip(combination.right)
    assert type(decoded_left) is type(combination.left), (
        f"{combination.description}: left runtime type was not preserved"
    )
    assert type(decoded_right) is type(combination.right), (
        f"{combination.description}: right runtime type was not preserved"
    )

    if combination.distinction == "runtime-type":
        assert decoded_left == decoded_right
        assert type(decoded_left) is not type(decoded_right), (
            f"{combination.description}: equality-only checks still cannot "
            "distinguish these values"
        )
    elif combination.distinction == "float-sign":
        assert type(decoded_left) is float
        assert type(decoded_right) is float
        assert float_sign(decoded_left) != float_sign(decoded_right), (
            f"{combination.description}: float sign was not preserved"
        )
    elif combination.distinction == "time-offset":
        assert type(decoded_left) is datetime
        assert type(decoded_right) is datetime
        assert decoded_left == decoded_right
        assert decoded_left.utcoffset() != decoded_right.utcoffset(), (
            f"{combination.description}: UTC offset was not preserved"
        )
    else:
        pytest.fail(f"unknown fidelity distinction {combination.distinction!r}")
