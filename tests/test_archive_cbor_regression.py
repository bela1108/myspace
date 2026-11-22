"""Regression tests for an archive service moving to canonical CBOR encoding.

The archive service must not use encoded bytes as its notion of evidence identity.
Normal CBOR preserves mapping insertion order, so two semantically identical records
can have different bytes.  These tests compare the *audit view* instead: every source
path and its type-tagged visible value after a normal or canonical round-trip.

The generated corpus is deliberately small.  Replay a single deterministic corpus with
one seed:

    ARCHIVE_CBOR_SEED=20261121 pytest tests/test_archive_cbor_regression.py

All inputs are synthetic records defined in this module.
"""

from __future__ import annotations

import math
import os
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
from decimal import Decimal
from typing import Any, Literal, TypeAlias

from hypothesis import given, seed, settings
from hypothesis import strategies as st
from hypothesis.strategies import DrawFn

from cbor2 import CBORSimpleValue, dumps, loads

REPLAY_SEED = int(os.environ.get("ARCHIVE_CBOR_SEED", "20261121"))
MAX_EXAMPLES = 16
MAX_EVIDENCE_ITEMS = 2
MAX_CUSTODY_EVENTS = 2
MAX_TEXT_LEN = 8
MAX_BYTES_LEN = 8

INDEX = "*"
PathSegment: TypeAlias = str | int
Path: TypeAlias = tuple[PathSegment, ...]
ContainerKind: TypeAlias = Literal["map", "list", "scalar"]
ArchiveRecord: TypeAlias = dict[str, Any]
AuditProjection: TypeAlias = dict[Path, "AuditEntry"]


@dataclass(frozen=True)
class AuditEntry:
    """What the audit layer can see for one source path."""

    kind: ContainerKind
    visible: object


# These declarations are the contract with the archive format.  Map paths are
# unordered; list paths are ordered and their order is part of the evidence identity.
UNORDERED_MAP_PATHS: frozenset[Path] = frozenset(
    {
        (),
        ("manifest",),
        ("evidence", INDEX),
        ("evidence", INDEX, "integrity"),
        ("evidence", INDEX, "custody", INDEX),
        ("labels",),
    }
)
ORDERED_LIST_PATHS: frozenset[Path] = frozenset(
    {
        ("evidence",),
        ("evidence", INDEX, "custody"),
    }
)
SCALAR_PATHS: frozenset[Path] = frozenset(
    {
        ("format",),
        ("manifest", "case_id"),
        ("manifest", "sealed"),
        ("manifest", "revision"),
        ("manifest", "digest"),
        ("evidence", INDEX, "evidence_id"),
        ("evidence", INDEX, "media_type"),
        ("evidence", INDEX, "payload"),
        ("evidence", INDEX, "integrity", "algorithm"),
        ("evidence", INDEX, "integrity", "digest"),
        ("evidence", INDEX, "integrity", "negative_zero"),
        ("evidence", INDEX, "integrity", "positive_zero"),
        ("evidence", INDEX, "integrity", "zero_int"),
        ("evidence", INDEX, "integrity", "zero_bool"),
        ("evidence", INDEX, "integrity", "one_int"),
        ("evidence", INDEX, "integrity", "one_bool"),
        ("evidence", INDEX, "integrity", "one_float"),
        ("evidence", INDEX, "integrity", "one_text"),
        ("evidence", INDEX, "integrity", "one_bytes"),
        ("evidence", INDEX, "integrity", "one_simple"),
        ("evidence", INDEX, "integrity", "one_decimal"),
        ("evidence", INDEX, "custody", INDEX, "event_id"),
        ("evidence", INDEX, "custody", INDEX, "action"),
        ("evidence", INDEX, "custody", INDEX, "offset_s"),
        ("labels", "priority"),
        ("labels", "retention_days"),
        ("labels", "reviewed"),
        ("labels", "checksum"),
    }
)
ARCHIVE_SCHEMA: dict[Path, ContainerKind] = {
    **{path: "map" for path in UNORDERED_MAP_PATHS},
    **{path: "list" for path in ORDERED_LIST_PATHS},
    **{path: "scalar" for path in SCALAR_PATHS},
}

TEXT_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"
MEDIA_TYPES = ("image/png", "application/pdf", "text/plain", "video/mp4")
CUSTODY_ACTIONS = ("sealed", "transferred", "opened", "verified")
PRIORITIES = ("low", "normal", "high")


def normalize_path(path: Path) -> Path:
    return tuple(INDEX if isinstance(segment, int) else segment for segment in path)


def format_path(path: Path) -> str:
    text = "archive"
    for segment in path:
        if isinstance(segment, int):
            text += f"[{segment}]"
        else:
            text += f".{segment}"
    return text


def schema_kind(path: Path) -> ContainerKind:
    kind = ARCHIVE_SCHEMA.get(normalize_path(path))
    assert kind is not None, f"{format_path(path)} is not declared in ARCHIVE_SCHEMA"
    return kind


def typed_visible(value: object) -> tuple[str, object]:
    """Type-tag a visible value so Python's cross-type equality cannot hide a change.

    In particular, ``0 == False``, ``1 == True``, ``1 == 1.0``,
    ``Decimal("1") == 1`` and ``CBORSimpleValue(1) == 1`` are all true, and
    ``-0.0 == 0.0``.  The audit layer must compare business identity, not just ``==``.
    """

    if isinstance(value, CBORSimpleValue):
        return ("simple", value.value)
    if isinstance(value, bool):
        return ("bool", value)
    if isinstance(value, int):
        return ("int", value)
    if isinstance(value, float):
        return ("float", value.hex())
    if isinstance(value, str):
        return ("text", value)
    if isinstance(value, bytes):
        return ("bytes", value.hex())
    if isinstance(value, Decimal):
        return ("decimal", str(value))
    if value is None:
        return ("null", None)

    raise AssertionError(f"unexpected archive value type: {type(value).__name__}")


def audit(value: object, path: Path = ()) -> AuditProjection:
    """Project a decoded archive to source paths and type-tagged visible values."""

    entries: AuditProjection = {}
    _audit_into(value, path, entries)
    return entries


def _audit_into(value: object, path: Path, entries: AuditProjection) -> None:
    kind = schema_kind(path)
    if isinstance(value, Mapping):
        assert kind == "map", (
            f"{format_path(path)} is declared {kind}, but the archive contains a mapping"
        )
        assert all(isinstance(key, str) for key in value), (
            f"{format_path(path)} contains a non-text field name; source paths would be ambiguous"
        )
        entries[path] = AuditEntry("map", ("map", frozenset(value)))
        for key, child in value.items():
            assert isinstance(key, str)
            _audit_into(child, path + (key,), entries)
    elif isinstance(value, list):
        assert kind == "list", (
            f"{format_path(path)} is declared {kind}, but the archive contains a list"
        )
        entries[path] = AuditEntry("list", ("list", len(value)))
        for index, child in enumerate(value):
            _audit_into(child, path + (index,), entries)
    else:
        assert kind == "scalar", (
            f"{format_path(path)} is declared {kind}, but the archive contains a scalar"
        )
        entries[path] = AuditEntry("scalar", typed_visible(value))


def _path_sort_key(path: Path) -> tuple[str, ...]:
    return tuple(f"{type(segment).__name__}:{segment}" for segment in path)


def audit_diff(expected: AuditProjection, actual: AuditProjection) -> list[str]:
    differences: list[str] = []
    for path in sorted(expected.keys() | actual.keys(), key=_path_sort_key):
        if path not in expected:
            differences.append(
                f"{format_path(path)}: decoder produced a path absent from the source archive"
            )
        elif path not in actual:
            differences.append(
                f"{format_path(path)}: source path missing after the round-trip"
            )
        elif expected[path] != actual[path]:
            differences.append(
                f"{format_path(path)}: expected {expected[path].kind} "
                f"{expected[path].visible!r}, got {actual[path].kind} "
                f"{actual[path].visible!r}"
            )

    return differences


def iter_container_paths(
    value: object, path: Path = ()
) -> Iterator[tuple[ContainerKind, Path]]:
    if isinstance(value, Mapping):
        yield "map", path
        for key, child in value.items():
            assert isinstance(key, str)
            yield from iter_container_paths(child, path + (key,))
    elif isinstance(value, list):
        yield "list", path
        for index, child in enumerate(value):
            yield from iter_container_paths(child, path + (index,))


def get_at_path(value: object, path: Path) -> object:
    current = value
    for segment in path:
        if isinstance(segment, int):
            assert isinstance(current, list)
            current = current[segment]
        else:
            assert isinstance(current, Mapping)
            current = current[segment]

    return current


def replace_at_path(
    value: object,
    target: Path,
    transform: Callable[[object], object],
    path: Path = (),
) -> object:
    if path == target:
        return transform(value)

    if isinstance(value, Mapping):
        result: dict[str, object] = {}
        for key, child in value.items():
            assert isinstance(key, str)
            result[key] = replace_at_path(child, target, transform, path + (key,))
        return result

    if isinstance(value, list):
        return [
            replace_at_path(child, target, transform, path + (index,))
            for index, child in enumerate(value)
        ]

    return value


def _reverse_mapping(value: object) -> object:
    assert isinstance(value, Mapping)
    assert all(isinstance(key, str) for key in value)
    return {key: value[key] for key in reversed(list(value))}


def _reverse_list(value: object) -> object:
    assert isinstance(value, list)
    return list(reversed(value))


def _identity_key(items: list[object]) -> str:
    assert items, "ordered lists in the archive must not be empty"
    first = items[0]
    assert isinstance(first, Mapping)
    if "evidence_id" in first:
        return "evidence_id"
    assert "event_id" in first
    return "event_id"


def _ids(items: list[object], key: str) -> list[object]:
    identifiers: list[object] = []
    for item in items:
        assert isinstance(item, Mapping)
        identifiers.append(item[key])
    return identifiers


def _integrity_map() -> dict[str, object]:
    return {
        "algorithm": "sha256",
        "digest": b"",
        "negative_zero": -0.0,
        "positive_zero": 0.0,
        "zero_int": 0,
        "zero_bool": False,
        "one_int": 1,
        "one_bool": True,
        "one_float": 1.0,
        "one_text": "1",
        "one_bytes": b"1",
        "one_simple": CBORSimpleValue(1),
        "one_decimal": Decimal("1"),
    }


def _make_evidence(
    evidence_index: int,
    suffix: str,
    media_type: str,
    payload: bytes,
    digest: bytes,
    custody: list[dict[str, object]],
) -> dict[str, object]:
    integrity = _integrity_map()
    integrity["digest"] = digest
    return {
        "evidence_id": f"E-{evidence_index:02d}-{suffix}",
        "media_type": media_type,
        "payload": payload,
        "integrity": integrity,
        "custody": custody,
    }


@st.composite
def archive_strategy(draw: DrawFn) -> ArchiveRecord:
    """Generate a bounded synthetic evidence archive."""

    evidence_count = draw(st.integers(min_value=2, max_value=MAX_EVIDENCE_ITEMS))
    evidence: list[dict[str, object]] = []
    for evidence_index in range(evidence_count):
        custody_count = draw(st.integers(min_value=2, max_value=MAX_CUSTODY_EVENTS))
        custody: list[dict[str, object]] = []
        for event_index in range(custody_count):
            event_suffix = draw(st.text(alphabet=TEXT_ALPHABET, max_size=MAX_TEXT_LEN))
            custody.append(
                {
                    "event_id": f"C-{evidence_index:02d}-{event_index:02d}-{event_suffix}",
                    "action": draw(st.sampled_from(CUSTODY_ACTIONS)),
                    "offset_s": draw(st.integers(min_value=0, max_value=86400)),
                }
            )

        suffix = draw(st.text(alphabet=TEXT_ALPHABET, max_size=MAX_TEXT_LEN))
        evidence.append(
            _make_evidence(
                evidence_index,
                suffix,
                draw(st.sampled_from(MEDIA_TYPES)),
                draw(st.binary(max_size=MAX_BYTES_LEN)),
                draw(st.binary(min_size=1, max_size=MAX_BYTES_LEN)),
                custody,
            )
        )

    return {
        "format": "evidence-archive/1",
        "manifest": {
            "case_id": f"CASE-{draw(st.text(alphabet=TEXT_ALPHABET, max_size=MAX_TEXT_LEN))}",
            "sealed": draw(st.booleans()),
            "revision": draw(st.integers(min_value=1, max_value=9999)),
            "digest": draw(st.binary(min_size=1, max_size=MAX_BYTES_LEN)),
        },
        "evidence": evidence,
        "labels": {
            "priority": draw(st.sampled_from(PRIORITIES)),
            "retention_days": draw(st.integers(min_value=1, max_value=3650)),
            "reviewed": draw(st.booleans()),
            "checksum": draw(st.binary(min_size=1, max_size=MAX_BYTES_LEN)),
        },
    }


def test_archive_schema_declares_map_and_list_order() -> None:
    assert UNORDERED_MAP_PATHS.isdisjoint(ORDERED_LIST_PATHS)
    assert UNORDERED_MAP_PATHS.isdisjoint(SCALAR_PATHS)
    assert ORDERED_LIST_PATHS.isdisjoint(SCALAR_PATHS)
    assert set(ARCHIVE_SCHEMA) == UNORDERED_MAP_PATHS | ORDERED_LIST_PATHS | SCALAR_PATHS

    # Explicitly pin the paths whose order matters to the archive service.
    assert ("manifest",) in UNORDERED_MAP_PATHS
    assert ("evidence", INDEX, "integrity") in UNORDERED_MAP_PATHS
    assert ("evidence", INDEX, "custody", INDEX) in UNORDERED_MAP_PATHS
    assert ("labels",) in UNORDERED_MAP_PATHS
    assert ("evidence",) in ORDERED_LIST_PATHS
    assert ("evidence", INDEX, "custody") in ORDERED_LIST_PATHS


@settings(max_examples=MAX_EXAMPLES, deadline=None)
@seed(REPLAY_SEED)
@given(archive_strategy())
def test_generated_archive_uses_only_declared_paths(archive: ArchiveRecord) -> None:
    assert 2 <= len(archive["evidence"]) <= MAX_EVIDENCE_ITEMS
    for item in archive["evidence"]:
        assert 2 <= len(item["custody"]) <= MAX_CUSTODY_EVENTS
        assert len(item["payload"]) <= MAX_BYTES_LEN

    projection = audit(archive)
    visited = {normalize_path(path) for path in projection}
    missing = set(ARCHIVE_SCHEMA) - visited
    assert not missing, (
        "the bounded generator never exercised these declared archive paths: "
        + ", ".join(format_path(path) for path in sorted(missing, key=_path_sort_key))
    )


@settings(max_examples=MAX_EXAMPLES, deadline=None)
@seed(REPLAY_SEED)
@given(archive_strategy())
def test_normal_and_canonical_roundtrips_reach_the_same_audit_view(
    archive: ArchiveRecord,
) -> None:
    source = audit(archive)
    normal = audit(loads(dumps(archive)))
    canonical = audit(loads(dumps(archive, canonical=True)))

    normal_diff = audit_diff(source, normal)
    assert not normal_diff, "normal round-trip changed archive fields:\n" + "\n".join(
        normal_diff
    )

    canonical_diff = audit_diff(normal, canonical)
    assert not canonical_diff, (
        "canonical round-trip changed archive fields:\n" + "\n".join(canonical_diff)
    )

    assert normal.keys() == canonical.keys(), (
        "normal and canonical round-trips exposed different source paths"
    )
    assert dumps(archive) != dumps(archive, canonical=True), (
        "the fixture must actually distinguish normal and canonical wire encodings"
    )


@settings(max_examples=MAX_EXAMPLES, deadline=None)
@seed(REPLAY_SEED)
@given(archive_strategy())
def test_unordered_map_write_order_is_not_evidence_identity(
    archive: ArchiveRecord,
) -> None:
    source = audit(archive)
    canonical_bytes = dumps(archive, canonical=True)
    map_paths = [path for kind, path in iter_container_paths(archive) if kind == "map"]
    assert () in map_paths

    for map_path in map_paths:
        variant = replace_at_path(archive, map_path, _reverse_mapping)
        variant_map = get_at_path(archive, map_path)
        assert isinstance(variant_map, Mapping)

        variant_view = audit(variant)
        differences = audit_diff(source, variant_view)
        assert not differences, (
            f"{format_path(map_path)} is declared unordered, but reversing its field write "
            "order changed the audit view:\n" + "\n".join(differences)
        )

        assert dumps(variant, canonical=True) == canonical_bytes, (
            f"{format_path(map_path)} is declared unordered, but canonical encoding changed "
            "when its fields were written in reverse order"
        )

        if len(variant_map) > 1:
            assert dumps(variant) != dumps(archive), (
                f"{format_path(map_path)} has multiple fields, so normal encoding should "
                "change with field write order; direct byte comparison would false-positive"
            )


@settings(max_examples=MAX_EXAMPLES, deadline=None)
@seed(REPLAY_SEED)
@given(archive_strategy())
def test_ordered_list_order_is_business_significant(archive: ArchiveRecord) -> None:
    source = audit(archive)
    canonical_bytes = dumps(archive, canonical=True)
    list_paths = [path for kind, path in iter_container_paths(archive) if kind == "list"]
    assert ("evidence",) in list_paths
    assert ("evidence", 0, "custody") in list_paths

    for list_path in list_paths:
        items = get_at_path(archive, list_path)
        assert isinstance(items, list)
        assert len(items) >= 2
        id_key = _identity_key(items)
        original_ids = _ids(items, id_key)

        variant = replace_at_path(archive, list_path, _reverse_list)
        differences = audit_diff(source, audit(variant))
        assert differences, (
            f"{format_path(list_path)} is declared ordered, but reversing it left the "
            "audit view unchanged"
        )
        first_path = differences[0].split(":", 1)[0]
        assert first_path.startswith(format_path(list_path)), (
            f"{format_path(list_path)} is declared ordered, but the first changed field was "
            f"{first_path!r}"
        )

        assert dumps(variant, canonical=True) != canonical_bytes, (
            f"{format_path(list_path)} is declared ordered, but canonical encoding sorted "
            "or dropped the list order"
        )

        for canonical in (False, True):
            decoded = loads(dumps(variant, canonical=canonical))
            decoded_items = get_at_path(decoded, list_path)
            assert isinstance(decoded_items, list)
            assert _ids(decoded_items, id_key) == list(reversed(original_ids)), (
                f"{format_path(list_path)} lost list order in "
                f"{'canonical' if canonical else 'normal'} round-trip"
            )


@settings(max_examples=MAX_EXAMPLES, deadline=None)
@seed(REPLAY_SEED)
@given(archive_strategy())
def test_similar_looking_types_keep_distinct_business_identity(
    archive: ArchiveRecord,
) -> None:
    # These are exactly the equalities that make a naive ``==`` audit unsafe.
    false_value: object = False
    true_value: object = True
    assert 0 == false_value
    assert 1 == true_value
    assert 1 == 1.0
    assert Decimal("1") == 1
    assert CBORSimpleValue(1) == 1

    expected_fields: dict[str, tuple[type[object], object]] = {
        "zero_int": (int, 0),
        "zero_bool": (bool, False),
        "one_int": (int, 1),
        "one_bool": (bool, True),
        "one_float": (float, 1.0),
        "one_text": (str, "1"),
        "one_bytes": (bytes, b"1"),
        "one_simple": (CBORSimpleValue, CBORSimpleValue(1)),
        "one_decimal": (Decimal, Decimal("1")),
    }

    for canonical in (False, True):
        decoded = loads(dumps(archive, canonical=canonical))
        for index in range(len(archive["evidence"])):
            integrity = get_at_path(decoded, ("evidence", index, "integrity"))
            assert isinstance(integrity, Mapping)
            for field, (expected_type, expected_value) in expected_fields.items():
                value = integrity[field]
                path = ("evidence", index, "integrity", field)
                assert type(value) is expected_type, (
                    f"{format_path(path)} changed business type in "
                    f"{'canonical' if canonical else 'normal'} round-trip: expected "
                    f"{expected_type.__name__}, got {type(value).__name__}"
                )
                assert value == expected_value, (
                    f"{format_path(path)} changed visible value in "
                    f"{'canonical' if canonical else 'normal'} round-trip: "
                    f"expected {expected_value!r}, got {value!r}"
                )

            visible = {
                field: typed_visible(integrity[field]) for field in expected_fields
            }
            assert len(set(visible.values())) == len(visible), (
                "type-tagged visible values collapsed for these archive fields: "
                + ", ".join(
                    f"{format_path(('evidence', index, 'integrity', field))}={value!r}"
                    for field, value in visible.items()
                )
            )

            one_bytes = integrity["one_bytes"]
            one_text = integrity["one_text"]
            assert isinstance(one_bytes, bytes)
            assert isinstance(one_text, str)
            assert one_bytes.decode("ascii") == one_text, (
                f"{format_path(('evidence', index, 'integrity', 'one_bytes'))} and "
                f"{format_path(('evidence', index, 'integrity', 'one_text'))} are no longer "
                "visually similar synthetic values"
            )


@settings(max_examples=MAX_EXAMPLES, deadline=None)
@seed(REPLAY_SEED)
@given(archive_strategy())
def test_negative_zero_keeps_its_sign_in_both_encodings(
    archive: ArchiveRecord,
) -> None:
    assert -0.0 == 0.0
    assert math.copysign(1.0, -0.0) == -1.0
    assert math.copysign(1.0, 0.0) == 1.0
    assert typed_visible(-0.0) != typed_visible(0.0)

    # The canonical form is the shortest exact form; negative zero must keep its sign bit.
    assert dumps(-0.0, canonical=True).hex() == "f98000"
    assert dumps(0.0, canonical=True).hex() == "f90000"

    for canonical in (False, True):
        decoded = loads(dumps(archive, canonical=canonical))
        for index in range(len(archive["evidence"])):
            for field, expected_sign in (
                ("negative_zero", -1.0),
                ("positive_zero", 1.0),
            ):
                path = ("evidence", index, "integrity", field)
                value = get_at_path(decoded, path)
                assert isinstance(value, float), (
                    f"{format_path(path)} stopped being a float in "
                    f"{'canonical' if canonical else 'normal'} round-trip"
                )
                assert math.copysign(1.0, value) == expected_sign, (
                    f"{format_path(path)} lost its zero sign in "
                    f"{'canonical' if canonical else 'normal'} round-trip: decoded {value!r}"
                )
