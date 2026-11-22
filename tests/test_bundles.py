from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

import cbor2
from cbor2 import (
    ABSENT,
    CROSS_REF_TAG,
    FORBIDDEN,
    LOCAL_REF_TAG,
    MISSING,
    RESOLVED,
    Bundle,
    ReferenceStatus,
    build_checklist,
    cross_ref,
    dumps_bundle,
    handover_check,
    load_bundle,
    loads_bundle,
    local_ref,
    public_index,
    resolve_reference,
)


def _package(name: str, index: dict, entries: dict) -> bytes:
    return cbor2.dumps({"bundle": name, "index": index, "entries": entries})


def _three_packages() -> list[bytes]:
    a = _package(
        "A",
        {
            0: {
                "refs": [
                    {"local": 1},
                    {"bundle": "B", "id": 0},
                ]
            },
            1: {"content": "A-one"},
        },
        {0: {"claim": "A-zero"}, 1: "A-one"},
    )
    b = _package(
        "B",
        {
            0: {
                "refs": [{"bundle": "C", "id": 0}],
                "content": "B-zero",
            }
        },
        {0: "B-zero"},
    )
    c = _package(
        "C",
        {0: {"content": "C-zero"}},
        {0: "C-zero"},
    )
    return [a, b, c]


def test_local_and_cross_bundle_references() -> None:
    report = handover_check(_three_packages(), ("A", 0))

    assert report.complete
    assert report.status is RESOLVED
    assert [item.kind.value for item in report.checklist()] == [
        "cross_bundle",
        "local",
        "cross_bundle",
        "cross_bundle",
    ]
    assert [item.provenance for item in report.checklist()] == [
        (None, None, 0),
        ("A", 0, 0),
        ("A", 0, 1),
        ("B", 0, 0),
    ]


def test_same_local_number_is_scoped_to_its_package() -> None:
    a = _package("A", {0: {"content": "A-zero"}}, {0: "A-zero"})
    b = _package("B", {0: {"content": "B-zero"}}, {0: "B-zero"})

    a_result = resolve_reference([a, b], ("A", 0))
    b_result = resolve_reference([a, b], ("B", 0))

    assert a_result.content == "A-zero"
    assert b_result.content == "B-zero"
    assert a_result.key == ("A", 0)
    assert b_result.key == ("B", 0)

    report = handover_check([a, b], [("A", 0), ("B", 0)])
    assert {item.target for item in report.checklist() if item.is_claim} == {
        ("A", 0),
        ("B", 0),
    }


def test_missing_and_forbidden_are_distinct() -> None:
    a = _package(
        "A",
        {
            0: {
                "refs": [
                    {"bundle": "B", "id": 0},
                    {"bundle": "C", "id": 0},
                ]
            }
        },
        {0: {"claim": True}},
    )
    b = _package("B", {0: {"content": "B-zero"}}, {0: "B-zero"})

    report = handover_check([a, b], ("A", 0), permissions={"A"})
    statuses = {item.target: item.status for item in report.checklist()}

    assert statuses[("B", 0)] is FORBIDDEN
    assert statuses[("C", 0)] is MISSING
    assert statuses[("B", 0)] is not statuses[("C", 0)]
    assert report.status is FORBIDDEN
    assert not report.sufficient


def test_forbidden_content_never_leaks_into_the_report() -> None:
    a = _package(
        "A",
        {0: {"refs": [{"bundle": "B", "id": 0}]}},
        {0: {"claim": True}},
    )
    b = _package(
        "B",
        {0: {"content": {"secret": "do not disclose"}}},
        {0: {"secret": "do not disclose"}},
    )

    report = handover_check([a, b], ("A", 0), permissions={"A"})
    serialized = json.dumps(report.to_dict())

    assert report.status is FORBIDDEN
    assert "do not disclose" not in serialized


def test_permission_boundary_stops_index_expansion() -> None:
    a = _package(
        "A",
        {0: {"refs": [{"bundle": "B", "id": 0}]}},
        {0: {"claim": True}},
    )
    b = _package(
        "B",
        {0: {"refs": [{"bundle": "C", "id": 0}], "content": "B-zero"}},
        {0: "B-zero"},
    )
    c = _package("C", {0: {"content": "C-zero"}}, {0: "C-zero"})

    report = handover_check([a, b, c], ("A", 0), permissions={"A"})
    assert {item.target for item in report.checklist()} == {("A", 0), ("B", 0)}


def test_missing_content_still_exposes_its_public_index() -> None:
    a = _package(
        "A",
        {0: {"refs": [{"bundle": "B", "id": 0}]}},
        {0: {"claim": True}},
    )
    b = _package("B", {0: {"refs": [{"bundle": "C", "id": 0}]}}, {})
    c = _package("C", {0: {"content": "C-zero"}}, {0: "C-zero"})

    report = handover_check([a, b, c], ("A", 0), permissions={"A", "B", "C"})
    statuses = {item.target: item.status for item in report.checklist()}
    assert statuses[("B", 0)] is MISSING
    assert statuses[("C", 0)] is RESOLVED
    assert not report.complete


def test_content_stored_in_another_approved_package() -> None:
    a = _package(
        "A",
        {0: {"stored_in": {"bundle": "B", "id": 7}}},
        {},
    )
    b = _package(
        "B",
        {7: {"content": "B-seven"}},
        {7: "B-seven"},
    )

    report = handover_check([a, b], ("A", 0), permissions={"A", "B"})
    assert report.complete
    item = next(item for item in report.checklist() if item.is_claim)
    assert item.resolved_bundle == "B"
    assert item.resolved_entry == 7

    denied = handover_check([a, b], ("A", 0), permissions={"A"})
    assert not denied.complete
    denied_item = next(item for item in denied.checklist() if item.is_claim)
    assert denied_item.status is FORBIDDEN
    assert denied_item.resolved_bundle == "B"


def test_missing_content_is_not_the_same_as_forbidden() -> None:
    a = _package(
        "A",
        {0: {"refs": [{"bundle": "B", "id": 0}]}},
        {0: {"claim": True}},
    )
    b = _package("B", {0: {"refs": []}}, {})

    report = handover_check([a, b], ("A", 0), permissions={"A", "B"})
    item = next(item for item in report.checklist() if item.target == ("B", 0))
    assert item.status is MISSING
    assert "not supplied" in item.reason


def test_public_index_never_contains_entry_content() -> None:
    bundle = load_bundle(
        _package(
            "A",
            {0: {"refs": [{"local": 1}]}, 1: {"content": "private"}},
            {0: "private too", 1: "private"},
        )
    )
    index = public_index(bundle)

    assert index[0]["refs"] == [{"local": 1}]
    assert "private" not in json.dumps(index)


def test_withdrawing_an_unrelated_package_preserves_conclusions() -> None:
    a = _package(
        "A",
        {0: {"refs": [{"local": 1}]}, 1: {"content": "A-one"}},
        {0: {"claim": True}, 1: "A-one"},
    )
    b = _package(
        "B",
        {0: {"refs": [{"bundle": "C", "id": 0}]}, 1: {"content": "B-one"}},
        {0: {"claim": True}, 1: "B-one"},
    )
    c = _package("C", {0: {"content": "C-zero"}}, {0: "C-zero"})

    before = handover_check([a, b, c], ("A", 0))
    after = handover_check([a, b, c], ("A", 0), withdrawn={"B"})

    assert before.complete and after.complete
    assert before.checklist() == after.checklist()

    dependent_before = handover_check([a, b, c], ("B", 0))
    dependent_after = handover_check([a, b, c], ("B", 0), withdrawn={"B"})
    assert dependent_before.complete
    assert not dependent_after.complete
    assert dependent_after.status is MISSING


def test_reference_tags_are_decoded_by_the_existing_entry_points() -> None:
    a = cbor2.dumps(
        {
            "bundle": "A",
            "index": {
                0: {
                    "refs": [
                        cbor2.CBORTag(LOCAL_REF_TAG, 1),
                        cbor2.CBORTag(CROSS_REF_TAG, ["B", 0]),
                    ]
                },
                1: {"content": "A-one"},
            },
            "entries": {0: {"claim": True}, 1: "A-one"},
        }
    )
    b = _package("B", {0: {"content": "B-zero"}}, {0: "B-zero"})

    report = handover_check([a, b], ("A", 0))
    assert report.complete
    assert [item.kind.value for item in report.checklist()][1:] == [
        "local",
        "cross_bundle",
    ]


def test_reference_marker_variants() -> None:
    a = cbor2.dumps(
        {
            "bundle": "A",
            "index": {
                0: {
                    "refs": [
                        {"$ref": {"bundle": "B", "id": 0}},
                        {"ref": "A:1"},
                        {"cross": ["B", 0]},
                    ]
                },
                1: {"content": "A-one"},
            },
            "entries": {0: {"claim": True}, 1: "A-one"},
        }
    )
    b = _package("B", {0: {"content": "B-zero"}}, {0: "B-zero"})

    report = handover_check([a, b], ("A", 0))
    assert report.complete
    assert [item.target for item in report.checklist()][1:] == [
        ("B", 0),
        ("A", 1),
        ("B", 0),
    ]


def test_bare_local_numbers_in_a_reference_list() -> None:
    a = _package(
        "A",
        {0: {"refs": [1, 2]}, 1: {"content": "one"}, 2: {"content": "two"}},
        {0: {"claim": True}, 1: "one", 2: "two"},
    )

    report = handover_check([a], ("A", 0))
    assert report.complete
    assert [item.target for item in report.checklist()][1:] == [
        ("A", 1),
        ("A", 2),
    ]


def test_duplicate_names_are_rejected() -> None:
    a = _package("A", {0: {"content": "one"}}, {0: "one"})
    a2 = _package("A", {0: {"content": "two"}}, {0: "two"})

    with pytest.raises(ValueError, match="duplicate bundle name"):
        handover_check([a, a2], ("A", 0))


def test_public_index_only_package_is_missing_content() -> None:
    a = _package("A", {0: {"refs": []}}, {})
    assert not handover_check([a], ("A", 0)).complete


def test_status_aliases() -> None:
    assert ReferenceStatus.UNAUTHORIZED is ReferenceStatus.FORBIDDEN
    assert ReferenceStatus.ABSENT is ReferenceStatus.MISSING
    assert ABSENT is MISSING


def test_build_checklist_accepts_a_report() -> None:
    report = handover_check(_three_packages(), ("A", 0))
    assert build_checklist(report) == report.checklist()


def test_bundle_round_trip() -> None:
    bundle = Bundle(
        name="A",
        index={0: cbor2.EntryDescriptor(refs=(local_ref(1),))},
        entries={0: {"claim": True}, 1: "A-one"},
    )
    round_tripped = loads_bundle(dumps_bundle(bundle))
    assert round_tripped.name == "A"
    assert round_tripped.entries == bundle.entries


def test_cli_prints_provenance_ordered_checklist(tmp_path: Path) -> None:
    a, b, c = _three_packages()
    paths = []
    for name, payload in zip(("a.cbor", "b.cbor", "c.cbor"), (a, b, c)):
        path = tmp_path / name
        path.write_bytes(payload)
        paths.append(str(path))

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "cbor2.bundles",
            "--claim",
            "A:0",
            "--permit",
            "A",
            "--permit",
            "B",
            "--compact",
            *paths,
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 1
    report = json.loads(result.stdout)
    assert report["complete"] is False
    assert report["checklist"][-1]["status"] == "forbidden"
