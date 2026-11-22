from __future__ import annotations

from typing import Any

import pytest

import cbor2
from cbor2.handoff import (
    CROSS_PACKAGE_REFERENCE_TAG,
    LOCAL_REFERENCE_TAG,
    EvidenceLicense,
    HandoffFormatError,
    PackageRef,
    ReferenceKind,
    ReferenceStatus,
    audit_claims,
    audit_handoff,
    resolve_references,
    scan_references,
    withdraw_package,
)


def package(
    package_id: str,
    entries: dict[Any, Any],
) -> dict[str, Any]:
    return {"package": package_id, "index": entries}


def test_local_and_cross_package_references_are_qualified_by_package() -> None:
    packages = {
        "a": cbor2.dumps(
            package(
                "a",
                {
                    "claim": {
                        "content": "the finding",
                        "references": [
                            {"entry": 1},
                            {"package": "b", "entry": 1},
                        ],
                    },
                    1: {"content": "local support"},
                },
            )
        ),
        "b": cbor2.dumps(
            package(
                "b",
                {
                    1: {"content": "other package's local support"},
                },
            )
        ),
    }

    report = audit_handoff(packages, {"package": "a", "entry": "claim"})

    assert report.sufficient
    assert report.status == ReferenceStatus.RESOLVED
    assert [item.target for item in report.checklist] == [
        PackageRef("a", 1),
        PackageRef("b", 1),
    ]
    assert [item.kind for item in report.checklist] == [
        ReferenceKind.LOCAL,
        ReferenceKind.CROSS_PACKAGE,
    ]


def test_checklist_is_sorted_by_reference_provenance() -> None:
    packages = {
        "a": package(
            "a",
            {
                "claim": {
                    "content": "claim",
                    "references": [
                        {"package": "b", "entry": 2},
                        {"entry": 2},
                        {"entry": "2"},
                    ],
                },
                2: {"content": "local"},
                "2": {
                    "content": "local again",
                    "references": [{"package": "b", "entry": 1}],
                },
            },
        ),
        "b": package("b", {1: {"content": "one"}, 2: {"content": "two"}}),
    }

    items = resolve_references(packages, "a#claim")

    assert [(item.source.package, item.source.entry) for item in items] == [
        ("a", "2"),
        ("a", "claim"),
        ("a", "claim"),
        ("a", "claim"),
    ]


def test_missing_and_not_authorized_are_distinct() -> None:
    packages = {
        "a": package(
            "a",
            {
                "claim": {
                    "content": "claim",
                    "references": [
                        {"package": "b", "entry": "held"},
                        {"package": "c", "entry": "sealed"},
                    ],
                }
            },
        ),
        "b": package("b", {"held": {"content": "held"}}),
        "c": package("c", {"sealed": {"content": "sealed"}}),
    }

    missing = audit_handoff(
        packages,
        "a#claim",
        license={"a": True, "b": True, "c": True},
    )
    assert missing.status is ReferenceStatus.RESOLVED

    missing = audit_handoff(
        packages,
        "a#claim",
        license={"a": True, "b": {"entries": ["held"]}, "c": {"entries": []}},
    )
    assert not missing.sufficient
    assert missing.status is ReferenceStatus.NOT_AUTHORIZED
    assert missing.not_authorized == [PackageRef("c", "sealed")]

    packages["c"] = package("c", {})
    missing = audit_handoff(
        packages,
        "a#claim",
        license={"a": True, "b": True, "c": True},
    )
    assert not missing.sufficient
    assert missing.status is ReferenceStatus.MISSING
    assert missing.missing == [PackageRef("c", "sealed")]


def test_withdrawing_a_package_does_not_change_independent_claims() -> None:
    packages = {
        "a": package(
            "a",
            {
                "one": {"content": "one", "references": [{"entry": "support"}]},
                "support": {"content": "support"},
                "two": {"content": "two", "references": [{"package": "b", "entry": "x"}]},
            },
        ),
        "b": package("b", {"x": {"content": "x"}}),
    }

    before = audit_claims(packages, ["a#one", "a#two"])
    without_b = withdraw_package(packages, "b")
    after = audit_claims(without_b, ["a#one", "a#two"])

    assert before[0] == after[0]
    assert before[0].sufficient
    assert before[1].sufficient
    assert before[1].status is ReferenceStatus.RESOLVED
    assert not after[1].sufficient
    assert after[1].status is ReferenceStatus.PACKAGE_MISSING


def test_evidence_license_can_scope_individual_entries() -> None:
    packages = {
        "a": package(
            "a",
            {"claim": {"content": "claim", "references": [{"package": "b", "entry": "x"}]}},
        ),
        "b": package("b", {"x": {"content": "x"}}),
    }

    report = audit_handoff(
        packages,
        "a#claim",
        license=EvidenceLicense({"a": True, "b": {"entries": ["y"]}}),
    )

    assert report.status is ReferenceStatus.NOT_AUTHORIZED
    assert report.not_authorized == [PackageRef("b", "x")]


def test_reference_tags_are_recognised_and_namespaced() -> None:
    packages = {
        "a": package(
            "a",
            {
                "claim": {
                    "content": "claim",
                    "references": [
                        cbor2.CBORTag(LOCAL_REFERENCE_TAG, 7),
                        cbor2.CBORTag(CROSS_PACKAGE_REFERENCE_TAG, "b#seven"),
                    ],
                },
                7: {"content": "a seven"},
            },
        ),
        "b": package("b", {"seven": {"content": "b seven"}}),
    }

    report = audit_handoff(packages, "a#claim")

    assert report.sufficient
    assert [item.target for item in report.checklist] == [
        PackageRef("a", 7),
        PackageRef("b", "seven"),
    ]
    assert scan_references(packages) == [
        item.reference for item in report.checklist
    ]


def test_claim_itself_must_be_in_scope() -> None:
    packages = {"a": package("a", {"claim": {"content": "claim"}})}

    report = audit_handoff(packages, "a#claim", license={"b": True})

    assert report.status is ReferenceStatus.NOT_AUTHORIZED
    assert report.not_authorized == [PackageRef("a", "claim")]


def test_entries_only_available_in_another_package_are_followed() -> None:
    packages = {
        "a": package("a", {"claim": {"content": {"package": "b", "entry": "report"}}}),
        "b": package("b", {"report": {"content": "the report"}}),
    }

    report = audit_handoff(packages, "a#claim")

    assert report.sufficient
    assert report.checklist[0].kind is ReferenceKind.CROSS_PACKAGE
    assert report.checklist[0].target == PackageRef("b", "report")


def test_unqualified_claim_requires_an_unambiguous_package() -> None:
    packages = {
        "a": package("a", {"claim": {"content": "claim"}}),
        "b": package("b", {"claim": {"content": "claim"}}),
    }

    with pytest.raises(HandoffFormatError, match="ambiguous"):
        audit_handoff(packages, "claim")


def test_public_index_can_be_separate_from_entries() -> None:
    packages = {
        "a": {
            "package": "a",
            "index": [{"id": "claim", "references": [{"package": "b", "entry": 7}]}],
            "entries": {"claim": "the claim body"},
        },
        "b": {"package": "b", "entries": {7: "the annex body"}},
    }

    report = audit_handoff(packages, "a#claim")

    assert report.sufficient
    assert report.checklist[0].target == PackageRef("b", 7)


def test_numeric_reference_text_resolves_against_integer_local_ids() -> None:
    packages = {
        "a": {"package": "a", "index": {"claim": {"content": "c", "refs": ["b:7"]}}},
        "b": {"package": "b", "index": {7: {"content": "b"}}},
    }

    report = audit_handoff(packages, "a#claim")

    assert report.sufficient
    assert report.checklist[0].target == PackageRef("b", 7)


def test_withheld_entry_is_missing_not_content() -> None:
    packages = {
        "a": {
            "package": "a",
            "index": {"claim": {"content": "not public", "withheld": True}},
        }
    }

    report = audit_handoff(packages, "a#claim")

    assert report.status is ReferenceStatus.MISSING
    assert report.missing == [PackageRef("a", "claim")]


def test_a_single_cbor_sequence_of_packages_is_accepted() -> None:
    packages = [
        package("a", {"claim": {"content": "c", "refs": [{"package": "b", "entry": "x"}]}}),
        package("b", {"x": {"content": "x"}}),
    ]

    report = audit_handoff(cbor2.dumps(packages), "a#claim")

    assert report.sufficient


def test_unauthorized_takes_precedence_over_missing() -> None:
    packages = {
        "a": {
            "package": "a",
            "index": {"claim": {"content": "c", "refs": [{"package": "b", "entry": "gone"}]}},
        },
        "b": {"package": "b", "index": {}},
    }

    report = audit_handoff(packages, "a#claim", license={"a": True, "b": False})

    assert report.status is ReferenceStatus.NOT_AUTHORIZED
    assert report.not_authorized == [PackageRef("b", "gone")]
