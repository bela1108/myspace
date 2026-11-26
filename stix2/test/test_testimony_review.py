import json
from pathlib import Path

import pytest

from stix2.testimony_review import (
    HEARSAY_CLAIM_ID,
    hearsay_demo,
    hearsay_fixture,
    maximal_coexisting_evidence_sets,
    review_testimony,
)

CLAIM = "campaign-039-uses-resolver"
FIXTURE_PATH = Path(__file__).parent / "fixtures" / "hearsay_testimony.json"


@pytest.fixture
def hearsay_payload():
    return hearsay_fixture()


def test_hearsay_fixture_changes_from_confirmed_to_disputed_after_source_merge():
    demo = hearsay_demo()

    before = demo["before_merge"]
    after = demo["after_merge"]

    assert demo["claim_id"] == CLAIM
    assert before["claims"][CLAIM]["status"] == "determined"
    assert before["claims"][CLAIM]["polarity"] is True
    assert len(before["optimal_evidence_sets"]) == 1
    assert before["optimal_evidence_sets"][0]["evidence_ids"] == [
        "testimony--relay-alpha",
        "testimony--relay-beta",
    ]

    assert after["claims"][CLAIM]["status"] == "divided"
    assert after["claims"][CLAIM]["is_disputed"] is True
    conclusions = [
        tuple(sorted(item["conclusions"].items()))
        for item in after["optimal_evidence_sets"]
    ]
    assert ((CLAIM, False),) in conclusions
    assert ((CLAIM, True),) in conclusions


def test_merged_relay_votes_have_equal_independent_source_cost():
    report = review_testimony(hearsay_fixture(merged=True))
    sets = report["optimal_evidence_sets"]

    assert len(sets) == 2
    assert {item["cost"] for item in sets} == {1.0}
    assert {item["independent_source_count"] for item in sets} == {1}
    assert sorted(item["conclusions"][CLAIM] for item in sets) == [False, True]


def test_unknown_relationship_and_similar_name_do_not_merge_sources():
    report = review_testimony({
        "evidence": [
            {
                "id": "testimony--one",
                "source_ref": "identity--collector-alpha",
                "claim_id": "P",
                "stance": "supports",
            },
            {
                "id": "testimony--two",
                "source_ref": "identity--collector-alpha-copy",
                "claim_id": "P",
                "stance": "supports",
            },
            {
                "id": "testimony--three",
                "source_ref": "identity--independent",
                "claim_id": "P",
                "stance": "opposes",
            },
        ],
        "relationships": [
            {
                "id": "relationship--name-only",
                "relationship_type": "display-name-resembles",
                "source_ref": "testimony--one",
                "target_ref": "testimony--two",
            },
        ],
    })

    clusters = report["source_groups"]["by_evidence"]
    assert clusters["testimony--one"] != clusters["testimony--two"]
    assert len(report["unknown_relationships"]) == 1
    assert len(report["optimal_evidence_sets"]) == 1
    assert report["optimal_evidence_sets"][0]["evidence_ids"] == [
        "testimony--one",
        "testimony--two",
    ]
    assert report["claims"]["P"]["status"] == "confirmed"


def test_versioned_source_declaration_supersedes_independence():
    report = review_testimony(hearsay_fixture(merged=True))
    declarations = report["source_groups"]["declarations"]
    current = [item for item in declarations if item["status"] == "current"]

    assert len(current) == 1
    assert current[0]["same_source_groups"] == [
        ["testimony--relay-alpha", "testimony--relay-beta"],
    ]
    declaration_versions = [
        group for group in report["version_groups"]
        if group["group"] == "source-declaration--hearsay-039"
    ]
    assert len(declaration_versions) == 1
    assert declaration_versions[0]["current"] == "source-declaration--hearsay-039"
    assert len(declaration_versions[0]["versions"]) == 2


def test_stix_like_bundle_uses_created_by_ref_for_source_cluster():
    report = review_testimony({
        "type": "bundle",
        "id": "bundle--test",
        "objects": [
            {
                "type": "opinion",
                "id": "opinion--one",
                "opinion": "agree",
                "object_refs": ["relationship--claim"],
                "created_by_ref": "identity--shared-collector",
            },
            {
                "type": "opinion",
                "id": "opinion--two",
                "opinion": "strongly-agree",
                "object_refs": ["relationship--claim"],
                "created_by_ref": "identity--shared-collector",
            },
            {
                "type": "opinion",
                "id": "opinion--three",
                "opinion": "strongly-disagree",
                "object_refs": ["relationship--claim"],
                "created_by_ref": "identity--independent",
            },
        ],
    })

    assert report["source_count"] == 2
    assert len(report["optimal_evidence_sets"]) == 2
    assert report["claims"]["relationship--claim"]["status"] == "disputed"


def test_maximal_sets_function_returns_all_inclusion_maximal_sets():
    sets = maximal_coexisting_evidence_sets([
        {"id": "a", "claim_id": "P", "value": True},
        {"id": "b", "claim_id": "P", "value": True},
        {"id": "c", "claim_id": "P", "value": False},
    ])

    assert sorted(item["evidence_ids"] for item in sets) == [
        ["a", "b"],
        ["c"],
    ]


def test_explicit_implication_is_used_for_conclusions():
    report = review_testimony({
        "evidence": [
            {"id": "e1", "claim_id": "P", "value": True},
        ],
        "rules": [
            {"id": "rule-1", "if": "P", "then": "Q"},
        ],
    })

    assert report["optimal_evidence_sets"][0]["conclusions"]["Q"] is True
    assert report["claims"]["Q"]["status"] == "confirmed"


def test_current_version_with_shared_stix_id_is_used():
    report = review_testimony({
        "evidence": [
            {
                "id": "statement--versioned",
                "version": 1,
                "modified": "2026-11-20T00:00:00Z",
                "claim_id": "V",
                "value": True,
            },
            {
                "id": "statement--versioned",
                "version": 2,
                "modified": "2026-11-21T00:00:00Z",
                "claim_id": "V",
                "value": False,
            },
        ],
    })

    assert report["evidence_count"] == 1
    assert report["optimal_evidence_sets"][0]["evidence_ids"] == [
        "statement--versioned",
    ]
    assert report["claims"]["V"]["polarity"] is False


def test_explicit_costs_use_exclusion_cost_ranking():
    report = review_testimony({
        "evidence": [
            {"id": "expensive-pro", "claim_id": "P", "value": True, "cost": 5},
            {"id": "cheap-con", "claim_id": "P", "value": False, "cost": 2},
        ],
    })

    assert report["cost_metric"] == "exclusion"
    assert report["optimal_evidence_sets"][0]["evidence_ids"] == ["expensive-pro"]
    assert report["optimal_evidence_sets"][0]["cost"] == 2.0


def test_hearsay_fixture_exposes_expected_claim_constant(hearsay_payload):
    assert hearsay_payload["claim_id"] == HEARSAY_CLAIM_ID
    assert len(hearsay_payload["testimonies"]) == 3
    assert len(hearsay_payload["upstream_observations"]) == 2


def test_json_fixture_file_reaches_tied_review():
    payload = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    report = review_testimony(payload)

    assert FIXTURE_PATH.is_file()
    assert report["claims"][CLAIM]["status"] == "disputed"
    assert len(report["optimal_evidence_sets"]) == 2
