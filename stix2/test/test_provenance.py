"""Tests for offline provenance review of STIX relationship claims."""

import pytest

from stix2.provenance import (
    Claim,
    ClaimStatus,
    IndependenceList,
    build_citation_graph,
    citations_from_reports,
    claims_from_stix_relationships,
    evaluate_claims,
    review_independence_lists,
)


USES_KEY = ("intrusion-set--x", "uses", "malware--y")


def test_three_feeds_two_share_one_original():
    """Three uses-relationships; two feeds republish the same original."""

    claims = [
        Claim("rel--vendor-a", "feed-a", ("original--1",), USES_KEY),
        Claim("rel--vendor-b", "feed-b", ("original--1",), USES_KEY),
        Claim("rel--vendor-c", "feed-c", ("original--2",), USES_KEY),
    ]
    no_grouping = IndependenceList("all independent")

    result = evaluate_claims(claims, no_grouping)

    assert result.retained == (USES_KEY,)
    conclusion = result.conclusion_for(USES_KEY)
    assert conclusion.independent_source_count == 2
    assert conclusion.root_units == frozenset((
        "original--1", "original--2",
    ))
    record_a = result.assessment_for("rel--vendor-a")
    assert record_a.evidence_records == ("original--1",)
    assert record_a.status is ClaimStatus.RETAINED


def test_two_feeds_same_original_is_only_one_source():
    """Two submissions tracing to one original do not corroborate."""

    claims = [
        Claim("rel--a", "feed-a", ("original--1",), USES_KEY),
        Claim("rel--b", "feed-b", ("original--1",), USES_KEY),
    ]

    result = evaluate_claims(claims, IndependenceList("flat"))

    assert result.retained == ()
    assert result.insufficient == (USES_KEY,)
    assert result.conclusion_for(USES_KEY).independent_source_count == 1


def test_independence_list_can_merge_distinct_originals():
    """Two originals collapse into one independent source under one policy."""

    claims = [
        Claim("rel--1", "feed-a", ("original--1",), USES_KEY),
        Claim("rel--2", "feed-b", ("original--2",), USES_KEY),
    ]
    separate = IndependenceList("separate publishers")
    merged = IndependenceList(
        "same publisher imprints",
        source_groups=[["original--1", "original--2"]],
    )

    review = review_independence_lists(claims, separate, merged)

    assert review.baseline.retained == (USES_KEY,)
    assert review.alternative.retained == ()
    assert review.lost_support == (USES_KEY,)
    assert review.gained_support == ()
    alternative = review.alternative.conclusion_for(USES_KEY)
    assert alternative.status is ClaimStatus.INSUFFICIENT
    assert alternative.independent_source_count == 1



def test_citation_chain_collapses_to_original():
    claims = [Claim("rel--chain", "feed-c", ("feed-b",), USES_KEY)]
    citation_records = [
        Claim("record--b", "feed-b", ("feed-a",)),
        Claim("record--a", "feed-a", ("original--1",)),
    ]

    result = evaluate_claims(
        claims, IndependenceList("flat"), 1, citation_records,
    )

    assessment = result.assessment_for("rel--chain")
    assert assessment.root_units == frozenset(("original--1",))
    assert assessment.evidence_records == ("original--1",)
    assert result.retained == (USES_KEY,)


def test_cycle_is_one_provenance_unit_not_many_records():
    """Records inside a citation cycle must not count as multiple support."""

    claims = [Claim("rel--x", "feed-x", ("cycle-a",), USES_KEY)]
    citation_records = [
        Claim("rec--a", "cycle-a", ("cycle-b",)),
        Claim("rec--b", "cycle-b", ("cycle-c",)),
        Claim("rec--c", "cycle-c", ("cycle-a",)),
    ]

    graph = build_citation_graph(tuple(claims) + tuple(citation_records))
    assert len(graph.cyclic_components) == 1
    assert next(iter(graph.cyclic_components)) == frozenset((
        "cycle-a", "cycle-b", "cycle-c",
    ))

    result = evaluate_claims(
        claims, IndependenceList("flat"), 2, citation_records,
    )
    assessment = result.assessment_for("rel--x")

    assert assessment.status is ClaimStatus.INSUFFICIENT
    assert assessment.independent_source_count == 1
    assert assessment.root_units == frozenset((
        "cycle:cycle-a|cycle-b|cycle-c",
    ))
    assert result.retained == ()


def test_self_citation_is_a_cycle():
    claims = [Claim("rel--loop", "self", ("self",), USES_KEY)]

    result = evaluate_claims(claims, IndependenceList("flat"))

    assert result.unattributed == ()
    assessment = result.assessment_for("rel--loop")
    assert assessment.status is ClaimStatus.INSUFFICIENT
    assert assessment.root_units == frozenset(("cycle:self",))


def test_cycle_with_escape_reaches_external_original():
    """A cycle that also cites an external record roots at that original."""

    claims = [Claim("rel--x", "feed-x", ("cycle-a",), USES_KEY)]
    citation_records = [
        Claim("rec--a", "cycle-a", ("cycle-b", "original--9")),
        Claim("rec--b", "cycle-b", ("cycle-a",)),
    ]

    result = evaluate_claims(
        claims, IndependenceList("flat"), 1, citation_records,
    )

    assessment = result.assessment_for("rel--x")
    assert assessment.root_units == frozenset(("original--9",))
    assert assessment.status is ClaimStatus.RETAINED



def test_unattributed_records_listed_separately():
    """A conclusion with one sourced and one bare record keeps both visible."""

    claims = [
        Claim("rel--sourced", "feed-a", ("original--1",), USES_KEY),
        Claim("rel--bare", "feed-z", (), USES_KEY),
    ]

    result = evaluate_claims(
        claims, IndependenceList("flat"), min_independent_sources=1,
    )

    assert result.unattributed == ("rel--bare",)
    bare = result.assessment_for("rel--bare")
    assert bare.status is ClaimStatus.UNATTRIBUTED
    assert bare.independent_source_count == 0
    conclusion = result.conclusion_for(USES_KEY)
    assert conclusion.status is ClaimStatus.RETAINED
    assert conclusion.unattributed_claims == ("rel--bare",)


def test_fully_unattributed_conclusion_is_not_retained():
    claims = [Claim("rel--bare", "feed-z", (), USES_KEY)]

    result = evaluate_claims(claims, IndependenceList("flat"))

    assert result.retained == ()
    assert result.insufficient == ()
    assert result.unattributed == ("rel--bare",)
    assert result.conclusion_for(USES_KEY).status is ClaimStatus.UNATTRIBUTED


def test_switching_lists_flags_relationships_that_lost_support():
    """Headline scenario: same claims, two independence policies."""

    claims = [
        Claim("uses--1", "vendor-a", ("doc--shared",), USES_KEY),
        Claim("uses--2", "vendor-b", ("doc--shared",), USES_KEY),
        Claim("uses--3", "vendor-c", ("doc--other",), USES_KEY),
    ]
    loose = IndependenceList("loose: every original stands alone")
    strict = IndependenceList(
        "strict: same upstream editorial pipeline",
        source_groups=[["doc--shared", "doc--other"]],
    )

    review = review_independence_lists(claims, loose, strict)

    assert review.baseline.retained == (USES_KEY,)
    assert review.alternative.retained == ()
    assert review.lost_support == (USES_KEY,)
    assert review.gained_support == ()
    assert review.unattributed == ()
    assert review.alternative.conclusion_for(
        USES_KEY,
    ).independent_source_count == 1


def test_distinct_conclusions_are_decisively_separated():
    other_key = ("intrusion-set--x", "uses", "tool--z")
    claims = [
        Claim("rel--1", "feed-a", ("original--1",), USES_KEY),
        Claim("rel--2", "feed-b", ("original--1",), other_key),
    ]

    result = evaluate_claims(claims, IndependenceList("flat"))

    assert sorted(result.insufficient) == sorted((USES_KEY, other_key))
    assert result.retained == ()


def test_duplicate_claim_ids_rejected():
    claims = [
        Claim("rel--dup", "feed-a", ("original--1",)),
        Claim("rel--dup", "feed-b", ("original--2",)),
    ]

    with pytest.raises(ValueError, match="Duplicate claim id"):
        evaluate_claims(claims, IndependenceList("flat"))


def test_invalid_min_independent_sources_rejected():
    with pytest.raises(ValueError, match="at least 1"):
        evaluate_claims(
            [Claim("rel--1", "feed-a", ())],
            IndependenceList("flat"),
            min_independent_sources=0,
        )



def _uses_relationship(relationship_id, external_id, source_name="Acme Weekly"):
    return {
        "type": "relationship",
        "id": relationship_id,
        "relationship_type": "uses",
        "source_ref": "intrusion-set--x",
        "target_ref": "malware--y",
        "external_references": [
            {"source_name": source_name, "external_id": external_id},
        ],
    }


def test_claims_built_from_stix_relationship_references():
    relationships = [
        _uses_relationship("relationship--aaaa", "ACME-2026-001"),
        _uses_relationship("relationship--bbbb", "ACME-2026-001"),
        _uses_relationship(
            "relationship--cccc", "IL-77", source_name="Independent Ledger",
        ),
    ]

    claims = claims_from_stix_relationships(relationships)
    result = evaluate_claims(claims, IndependenceList("all independent"))

    expected_key = ("intrusion-set--x", "uses", "malware--y")
    assert result.retained == (expected_key,)
    assert result.assessment_for(
        "relationship--aaaa",
    ).root_units == frozenset(("ACME-2026-001",))
    assert result.conclusion_for(expected_key).independent_source_count == 2


def test_stix_relationships_sharing_original_are_not_corroboration():
    relationships = [
        _uses_relationship("relationship--aaaa", "ACME-2026-001"),
        _uses_relationship("relationship--bbbb", "ACME-2026-001"),
    ]

    result = evaluate_claims(
        claims_from_stix_relationships(relationships),
        IndependenceList("all independent"),
    )

    assert result.retained == ()
    assert result.insufficient == (
        ("intrusion-set--x", "uses", "malware--y"),
    )


def test_citation_map_overrides_embedded_references():
    relationships = [_uses_relationship("relationship--aaaa", "ACME-2026-001")]
    citation_map = {"relationship--aaaa": ("upstream--report--7",)}

    claims = claims_from_stix_relationships(
        relationships, citation_map=citation_map,
    )

    assert claims[0].cited_sources == ("upstream--report--7",)


def test_citations_from_reports():
    reports = [
        {
            "type": "report",
            "id": "report--1",
            "external_references": [
                {"source_name": "Acme Weekly", "external_id": "ACME-2026-001"},
                {"source_name": "Acme Weekly", "external_id": "ACME-2026-001"},
            ],
        },
        {
            "type": "report",
            "id": "report--2",
            "external_references": [
                {"source_name": "Bare Source Without External Id"},
            ],
        },
    ]

    assert citations_from_reports(reports) == {
        "report--1": ("ACME-2026-001",),
        "report--2": ("Bare Source Without External Id",),
    }


def test_stix_relationship_without_references_is_unattributed():
    relationships = [
        {
            "type": "relationship",
            "id": "relationship--naked",
            "relationship_type": "uses",
            "source_ref": "intrusion-set--x",
            "target_ref": "malware--y",
        },
    ]

    result = evaluate_claims(
        claims_from_stix_relationships(relationships),
        IndependenceList("flat"),
        min_independent_sources=1,
    )

    assert result.unattributed == ("relationship--naked",)
