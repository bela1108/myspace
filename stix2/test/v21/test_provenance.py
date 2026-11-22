import json

import pytest

import stix2
from stix2.provenance import (
    CALLER_RELATION,
    COLLECTION_RELATIONSHIP,
    CUSTODIAN_VIEW,
    PUBLIC_VIEW,
    SELF_CITATION,
    IndependenceChecker,
    check_independence,
)


OBS_A1 = "observed-data--00000000-0000-4000-8000-000000000001"
OBS_A2 = "observed-data--00000000-0000-4000-8000-000000000002"
OBS_A3 = "observed-data--00000000-0000-4000-8000-000000000003"
OBS_B1 = "observed-data--00000000-0000-4000-8000-000000000004"
OBS_B2 = "observed-data--00000000-0000-4000-8000-000000000005"
OBS_HIDDEN = "observed-data--00000000-0000-4000-8000-000000000006"
OBS_C1 = "observed-data--00000000-0000-4000-8000-000000000021"
OBS_C2 = "observed-data--00000000-0000-4000-8000-000000000022"
OBS_C3 = "observed-data--00000000-0000-4000-8000-000000000023"
OBS_D1 = "observed-data--00000000-0000-4000-8000-000000000031"
OBS_D2 = "observed-data--00000000-0000-4000-8000-000000000032"
OBS_D3 = "observed-data--00000000-0000-4000-8000-000000000033"
OBS_D4 = "observed-data--00000000-0000-4000-8000-000000000034"
OBS_MISSING = "observed-data--00000000-0000-4000-8000-000000000099"

MARKING_ID = "marking-definition--00000000-0000-4000-8000-000000000077"
REPORT_A1 = "report--00000000-0000-4000-8000-000000000011"
REPORT_A2 = "report--00000000-0000-4000-8000-000000000012"
REPORT_A3 = "report--00000000-0000-4000-8000-000000000013"
REPORT_B1 = "report--00000000-0000-4000-8000-000000000014"
REPORT_B2 = "report--00000000-0000-4000-8000-000000000015"
RELATIONSHIP_D1 = "relationship--00000000-0000-4000-8000-000000000041"

CREATED = "2026-01-01T00:00:00.000Z"
MODIFIED = "2026-01-01T00:00:00.000Z"
OBSERVED = "2026-01-01T00:00:00Z"
PUBLISHED = "2026-01-02T00:00:00Z"


def _observation(oid, name, **kwargs):
    kwargs.setdefault("created", CREATED)
    kwargs.setdefault("modified", MODIFIED)
    if "objects" not in kwargs and "object_refs" not in kwargs:
        kwargs["object_refs"] = ["file--" + oid.split("--", 1)[1]]
    return stix2.v21.ObservedData(
        id=oid,
        first_observed=OBSERVED,
        last_observed=OBSERVED,
        number_observed=1,
        name=name,
        allow_custom=True,
        **kwargs,
    )


def _report(rid, refs):
    return stix2.v21.Report(
        id=rid,
        created=CREATED,
        modified=MODIFIED,
        name="case report " + rid,
        published=PUBLISHED,
        report_types=["threat-report"],
        object_refs=refs,
    )


def _custodian_marking(marking_id=MARKING_ID, name="CUSTODIAN-ONLY EVIDENCE"):
    return stix2.v21.MarkingDefinition(
        id=marking_id,
        created=CREATED,
        name=name,
        definition_type="statement",
        definition=stix2.v21.StatementMarking(
            statement="Custodian team only",
        ),
    )


def _bundle(*objects):
    return stix2.v21.Bundle(objects=list(objects), allow_custom=True)


def _public_json(result):
    return json.dumps(
        result.as_dict(), ensure_ascii=False, sort_keys=True,
    )


def test_three_reports_three_independent_collections():
    bundle = _bundle(
        _observation(OBS_A1, "collection alpha"),
        _observation(OBS_A2, "collection bravo"),
        _observation(OBS_A3, "collection charlie"),
        _report(REPORT_A1, [OBS_A1]),
        _report(REPORT_A2, [OBS_A2]),
        _report(REPORT_A3, [OBS_A3]),
    )

    result = check_independence(bundle, view=PUBLIC_VIEW)

    assert result.report_count == 3
    assert result.referenced_observation_count == 3
    assert result.observation_count == 3
    assert result.independent_sources_lower_bound == 3
    assert result.independent_sources is None
    assert result.closed_component_count == 3
    assert result.open_component_count == 0
    assert len(result.components) == 3
    assert all(not component.open for component in result.components)
    assert {
        component.label for component in result.components
    } == {"collection alpha", "collection bravo", "collection charlie"}
    assert result.edges == []
    assert result.gaps == []

    custodian = check_independence(bundle, view=CUSTODIAN_VIEW)
    assert custodian.independent_sources == 3
    assert custodian.independent_sources_lower_bound == 3
    assert custodian.conservative_lower_bound == 3


def test_two_citations_to_same_hidden_source():
    marking = _custodian_marking()
    hidden = _observation(
        OBS_HIDDEN,
        "sealed original",
        object_marking_refs=[marking.id],
    )
    first = _observation(
        OBS_B1, "first transcript", citation_refs=[OBS_HIDDEN],
    )
    second = _observation(
        OBS_B2, "second transcript", citation_refs=[OBS_HIDDEN],
    )
    bundle = _bundle(
        marking, hidden, first, second,
        _report(REPORT_B1, [OBS_B1]),
        _report(REPORT_B2, [OBS_B2]),
    )

    result = check_independence(bundle, view=PUBLIC_VIEW)

    assert result.report_count == 2
    assert result.referenced_observation_count == 2
    assert result.observation_count == 2
    assert result.independent_sources_lower_bound == 1
    assert result.independent_sources is None
    assert result.conservative_lower_bound == 1
    assert len(result.gaps) == 2
    assert all(gap.target_ref is None for gap in result.gaps)
    assert all(gap.target_redacted for gap in result.gaps)
    assert all(
        gap.reason == "unresolved" for gap in result.gaps
    )
    assert len(result.components) == 1
    component = result.components[0]
    assert component.open
    assert component.observation_refs == [OBS_B1, OBS_B2]
    assert component.label is None
    assert component.unresolved_ref_count == 1

    serialized = _public_json(result)
    assert OBS_HIDDEN not in serialized
    assert "sealed original" not in serialized
    assert marking.id not in serialized
    assert OBS_HIDDEN not in repr(result)
    assert OBS_HIDDEN not in repr(component)

    custodian = check_independence(bundle, view=CUSTODIAN_VIEW)
    assert custodian.independent_sources == 1
    assert custodian.independent_sources_lower_bound == 1
    assert len(custodian.components) == 1
    assert set(custodian.components[0].observation_refs) == {
        OBS_B1, OBS_B2, OBS_HIDDEN,
    }
    assert len(custodian.edges) == 2
    assert custodian.gaps == []


def test_public_view_is_blind_to_hidden_existence():
    visible = _observation(
        OBS_B1, "relay transcript", citation_refs=[OBS_HIDDEN],
    )
    missing_bundle = _bundle(visible)

    marking = _custodian_marking()
    hidden = _observation(
        OBS_HIDDEN,
        "sealed original",
        object_marking_refs=[marking.id],
    )
    hidden_bundle = _bundle(visible, marking, hidden)

    missing_result = check_independence(missing_bundle)
    hidden_result = check_independence(hidden_bundle)

    assert _public_json(missing_result) == _public_json(hidden_result)
    assert missing_result.independent_sources_lower_bound == 1
    assert hidden_result.independent_sources_lower_bound == 1
    assert len(missing_result.gaps) == 1
    assert len(hidden_result.gaps) == 1


def test_public_view_ignores_uncited_hidden_objects():
    visible = _observation(OBS_A1, "collection alpha")
    marking = _custodian_marking()
    uncited_hidden = _observation(
        OBS_HIDDEN,
        "sealed original",
        object_marking_refs=[marking.id],
    )

    without_hidden = check_independence(_bundle(visible))
    with_hidden = check_independence(
        _bundle(visible, marking, uncited_hidden),
    )

    assert _public_json(without_hidden) == _public_json(with_hidden)
    assert without_hidden.observation_count == 1
    assert with_hidden.observation_count == 1


def test_mutual_citations_and_missing_reference_gap():
    first = _observation(
        OBS_C1, "cycle member one", citation_refs=[OBS_C2],
    )
    second = _observation(
        OBS_C2, "cycle member two", citation_refs=[OBS_C1],
    )
    lone = _observation(
        OBS_C3, "lone member", citation_refs=[OBS_MISSING],
    )

    result = check_independence([first, second, lone])

    assert len(result.components) == 2
    assert result.independent_sources_lower_bound == 2
    assert result.conservative_lower_bound == 1
    assert result.closed_plus_open_bound == 2
    cycle = next(
        component for component in result.components
        if len(component.observation_refs) == 2
    )
    assert cycle.observation_refs == [OBS_C1, OBS_C2]
    assert not cycle.open
    lone_component = next(
        component for component in result.components
        if component.observation_refs == [OBS_C3]
    )
    assert lone_component.open
    assert len(result.edges) == 2
    assert len(result.gaps) == 1
    assert result.gaps[0].target_ref is None
    assert result.gaps[0].reason == "unresolved"

    custodian = check_independence(
        [first, second, lone], view=CUSTODIAN_VIEW,
    )
    assert custodian.independent_sources == 2
    assert custodian.conservative_lower_bound == 2
    assert custodian.closed_plus_open_bound == 2
    assert len(custodian.gaps) == 1
    assert custodian.gaps[0].target_ref == OBS_MISSING
    assert custodian.gaps[0].reason == "unresolved"


def test_caller_registered_relationship_and_explicit_group():
    first = _observation(OBS_D1, "first")
    second = _observation(OBS_D2, "second")
    third = _observation(OBS_D3, "third")
    relationship = stix2.v21.Relationship(
        id=RELATIONSHIP_D1,
        created=CREATED,
        modified=MODIFIED,
        source_ref=OBS_D1,
        relationship_type="derived-from",
        target_ref=OBS_D2,
    )

    by_relationship = check_independence(
        [first, second, third, relationship],
    )
    assert len(by_relationship.components) == 2
    assert {
        (edge.kind, edge.detail) for edge in by_relationship.edges
    } == {(COLLECTION_RELATIONSHIP, "derived-from")}

    by_group = check_independence(
        [first, second, third],
        collection_relations={OBS_D1: "collection-one", OBS_D2: "collection-one"},
    )
    assert len(by_group.components) == 2
    assert by_group.gaps == []

    by_reverse_group = check_independence(
        [first, second, third],
        collection_relations={"collection-two": [OBS_D1, OBS_D2]},
    )
    assert len(by_reverse_group.components) == 2

    by_pair = check_independence(
        [first, second, third],
        collection_relations=[(OBS_D1, OBS_D2)],
    )
    assert len(by_pair.components) == 2
    assert {
        (edge.kind, edge.detail) for edge in by_pair.edges
    } == {(CALLER_RELATION, "caller-registered")}


def test_external_reference_citation():
    first = _observation(OBS_D1, "derived")
    second = _observation(OBS_D2, "upstream")
    third = _observation(
        OBS_D3,
        "external citation",
        external_references=[
            {"source_name": "case", "external_id": OBS_D2},
        ],
    )

    result = check_independence([first, second, third])

    assert len(result.components) == 2
    assert {
        (edge.kind, edge.detail) for edge in result.edges
    } == {(SELF_CITATION, "external_references.external_id")}


def test_explicit_restricted_marking_and_memory_source():
    marking = stix2.v21.MarkingDefinition(
        id=MARKING_ID,
        created=CREATED,
        definition_type="statement",
        definition=stix2.v21.StatementMarking(statement="Restricted"),
    )
    hidden = _observation(
        OBS_HIDDEN, "sealed", object_marking_refs=[marking.id],
    )
    copy = _observation(
        OBS_B1, "copy", citation_refs=[OBS_HIDDEN],
    )
    source = stix2.MemorySource(stix_data=[marking, hidden, copy])

    result = check_independence(
        source, restricted_markings=[marking.id],
    )
    assert result.independent_sources_lower_bound == 1
    assert len(result.gaps) == 1
    assert result.gaps[0].target_ref is None
    assert result.gaps[0].reason == "unresolved"

    custodian = check_independence(
        source,
        view=CUSTODIAN_VIEW,
        restricted_markings=[marking.id],
    )
    assert custodian.independent_sources == 1
    assert custodian.gaps == []


def test_versioned_observation_uses_latest_visible_version():
    old = _observation(
        OBS_A1,
        "old version",
        modified="2026-01-01T00:00:00.000Z",
    )
    new = _observation(
        OBS_A1,
        "new version",
        modified="2026-02-01T00:00:00.000Z",
        citation_refs=[OBS_A2],
    )
    other = _observation(OBS_A2, "other collection")

    result = check_independence([old, new, other])

    assert result.observation_count == 2
    assert len(result.components) == 1
    assert result.components[0].observation_refs == [OBS_A1, OBS_A2]


def test_mapping_json_and_checker_inputs():
    first = _observation(OBS_A1, "first")
    second = _observation(OBS_A2, "second")

    from_mapping = check_independence(
        {OBS_A1: first, OBS_A2: second},
    )
    from_json = check_independence(_public_json_bundle([first, second]))
    from_checker = IndependenceChecker(view=PUBLIC_VIEW).check(
        [first, second],
    )

    assert from_mapping.independent_sources_lower_bound == 2
    assert from_json.independent_sources_lower_bound == 2
    assert from_checker.independent_sources_lower_bound == 2


def _public_json_bundle(objects):
    bundle = _bundle(*objects)
    return bundle.serialize()


def test_gap_redaction_is_deterministic():
    hidden_a = "observed-data--00000000-0000-4000-8000-000000000051"
    hidden_b = "observed-data--00000000-0000-4000-8000-000000000052"
    visible = _observation(
        OBS_B1,
        "multi citation",
        citation_refs=[hidden_b, hidden_a],
    )

    first = check_independence([visible])
    second = check_independence([visible])

    assert _public_json(first) == _public_json(second)
    assert len(first.gaps) == 2


def test_invalid_view_raises():
    with pytest.raises(ValueError):
        check_independence(
            [_observation(OBS_A1, "solo")], view="insider",
        )


def test_hidden_relationship_target_is_redacted():
    marking = _custodian_marking()
    hidden = _observation(
        OBS_HIDDEN,
        "sealed relationship target",
        object_marking_refs=[marking.id],
    )
    visible = _observation(OBS_B1, "visible relay")
    relationship = stix2.v21.Relationship(
        id=RELATIONSHIP_D1,
        created=CREATED,
        modified=MODIFIED,
        source_ref=OBS_B1,
        relationship_type="derived-from",
        target_ref=OBS_HIDDEN,
    )

    result = check_independence(
        [marking, hidden, visible, relationship],
    )

    assert len(result.gaps) == 1
    assert result.gaps[0].target_ref is None
    assert result.gaps[0].reason == "unresolved"
    serialized = _public_json(result)
    assert OBS_HIDDEN not in serialized
    assert "sealed relationship target" not in serialized

    custodian = check_independence(
        [marking, hidden, visible, relationship],
        view=CUSTODIAN_VIEW,
    )
    assert custodian.independent_sources == 1
    assert custodian.gaps == []
    assert len(custodian.edges) == 1


def test_caller_supplied_citation_merges_observations():
    first = _observation(OBS_D1, "first")
    second = _observation(OBS_D2, "second")

    result = check_independence(
        [first, second],
        citations={OBS_D1: [OBS_D2]},
    )

    assert len(result.components) == 1
    assert result.independent_sources_lower_bound == 1
    assert {
        (edge.kind, edge.detail) for edge in result.edges
    } == {(SELF_CITATION, "caller-citation")}


def test_public_result_exposes_stricter_bound_with_hidden_incoming_edges():
    marking = _custodian_marking()
    hidden = _observation(
        OBS_HIDDEN,
        "sealed connector",
        object_marking_refs=[marking.id],
        citation_refs=[OBS_A1],
    )
    independent = _observation(OBS_A1, "closed independent")
    relay = _observation(
        OBS_B1, "relay to sealed connector", citation_refs=[OBS_HIDDEN],
    )
    objects = [marking, hidden, independent, relay]

    public = check_independence(objects)
    assert public.independent_sources_lower_bound == 2
    assert public.conservative_lower_bound == 1
    assert public.closed_plus_open_bound == 2
    assert len(public.components) == 2

    custodian = check_independence(objects, view=CUSTODIAN_VIEW)
    assert custodian.independent_sources == 1


def test_public_component_label_does_not_read_restricted_name():
    hidden_file_id = "file--00000000-0000-4000-8000-000000000088"
    marking = _custodian_marking()
    hidden_file = stix2.v21.File(
        id=hidden_file_id,
        name="sealed file name",
        object_marking_refs=[marking.id],
    )
    visible = stix2.v21.ObservedData(
        id=OBS_A1,
        created=CREATED,
        modified=MODIFIED,
        first_observed=OBSERVED,
        last_observed=OBSERVED,
        number_observed=1,
        object_refs=[hidden_file_id],
        allow_custom=True,
    )
    objects = [marking, hidden_file, visible]

    public = check_independence(objects)
    assert public.components[0].label is None
    assert "sealed file name" not in _public_json(public)

    custodian = check_independence(objects, view=CUSTODIAN_VIEW)
    assert custodian.components[0].label == "sealed file name"


def test_report_reference_to_hidden_observation_is_not_counted_publicly():
    report = _report(REPORT_A1, [OBS_HIDDEN])
    missing = check_independence(_bundle(report))

    marking = _custodian_marking()
    hidden = _observation(
        OBS_HIDDEN,
        "sealed report subject",
        object_marking_refs=[marking.id],
    )
    hidden_view = check_independence(
        _bundle(report, marking, hidden),
    )

    assert _public_json(missing) == _public_json(hidden_view)
    assert missing.report_count == 1
    assert missing.referenced_observation_count == 0
    assert missing.observation_count == 0
    assert missing.independent_sources_lower_bound == 0

    custodian = check_independence(
        _bundle(report, marking, hidden),
        view=CUSTODIAN_VIEW,
    )
    assert custodian.referenced_observation_count == 1
    assert custodian.independent_sources == 1


def test_two_citations_to_same_missing_source_are_one_component():
    first = _observation(
        OBS_B1, "first missing citation", citation_refs=[OBS_MISSING],
    )
    second = _observation(
        OBS_B2, "second missing citation", citation_refs=[OBS_MISSING],
    )

    public = check_independence([first, second])
    assert len(public.components) == 1
    assert public.components[0].open
    assert public.components[0].observation_refs == [OBS_B1, OBS_B2]
    assert public.independent_sources_lower_bound == 1
    assert len(public.gaps) == 2
    assert all(gap.target_ref is None for gap in public.gaps)

    custodian = check_independence(
        [first, second], view=CUSTODIAN_VIEW,
    )
    assert len(custodian.components) == 1
    assert custodian.independent_sources == 1
    assert len(custodian.gaps) == 2
    assert all(gap.target_ref == OBS_MISSING for gap in custodian.gaps)


def test_three_reports_two_relays_and_one_independent_collection():
    marking = _custodian_marking()
    hidden = _observation(
        OBS_HIDDEN,
        "sealed shared original",
        object_marking_refs=[marking.id],
    )
    first = _observation(
        OBS_B1, "first relay", citation_refs=[OBS_HIDDEN],
    )
    second = _observation(
        OBS_B2, "second relay", citation_refs=[OBS_HIDDEN],
    )
    independent = _observation(OBS_A1, "independent collection")
    objects = [
        marking,
        hidden,
        first,
        second,
        independent,
        _report(REPORT_A1, [OBS_B1]),
        _report(REPORT_A2, [OBS_B2]),
        _report(REPORT_A3, [OBS_A1]),
    ]

    public = check_independence(objects)
    assert public.report_count == 3
    assert public.referenced_observation_count == 3
    assert public.observation_count == 3
    assert public.independent_sources_lower_bound == 2
    assert public.conservative_lower_bound == 1
    assert public.closed_plus_open_bound == 2
    assert public.closed_component_count == 1
    assert public.open_component_count == 1
    assert len(public.components) == 2
    assert len(public.gaps) == 2
    assert all(gap.target_ref is None for gap in public.gaps)

    serialized = _public_json(public)
    assert OBS_HIDDEN not in serialized
    assert "sealed shared original" not in serialized

    custodian = check_independence(objects, view=CUSTODIAN_VIEW)
    assert custodian.report_count == 3
    assert custodian.referenced_observation_count == 3
    assert custodian.observation_count == 4
    assert custodian.independent_sources == 2
    assert custodian.gaps == []

