import pytest

import stix2
from stix2.provenance import (
    CUSTODIAN_VIEW,
    PUBLIC_VIEW,
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
MISSING = "observed-data--00000000-0000-4000-8000-000000000099"


def _observation(oid, name, **kwargs):
    return stix2.v21.ObservedData(
        id=oid,
        first_observed="2026-01-01T00:00:00Z",
        last_observed="2026-01-01T00:00:00Z",
        number_observed=1,
        objects={"0": {"type": "file", "name": name}},
        allow_custom=True,
        **kwargs,
    )


def _report(rid, refs):
    return stix2.v21.Report(
        id=rid,
        name="case report " + rid,
        published="2026-01-02T00:00:00Z",
        report_types="other",
        object_refs=refs,
    )


@pytest.fixture


def independent_collections_bundle():
    a1 = _observation(OBS_A1, "collection alpha")
    a2 = _observation(OBS_A2, "collection bravo")
    a3 = _observation(OBS_A3, "collection charlie")
    return [
        a1, a2, a3,
        _report("report--00000000-0000-4000-8000-000000000011", [OBS_A1]),
        _report("report--00000000-0000-4000-8000-000000000012", [OBS_A2]),
        _report("report--00000000-0000-4000-8000-000000000013", [OBS_A3]),
    ]


@pytest.fixture


def shared_hidden_source_bundle():
    custodian_marking = stix2.v21.MarkingDefinition(
        definition_type="statement",
        name="CUSTODIAN-ONLY EVIDENCE",
        definition=stix2.v21.StatementMarking(
            statement="Custodian team only",
        ),
    )
    hidden = _observation(
        OBS_HIDDEN, "original seizure record",
        object_marking_refs=[custodian_marking.id],
    )
    first_copy = _observation(OBS_B1, "first transcript", citation_refs=[OBS_HIDDEN])
    second_copy = _observation(OBS_B2, "second transcript", citation_refs=[OBS_HIDDEN])
    return [
        custodian_marking, hidden, first_copy, second_copy,
        _report("report--00000000-0000-4000-8000-000000000014", [OBS_B1]),
        _report("report--00000000-0000-4000-8000-000000000015", [OBS_B2]),
    ]


def test_three_reports_three_independent_collections(independent_collections_bundle):
    result = check_independence(independent_collections_bundle, view=PUBLIC_VIEW)

    assert result.report_count == 3
    assert result.referenced_observation_count == 3
    assert result.independent_sources_lower_bound == 3
    assert result.independent_sources is None
    assert len(result.components) == 3
    assert all(not component.open for component in result.components)
    assert result.gaps == []
    assert {
        component.label for component in result.components
    } == {"collection alpha", "collection bravo", "collection charlie"}


def test_shared_hidden_source_public_view_does_not_disclose(shared_hidden_source_bundle):
    result = check_independence(shared_hidden_source_bundle, view=PUBLIC_VIEW)

    assert result.report_count == 2
    assert result.referenced_observation_count == 2
    assert result.independent_sources_lower_bound == 1
    assert result.independent_sources is None
    assert len(result.gaps) == 2
    assert all(gap.target_ref is None for gap in result.gaps)
    assert all(gap.reason == "restricted" for gap in result.gaps)
    assert all(component.open for component in result.components)
    assert all(component.label is None for component in result.components)

    serialized = str(result.as_dict())
    assert OBS_HIDDEN not in serialized
    assert "original seizure record" not in serialized
    assert all(OBS_HIDDEN not in str(edge.as_dict()) for edge in result.edges)


def test_shared_hidden_source_custodian_view_merges_copies(shared_hidden_source_bundle):
    result = check_independence(shared_hidden_source_bundle, view=CUSTODIAN_VIEW)

    assert result.independent_sources == 1
    assert result.independent_sources_lower_bound == 1
    assert len(result.components) == 1
    assert result.gaps == []
    member_ids = result.components[0].observation_refs
    assert OBS_HIDDEN in member_ids
    assert OBS_B1 in member_ids and OBS_B2 in member_ids


def test_mutual_citations_form_one_component_and_gap_is_reported():
    first = _observation(OBS_C1, "cycle member one", citation_refs=[OBS_C2])
    second = _observation(OBS_C2, "cycle member two", citation_refs=[OBS_C1])
    lone = _observation(OBS_C3, "lone member", citation_refs=[MISSING])

    result = check_independence([first, second, lone], view=PUBLIC_VIEW)

    assert len(result.components) == 2
    assert result.independent_sources_lower_bound == 2
    cycle = next(
        component for component in result.components
        if len(component.observation_refs) == 2
    )
    assert cycle.observation_refs == [OBS_C1, OBS_C2]
    assert not cycle.open
    lone_component = next(
        component for component in result.components
        if len(component.observation_refs) == 1
    )
    assert lone_component.open
    assert len(result.edges) == 2
    assert len(result.gaps) == 1
    assert result.gaps[0].target_ref == MISSING
    assert result.gaps[0].reason == "unresolved"


def test_caller_registered_relationship_and_external_reference():
    first = _observation("observed-data--00000000-0000-4000-8000-000000000031", "derived")
    second = _observation("observed-data--00000000-0000-4000-8000-000000000032", "upstream")
    third = _observation("observed-data--00000000-0000-4000-8000-000000000033", "external upstream")
    fourth = _observation(
        "observed-data--00000000-0000-4000-8000-000000000034",
        "external citation",
        external_references=[{"source_name": "case", "external_id": third.id}],
    )
    relationship = stix2.v21.Relationship(
        source_ref=first.id,
        relationship_type="derived-from",
        target_ref=second.id,
        allow_custom=True,
    )

    result = check_independence([first, second, third, fourth, relationship])

    assert len(result.components) == 2
    edge_keys = {(edge.kind, edge.detail) for edge in result.edges}
    assert ("collection-relationship", "derived-from") in edge_keys
    assert ("self-citation", "external_references.external_id") in edge_keys


def test_explicit_restricted_marking_and_memory_source():
    marking = stix2.v21.MarkingDefinition(
        id="marking-definition--00000000-0000-4000-8000-000000000077",
        definition_type="statement",
        definition=stix2.v21.StatementMarking(statement="Restricted"),
    )
    hidden = _observation(OBS_HIDDEN, "sealed", object_marking_refs=[marking.id])
    copy = _observation(OBS_B1, "copy", citation_refs=[OBS_HIDDEN])
    source = stix2.MemorySource(stix_data=[marking, hidden, copy])

    result = check_independence(
        source, restricted_markings=[marking.id],
    )

    assert result.independent_sources_lower_bound == 1
    assert result.gaps[0].target_ref is None
    assert result.gaps[0].reason == "restricted"


def test_lower_bound_counts_closed_components_plus_one_for_open_ones():
    independent_one = _observation(OBS_A1, "independent one")
    independent_two = _observation(OBS_A2, "independent two")
    open_member = _observation(OBS_C3, "open member", citation_refs=[MISSING])

    result = check_independence([independent_one, independent_two, open_member])

    assert len(result.components) == 3
    assert result.independent_sources_lower_bound == 3
    assert sum(1 for component in result.components if component.open) == 1


def test_invalid_view_raises():
    observation = _observation(OBS_A1, "solo")
    with pytest.raises(ValueError):
        check_independence([observation], view="insider")
