# Tests for embargo-aware STIX delivery previews.

import json
from pathlib import Path

import stix2
from stix2.delivery import preview_delivery, preview_transition

CREATED = "2026-01-01T00:00:00Z"
AT = "2027-06-01T00:00:00Z"

SRC_ID = "identity--aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
TGT_ID = "identity--bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
REL_ID = "relationship--cccccccc-cccc-4ccc-8ccc-cccccccccccc"


def _identity(obj_id, name, **props):
    values = {
        "id": obj_id,
        "created": props.pop("created", CREATED),
        "modified": props.pop("modified", props.get("created", CREATED)),
        "name": name,
    }
    values.update(props)
    return stix2.Identity(allow_custom=True, **values)


def _relationship(source, target, **props):
    values = {
        "id": props.pop("id", REL_ID),
        "created": props.pop("created", CREATED),
        "modified": props.pop("modified", props.get("created", CREATED)),
        "relationship_type": props.pop("relationship_type", "related-to"),
        "source_ref": source,
        "target_ref": target,
    }
    values.update(props)
    return stix2.Relationship(allow_custom=True, **values)


def test_relationship_release_after_both_endpoints_is_denied_then_released():
    source = _identity(SRC_ID, "Source")
    target = _identity(TGT_ID, "Target", x_embargo_until="2027-01-01T00:00:00Z")
    rel = _relationship(SRC_ID, TGT_ID, x_embargo_until="2027-02-01T00:00:00Z")

    before = preview_delivery(
        [source, target, rel], receiving_categories=["press"], at="2027-01-15T00:00:00Z"
    )
    assert before.by_id[SRC_ID].allowed
    assert before.by_id[TGT_ID].allowed
    assert before.by_id[REL_ID].blocked

    permit = before.permits[REL_ID]
    assert permit.status == "denied"
    assert permit.effect == "deny"
    assert permit.outlasts_endpoints
    assert permit.still_blocks_publication
    assert permit.endpoint_release_at == "2027-01-01T00:00:00Z"
    assert "publication remains blocked" in permit.reason

    after = preview_delivery([source, target, rel], at="2027-02-01T00:00:00Z")
    assert after.by_id[REL_ID].allowed
    assert after.permits[REL_ID].status == "granted"
    assert after.permits[REL_ID].outlasts_endpoints
    assert not after.permits[REL_ID].still_blocks_publication


def test_receiving_category_restriction_blocks_object_and_endpoint_relationship():
    source = _identity(SRC_ID, "Source", x_release_categories=["partner"])
    target = _identity(TGT_ID, "Target")
    rel = _relationship(SRC_ID, TGT_ID)

    preview = preview_delivery([source, target, rel], receiving_categories=["press"], at=AT)
    assert preview.by_id[SRC_ID].blocked
    assert preview.by_id[TGT_ID].allowed
    assert preview.by_id[REL_ID].blocked
    assert any(
        "not allowed by object-category" in reason
        for reason in preview.by_id[SRC_ID].reasons
    )
    assert preview.by_id[REL_ID].blocked_by == [SRC_ID]


def test_version_selection_and_declared_source_version_are_consistent():
    indicator_id = "indicator--dddddddd-dddd-4ddd-8ddd-dddddddddddd"
    v1 = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": indicator_id,
        "created": CREATED,
        "modified": CREATED,
        "name": "version one",
        "pattern": "[file:size > 0]",
        "pattern_type": "stix",
        "valid_from": CREATED,
    }
    v2 = dict(v1, modified="2026-06-01T00:00:00Z", name="version two")
    target = _identity(TGT_ID, "Target")

    latest = preview_delivery([v1, v2, target], at="2026-07-01T00:00:00Z")
    assert latest.by_id[indicator_id].version == "2026-06-01T00:00:00Z"

    pinned_rel = _relationship(
        indicator_id,
        TGT_ID,
        x_source_version="2026-01-01T00:00:00Z",
    )
    pinned = preview_delivery([v1, v2, target, pinned_rel], at="2026-07-01T00:00:00Z")
    assert pinned.by_id[indicator_id].version == "2026-01-01T00:00:00Z"
    assert pinned.by_id[REL_ID].source_version == "2026-01-01T00:00:00Z"
    assert pinned.by_id[REL_ID].source_version_declared == CREATED
    assert "declared=" in pinned.by_id[REL_ID].version_note
    assert pinned.to_bundle().get_obj(indicator_id)[0]["name"] == "version one"


def test_cross_spec_version_reference_is_described():
    source = stix2.v20.Identity(
        id=SRC_ID, created=CREATED, name="v20 source", identity_class="organization"
    )
    target = _identity(TGT_ID, "v21 target")
    rel = _relationship(SRC_ID, TGT_ID)

    preview = preview_delivery([source, target, rel], at=AT)
    item = preview.by_id[REL_ID]
    assert item.source_spec_version == "2.0"
    assert item.target_spec_version == "2.1"
    assert item.cross_version_reference
    assert "cross-version reference" in item.version_note


def test_temporary_extension_revises_only_affected_items():
    source = _identity(SRC_ID, "Source")
    target = _identity(TGT_ID, "Target")
    rel = _relationship(SRC_ID, TGT_ID)
    base = preview_delivery([source, target, rel], at=AT)

    extended = base.extend_embargo(
        REL_ID,
        "2027-12-01T00:00:00Z",
        reason="case review",
        now="2027-06-02T00:00:00Z",
    )
    assert extended.revision == 2
    assert extended.updated_ids == [REL_ID]
    assert extended.by_id[REL_ID].revision == 2
    assert extended.by_id[REL_ID].blocked
    assert extended.by_id[SRC_ID].revision == 1
    assert extended.by_id[TGT_ID].revision == 1
    assert any(
        "temporary embargo extension" in note
        for note in extended.by_id[REL_ID].extension_notes
    )
    assert base.by_id[REL_ID].revision == 1
    assert base.by_id[REL_ID].allowed

    source_extended = extended.extend_embargo(
        SRC_ID,
        "2027-11-01T00:00:00Z",
        reason="source review",
        now="2027-06-03T00:00:00Z",
    )
    assert source_extended.revision == 3
    assert source_extended.updated_ids == sorted([SRC_ID, REL_ID])
    assert source_extended.by_id[SRC_ID].revision == 2
    assert source_extended.by_id[TGT_ID].revision == 1
    assert source_extended.by_id[REL_ID].revision == 3
    assert source_extended.change_log[-1]["parent_revision"] == 2

    restored = source_extended.clear_extension(SRC_ID)
    assert restored.by_id[SRC_ID].allowed
    assert restored.change_log[-1]["until"] is None


def test_cycle_has_deterministic_direction_and_members():
    a_id = "identity--11111111-1111-4111-8111-111111111111"
    b_id = "identity--22222222-2222-4222-8222-222222222222"
    r1_id = "relationship--33333333-3333-4333-8333-333333333333"
    r2_id = "relationship--44444444-4444-4444-8444-444444444444"
    a = _identity(a_id, "A")
    b = _identity(b_id, "B")
    r1 = _relationship(a_id, b_id, id=r1_id)
    r2 = _relationship(b_id, a_id, id=r2_id)

    preview = preview_delivery([a, b, r1, r2], at=AT)
    assert len(preview.cycles) == 1
    cycle = preview.cycles[0]
    assert cycle["direction"] == "source_ref->target_ref"
    assert cycle["path"] == [a_id, b_id, a_id]
    assert cycle["edges"][0]["relationship_id"] == r1_id
    assert cycle["edges"][1]["relationship_id"] == r2_id
    assert cycle["members"] == sorted([r1_id, r2_id])
    assert cycle["released"] is True
    for rel_id in (r1_id, r2_id):
        item = preview.by_id[rel_id]
        assert item.cycle_id == cycle["id"]
        assert item.cycle_path == cycle["path"]
        assert item.cycle_direction == "source_ref->target_ref"
        assert item.cycle_next_ref == item.target_ref


def test_before_and_after_transition_writes_two_previews(tmp_path):
    source = _identity(SRC_ID, "Source")
    target = _identity(TGT_ID, "Target")
    rel = _relationship(SRC_ID, TGT_ID, x_embargo_until="2027-02-01T00:00:00Z")

    transition = preview_transition(
        [source, target, rel],
        receiving_categories=["press"],
        embargo_until="2027-02-01T00:00:00Z",
        before="2027-01-31T23:59:59Z",
        after="2027-02-01T00:00:00Z",
    )
    assert transition.before.by_id[REL_ID].blocked
    assert transition.after.by_id[REL_ID].allowed
    assert transition.changed_ids == [REL_ID]
    assert transition.newly_released_ids == [REL_ID]
    assert transition.still_blocked_ids == []

    before_path, after_path = transition.save(tmp_path, stem="case-embargo")
    before_data = json.loads(Path(before_path).read_text())
    after_data = json.loads(Path(after_path).read_text())
    assert before_data["type"] == "delivery-preview"
    assert after_data["type"] == "delivery-preview"
    assert REL_ID in before_data["blocked_ids"]
    assert REL_ID in after_data["released_ids"]


def test_restricted_case_has_independent_embargo():
    source = _identity(SRC_ID, "Source")
    target = _identity(TGT_ID, "Target")
    case_id = "x-case--55555555-5555-4555-8555-555555555555"
    rel = _relationship(SRC_ID, TGT_ID, x_restricted_case_refs=[case_id])

    early = preview_delivery(
        [source, target, rel],
        at="2027-02-01T00:00:00Z",
        case_embargoes={case_id: "2027-03-01T00:00:00Z"},
    )
    assert early.by_id[SRC_ID].allowed
    assert early.by_id[TGT_ID].allowed
    assert early.by_id[REL_ID].blocked
    assert early.by_id[REL_ID].case_refs == [case_id]
    assert "restricted case" in early.by_id[REL_ID].release_at_property

    late = preview_delivery(
        [source, target, rel],
        at="2027-03-01T00:00:00Z",
        case_embargoes={case_id: "2027-03-01T00:00:00Z"},
    )
    assert late.by_id[REL_ID].allowed


def test_unknown_endpoint_blocks_relationship_and_records_dependency():
    target = _identity(TGT_ID, "Target")
    rel = _relationship(SRC_ID, TGT_ID)

    preview = preview_delivery([target, rel], at=AT)
    item = preview.by_id[REL_ID]
    assert item.blocked
    assert item.blocked_by == [SRC_ID]
    assert any("not present" in reason for reason in item.reasons)


def test_marking_definition_can_carry_embargo_policy():
    marking_id = "marking-definition--66666666-6666-4666-8666-666666666666"
    marking = stix2.MarkingDefinition(
        id=marking_id,
        created=CREATED,
        allow_custom=True,
        definition_type="statement",
        definition={"statement": "partner embargo"},
        x_embargo_until="2027-04-01T00:00:00Z",
        x_release_categories=["partner"],
    )
    source = _identity(SRC_ID, "Source", object_marking_refs=[marking_id])
    target = _identity(TGT_ID, "Target")
    rel = _relationship(SRC_ID, TGT_ID)

    early = preview_delivery(
        [marking, source, target, rel],
        receiving_categories=["partner"],
        at="2027-03-01T00:00:00Z",
    )
    assert early.by_id[SRC_ID].blocked
    assert any("embargoed until" in reason for reason in early.by_id[SRC_ID].reasons)

    late = preview_delivery(
        [marking, source, target, rel],
        receiving_categories=["partner"],
        at="2027-04-01T00:00:00Z",
    )
    assert late.by_id[SRC_ID].allowed
    assert late.by_id[REL_ID].allowed


def test_to_dict_bundle_and_serialization_are_practical_for_a_backend():
    source = _identity(SRC_ID, "Source")
    target = _identity(TGT_ID, "Target")
    rel = _relationship(SRC_ID, TGT_ID)
    preview = preview_delivery([source, target, rel], at=AT)

    data = preview.to_dict()
    assert data["released_ids"] == sorted([SRC_ID, TGT_ID, REL_ID])
    assert data["blocked_ids"] == []
    assert data["released"]["ids"] == data["released_ids"]
    assert data["revision"] == 1
    assert data["version_notes"]
    assert {obj["id"] for obj in data["bundle"]["objects"]} == {SRC_ID, TGT_ID, REL_ID}
    assert json.loads(preview.serialize())["type"] == "delivery-preview"
    assert len(preview.to_bundle().objects) == 3


def test_positional_backend_call_and_in_band_case_policy():
    source = _identity(SRC_ID, "Source")
    target = _identity(TGT_ID, "Target")
    case_id = "incident--99999999-9999-4999-8999-999999999999"
    case = stix2.Incident(
        id=case_id,
        created=CREATED,
        modified=CREATED,
        name="Restricted case",
        allow_custom=True,
        x_embargo_until="2027-08-01T00:00:00Z",
    )
    rel = _relationship(SRC_ID, TGT_ID, x_restricted_cases=[case_id])
    bundle = stix2.Bundle(objects=[source, target, case, rel], allow_custom=True)

    preview = preview_delivery(bundle, ["press"], "2027-07-01T00:00:00Z")
    assert preview.delivery_at == "2027-07-01T00:00:00Z"
    assert preview.by_id[REL_ID].blocked
    assert preview.by_id[REL_ID].case_refs == [case_id]
    assert preview.by_id[REL_ID].release_at == "2027-08-01T00:00:00Z"

    released = preview_delivery(bundle, ["press"], "2027-08-01T00:00:00Z")
    assert released.by_id[REL_ID].allowed


def test_class_level_transition_and_request_mapping():
    source = _identity(SRC_ID, "Source")
    target = _identity(TGT_ID, "Target")
    rel = _relationship(SRC_ID, TGT_ID, x_embargo_until="2027-02-01T00:00:00Z")
    request = {
        "objects": [source, target, rel],
        "receiving_categories": ["press"],
        "embargo_until": "2027-02-01T00:00:00Z",
    }

    preview = stix2.DeliveryPreview(request)
    assert preview.by_id[REL_ID].blocked

    transition = stix2.DeliveryPreview.transition(request)
    assert not transition.before.by_id[REL_ID].allowed
    assert transition.after.by_id[REL_ID].allowed
    assert transition["before"].delivery_at < transition["after"].delivery_at
    assert transition.before_preview is transition.before
