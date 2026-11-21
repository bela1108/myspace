import json

import pytest
import simplejson

import stix2


BUNDLE_ID = "bundle--aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
WHITE_ID = "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
RED_ID = "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed"

INDICATOR_OK_ID = "indicator--11111111-1111-4111-8111-111111111111"
MALWARE_OK_ID = "malware--22222222-2222-4222-8222-222222222222"
MALWARE_REQUIRED_ID = "malware--33333333-3333-4333-8333-333333333333"
INDICATOR_RED_ID = "indicator--44444444-4444-4444-8444-444444444444"
INDICATOR_NESTED_REQUIRED_ID = "indicator--88888888-8888-4888-8888-888888888888"
REL_KEEP_ID = "relationship--55555555-5555-4555-8555-555555555555"
REL_REQUIRED_ID = "relationship--66666666-6666-4666-8666-666666666666"
REL_RED_ID = "relationship--77777777-7777-4777-8777-777777777777"
REL_NESTED_ID = "relationship--99999999-9999-4999-8999-999999999999"

TIMESTAMP = "2024-01-01T00:00:00.000Z"


def _marking(marking_id, name, color):
    return {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": marking_id,
        "created": "2017-01-20T00:00:00.000Z",
        "definition_type": "tlp",
        "name": name,
        "definition": {"tlp": color},
    }


def _indicator(indicator_id, **extra):
    obj = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": indicator_id,
        "created": TIMESTAMP,
        "modified": TIMESTAMP,
        "name": "Indicator " + indicator_id[-4:],
        "pattern": "[ipv4-addr:value = '198.51.100.1']",
        "pattern_type": "stix",
        "valid_from": TIMESTAMP,
        "object_marking_refs": [WHITE_ID],
    }
    obj.update(extra)
    return obj


def _malware(malware_id, name, **extra):
    obj = {
        "type": "malware",
        "spec_version": "2.1",
        "id": malware_id,
        "created": TIMESTAMP,
        "modified": TIMESTAMP,
        "name": name,
        "is_family": False,
        "object_marking_refs": [WHITE_ID],
    }
    obj.update(extra)
    return obj


def _relationship(rel_id, source_ref, target_ref, **extra):
    obj = {
        "type": "relationship",
        "spec_version": "2.1",
        "id": rel_id,
        "created": TIMESTAMP,
        "modified": TIMESTAMP,
        "relationship_type": "indicates",
        "source_ref": source_ref,
        "target_ref": target_ref,
        "object_marking_refs": [WHITE_ID],
    }
    obj.update(extra)
    return obj


def _synthetic_bundle():
    indicator_ok = _indicator(
        INDICATOR_OK_ID,
        x_items=[
            {"name": "first", "tags": ["a", "b"]},
            {"name": "second", "tags": ["c", "d"]},
            {"name": "third", "tags": ["e", "f"]},
        ],
        granular_markings=[
            {"marking_ref": RED_ID, "selectors": ["x_items.[0]"]},
            {"marking_ref": RED_ID, "selectors": ["x_items.[2].tags.[0]"]},
            {"marking_ref": WHITE_ID, "selectors": ["x_items.[2].tags.[1]"]},
        ],
    )

    # Required top-level property is withheld: the whole object must go.
    malware_required = _malware(
        MALWARE_REQUIRED_ID,
        "Restricted required name",
        granular_markings=[
            {"marking_ref": RED_ID, "selectors": ["is_family"]},
        ],
    )

    # Required nested property is withheld: the whole object must go too.
    indicator_nested_required = _indicator(
        INDICATOR_NESTED_REQUIRED_ID,
        external_references=[
            {"source_name": "restricted source", "url": "https://example.com/restricted"},
        ],
        granular_markings=[
            {"marking_ref": RED_ID, "selectors": ["external_references.[0].source_name"]},
        ],
    )

    indicator_red = _indicator(
        INDICATOR_RED_ID,
        object_marking_refs=[RED_ID],
    )

    return {
        "type": "bundle",
        "id": BUNDLE_ID,
        "objects": [
            _marking(WHITE_ID, "TLP:WHITE", "white"),
            _marking(RED_ID, "TLP:RED", "red"),
            indicator_ok,
            _malware(MALWARE_OK_ID, "Allowed malware"),
            malware_required,
            indicator_nested_required,
            indicator_red,
            # All three relationships share INDICATOR_OK_ID as their source.
            _relationship(REL_KEEP_ID, INDICATOR_OK_ID, MALWARE_OK_ID),
            _relationship(REL_REQUIRED_ID, INDICATOR_OK_ID, MALWARE_REQUIRED_ID),
            _relationship(REL_RED_ID, INDICATOR_OK_ID, INDICATOR_RED_ID),
            _relationship(REL_NESTED_ID, MALWARE_OK_ID, INDICATOR_NESTED_REQUIRED_ID),
        ],
    }


def _walk_refs(value, path=()):
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = path + (key,)
            if key.endswith("_ref") and isinstance(child, str):
                yield child_path, [child]
            elif key.endswith("_refs") and isinstance(child, list):
                yield child_path, child
            else:
                yield from _walk_refs(child, child_path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _walk_refs(child, path + (index,))


def test_export_bundle_filters_markings_and_remaps_list_selectors():
    exported = stix2.export_bundle(
        _synthetic_bundle(), allowed_markings=[WHITE_ID],
    )

    assert isinstance(exported, stix2.Bundle)
    bundle, report = exported
    assert bundle is exported
    assert report is exported.report

    # Re-parse the serialized result exactly as a receiving system would.
    reparsed = stix2.parse(exported.serialize(), allow_custom=True)
    by_id = {obj["id"]: obj for obj in reparsed.objects}

    assert set(by_id) == {
        WHITE_ID, RED_ID, INDICATOR_OK_ID, MALWARE_OK_ID, REL_KEEP_ID,
    }

    indicator = by_id[INDICATOR_OK_ID]
    assert indicator.x_items == [
        {"name": "second", "tags": ["c", "d"]},
        {"name": "third", "tags": ["f"]},
    ]

    # The permitted granular marking used to point at x_items.[2].tags.[1].
    # Both an outer list element and an inner list element were removed, so it
    # must now point at the surviving "f" value.
    assert indicator.granular_markings == [
        {"marking_ref": WHITE_ID, "selectors": ["x_items.[1].tags.[0]"]},
    ]
    assert indicator["x_items"][1]["tags"][0] == "f"

    # Every relationship endpoint in the output resolves to an output object.
    output_ids = set(by_id)
    for obj in reparsed.objects:
        for _, refs in _walk_refs(obj):
            for ref in refs:
                if ref.startswith("marking-definition--"):
                    continue
                if ref in {o["id"] for o in _synthetic_bundle()["objects"]}:
                    assert ref in output_ids

    # The kept relationship still shares the same source as the dropped ones.
    kept_rel = by_id[REL_KEEP_ID]
    assert kept_rel.source_ref == INDICATOR_OK_ID
    assert kept_rel.target_ref == MALWARE_OK_ID

    reasons = {(entry["type"], entry["reason"]) for entry in report.excluded}
    assert ("malware", "required_property_not_permitted") in reasons
    assert ("indicator", "required_property_not_permitted") in reasons
    assert ("indicator", "object_marking_not_permitted") in reasons
    assert ("relationship", "relationship_endpoint_not_available") in reasons
    assert len(report.relationships) == 3

    # Report entries must not identify withheld objects.
    text = exported.serialize() + json.dumps(report, sort_keys=True)
    for withheld_id in (
        MALWARE_REQUIRED_ID, INDICATOR_NESTED_REQUIRED_ID, INDICATOR_RED_ID,
        REL_REQUIRED_ID, REL_RED_ID, REL_NESTED_ID,
    ):
        assert withheld_id not in text


def test_export_bundle_accepts_json_and_alias_keywords():
    source = simplejson.dumps(_synthetic_bundle())
    result = stix2.filter_bundle(source, permissions=[WHITE_ID])
    assert {obj["id"] for obj in result.objects} == {
        WHITE_ID, RED_ID, INDICATOR_OK_ID, MALWARE_OK_ID, REL_KEEP_ID,
    }


def test_export_bundle_tlp_clearance_hierarchy():
    policy = stix2.MarkingPolicy(["TLP:AMBER"])
    assert policy.allows_marking(WHITE_ID)
    assert policy.allows_marking("marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da")
    assert not policy.allows_marking(RED_ID)

    exact = stix2.MarkingPolicy(["TLP:AMBER"], tlp_hierarchy=False)
    assert not exact.allows_marking(WHITE_ID)


def test_export_bundle_requires_permission_source_to_be_consistent():
    with pytest.raises(TypeError):
        stix2.export_bundle(
            _synthetic_bundle(), allowed_markings=[WHITE_ID],
            permissions=[WHITE_ID],
        )
