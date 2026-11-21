"""Tests for injectable parsing contexts (stix2.parsing_context)."""

from collections import OrderedDict

import pytest

import stix2
import stix2.registry
from stix2.exceptions import InvalidValueError, ParseError
from stix2.parsing_context import ExtensionConflict, ParsingContext
from stix2.properties import (
    EnumProperty, IntegerProperty, StringProperty,
)
from stix2.v21.base import _Extension

WIDGET_EXT_TYPE = "x-acme-widget-ext"
EXT_DEF_ID = "extension-definition--9c59fd79-4215-4ba2-920d-3e4f320e1e62"
OTHER_EXT_DEF_ID = "extension-definition--3175b1e2-0b5a-4f0e-9f2a-2d0f8a2f9c01"


# Two synthetic partner extensions sharing one name but following different
# conventions: partner A treats "level" as an integer, partner B as a string
# with an optional label.  Neither is registered globally.

class WidgetExtA(_Extension):
    _type = WIDGET_EXT_TYPE
    _properties = OrderedDict([
        ("level", IntegerProperty(required=True)),
    ])


class WidgetExtB(_Extension):
    _type = WIDGET_EXT_TYPE
    _properties = OrderedDict([
        ("level", StringProperty(required=True)),
        ("label", StringProperty()),
    ])


class UnusedExt(_Extension):
    _type = "x-acme-unused-ext"
    _properties = OrderedDict([
        ("note", StringProperty()),
    ])


WIDGET_DOC_A = """{
    "type": "file",
    "spec_version": "2.1",
    "id": "file--364fe3e5-b1f4-5ba3-b951-71b3b6c7f456",
    "name": "widget.dll",
    "extensions": {
        "x-acme-widget-ext": {"level": 7}
    }
}"""

WIDGET_DOC_B = """{
    "type": "file",
    "spec_version": "2.1",
    "id": "file--364fe3e5-b1f4-5ba3-b951-71b3b6c7f456",
    "name": "widget.dll",
    "extensions": {
        "x-acme-widget-ext": {"level": "high", "label": "triaged"}
    }
}"""


def _global_ext_map():
    return stix2.registry.STIX2_OBJ_MAPS["2.1"]["extensions"]


def test_side_by_side_same_name_extensions():
    """Acceptance: two same-named synthetic extensions imported side by
    side, each context interpreting its own fields."""
    ctx_a = ParsingContext([WidgetExtA])
    ctx_b = ParsingContext([WidgetExtB])

    obj_a = stix2.parse(WIDGET_DOC_A, context=ctx_a)
    ext_a = obj_a.extensions[WIDGET_EXT_TYPE]
    assert isinstance(ext_a, WidgetExtA)
    assert ext_a.level == 7

    obj_b = stix2.parse(WIDGET_DOC_B, context=ctx_b)
    ext_b = obj_b.extensions[WIDGET_EXT_TYPE]
    assert isinstance(ext_b, WidgetExtB)
    assert ext_b.level == "high"
    assert ext_b.label == "triaged"

    # Each context recorded which definitions it used.
    assert ctx_a.used_definitions == {WIDGET_EXT_TYPE: WidgetExtA}
    assert ctx_b.used_definitions == {WIDGET_EXT_TYPE: WidgetExtB}

    # The global registry was never touched.
    assert WIDGET_EXT_TYPE not in _global_ext_map()


def test_contexts_interpret_same_field_differently():
    """Partner B's convention is rejected under partner A's definitions."""
    ctx_a = ParsingContext([WidgetExtA])
    with pytest.raises(InvalidValueError):
        stix2.parse(WIDGET_DOC_B, context=ctx_a)


def test_parse_without_context_unaffected():
    """Another batch in the same process reads as usual."""
    # Unknown extension without a context: normal strict behavior.
    with pytest.raises(InvalidValueError):
        stix2.parse(WIDGET_DOC_A)

    # Ordinary content parses fine with no context involved.
    identity = stix2.parse(
        '{"type": "identity", "spec_version": "2.1", '
        '"id": "identity--d2916708-57b9-5636-8689-62f049e9f727", '
        '"name": "ACME"}',
    )
    assert identity.name == "ACME"


def test_conflict_keeps_raw_bytes():
    doc = """{
        "type": "identity",
        "spec_version": "2.1",
        "id": "identity--d2916708-57b9-5636-8689-62f049e9f727",
        "name": "ACME",
        "extensions": {
            "%s": {"extension_type": "property-extension", "score": 42}
        }
    }""" % EXT_DEF_ID

    ctx = ParsingContext([WidgetExtA])
    obj = stix2.parse(doc, context=ctx)

    # The unapproved reference is left as raw content on the object...
    assert isinstance(obj.extensions[EXT_DEF_ID], dict)
    assert obj.extensions[EXT_DEF_ID]["score"] == 42

    # ...and a conflict with the original bytes is recorded for review.
    assert len(ctx.conflicts) == 1
    conflict = ctx.conflicts[0]
    assert isinstance(conflict, ExtensionConflict)
    assert conflict.extension_key == EXT_DEF_ID
    assert conflict.object_id == "identity--d2916708-57b9-5636-8689-62f049e9f727"
    assert EXT_DEF_ID.encode("utf-8") in conflict.raw_bytes
    assert b'"score": 42' in conflict.raw_bytes

    assert ctx.missing_definitions == [EXT_DEF_ID]


def test_strict_context_rejects_unapproved_extension():
    ctx = ParsingContext([WidgetExtA], strict=True)
    doc = """{
        "type": "identity",
        "spec_version": "2.1",
        "id": "identity--d2916708-57b9-5636-8689-62f049e9f727",
        "name": "ACME",
        "extensions": {
            "%s": {"extension_type": "property-extension", "score": 42}
        }
    }""" % EXT_DEF_ID
    with pytest.raises(ParseError):
        stix2.parse(doc, context=ctx)


def test_bundle_cross_check_registered_vs_referenced():
    bundle = """{
        "type": "bundle",
        "id": "bundle--44af6c39-c09b-49c5-9de2-394224b04982",
        "objects": [
            {
                "type": "file",
                "spec_version": "2.1",
                "id": "file--364fe3e5-b1f4-5ba3-b951-71b3b6c7f456",
                "name": "widget.dll",
                "extensions": {
                    "x-acme-widget-ext": {"level": 3}
                }
            },
            {
                "type": "identity",
                "spec_version": "2.1",
                "id": "identity--d2916708-57b9-5636-8689-62f049e9f727",
                "name": "ACME",
                "extensions": {
                    "%s": {"extension_type": "property-extension", "score": 1}
                }
            }
        ]
    }""" % OTHER_EXT_DEF_ID

    ctx = ParsingContext([WidgetExtA, UnusedExt])
    parsed = stix2.parse(bundle, context=ctx)

    # Bundle contents were parsed with the approved definitions.
    file_obj = parsed.objects[0]
    assert isinstance(file_obj.extensions[WIDGET_EXT_TYPE], WidgetExtA)

    # Cross-check results: one referenced-but-unapproved definition, one
    # approved-but-unreferenced definition.
    assert ctx.missing_definitions == [OTHER_EXT_DEF_ID]
    assert ctx.unreferenced_definitions == ["x-acme-unused-ext"]
    assert [c.extension_key for c in ctx.conflicts] == [OTHER_EXT_DEF_ID]


def test_reparse_old_objects_with_derived_context():
    """Definitions used for a batch can be looked up later to re-parse."""
    ctx = ParsingContext([WidgetExtA, UnusedExt])
    stix2.parse(WIDGET_DOC_A, context=ctx)

    # Only the definition actually used is carried over.
    derived = ctx.derive()
    assert derived.definitions == {WIDGET_EXT_TYPE: WidgetExtA}

    reparsed = stix2.parse(WIDGET_DOC_A, context=derived)
    assert isinstance(reparsed.extensions[WIDGET_EXT_TYPE], WidgetExtA)
    assert reparsed.extensions[WIDGET_EXT_TYPE].level == 7


def test_context_manager_activation():
    ctx = ParsingContext([WidgetExtB])
    with ctx:
        obj = stix2.parse(WIDGET_DOC_B)
    assert isinstance(obj.extensions[WIDGET_EXT_TYPE], WidgetExtB)

    # After the with-block, the context no longer applies.
    with pytest.raises(InvalidValueError):
        stix2.parse(WIDGET_DOC_B)


def test_toplevel_property_extension_from_context():
    """Same extension-definition ID, different toplevel conventions."""
    class TopLevelExtA(_Extension):
        _type = EXT_DEF_ID
        extension_type = "toplevel-property-extension"
        _properties = OrderedDict([
            ("extension_type", EnumProperty(
                ["toplevel-property-extension"], required=True,
            )),
        ])
        _toplevel_properties = OrderedDict([
            ("rank", IntegerProperty()),
        ])

    class TopLevelExtB(_Extension):
        _type = EXT_DEF_ID
        extension_type = "toplevel-property-extension"
        _properties = OrderedDict([
            ("extension_type", EnumProperty(
                ["toplevel-property-extension"], required=True,
            )),
        ])
        _toplevel_properties = OrderedDict([
            ("rank", StringProperty()),
        ])

    doc_template = """{
        "type": "identity",
        "spec_version": "2.1",
        "id": "identity--d2916708-57b9-5636-8689-62f049e9f727",
        "name": "ACME",
        "rank": %s,
        "extensions": {
            "%s": {"extension_type": "toplevel-property-extension"}
        }
    }"""

    ctx_a = ParsingContext([TopLevelExtA])
    obj_a = stix2.parse(doc_template % ("5", EXT_DEF_ID), context=ctx_a)
    assert obj_a["rank"] == 5

    ctx_b = ParsingContext([TopLevelExtB])
    obj_b = stix2.parse(doc_template % ('"five"', EXT_DEF_ID), context=ctx_b)
    assert obj_b["rank"] == "five"

    assert EXT_DEF_ID not in _global_ext_map()
