import json
import types
import struct
import hashlib

import pytest

from dnfile import base, mdtable, stream
from dnfile.forensic import (
    Disclosure,
    FieldRule,
    ViewPolicy,
    RestrictedView,
    REASON_NO_DATA,
    REASON_ROW_MISSING,
    REASON_SUMMARY_ONLY,
    REASON_REF_OUT_OF_SCOPE,
)

HEAP_RVA = 0x2000
HEAP_FILE_OFFSET = 0x400
ROW1_FILE_OFFSET = 0x800
ROW_SIZE = 14

# #Strings heap layout:
#   0   "\0"
#   1   "SharedName\0"   <- shared by both TypeDef rows
#   12  "AlphaNS\0"      <- namespace of row 1 (quarantined in scope B)
#   20  "BetaNS\0"       <- namespace of row 2 (quarantined in scope A)
STRINGS_DATA = b"\x00" + b"SharedName\x00" + b"AlphaNS\x00" + b"BetaNS\x00"
SHARED_NAME_INDEX = 1
ROW1_NAMESPACE_INDEX = 12
ROW2_NAMESPACE_INDEX = 20


class FakeStreamStruct:
    Offset = 0
    Size = 0

    def sizeof(self):
        return 0


class FakeTable:
    def __init__(self, name, rows):
        self.name = name
        self.rows = rows

    def get_with_row_index(self, row_index):
        if not 1 <= row_index <= len(self.rows):
            raise IndexError(row_index)
        return self.rows[row_index - 1]


def build_sample():
    """
    Build a synthetic two-row TypeDef table in which both rows share a
    single #Strings heap entry, plus a dnPE-like object wrapping it.
    """
    strings_heap = stream.StringsHeap(HEAP_RVA, FakeStreamStruct(), STRINGS_DATA)
    strings_heap.file_offset = HEAP_FILE_OFFSET

    tables_rowcounts = [None] * 64

    def make_row(flags, name_index, namespace_index, file_offset):
        row = mdtable.TypeDefRow(tables_rowcounts, 2, 2, 2, strings_heap, None, None)
        data = struct.pack("<IHHHHH", flags, name_index, namespace_index, 0, 1, 1)
        assert len(data) == ROW_SIZE
        row.set_data(data, file_offset=file_offset)
        row.parse(tables=[], next_row=None)
        return row

    row1 = make_row(0x00100001, SHARED_NAME_INDEX, ROW1_NAMESPACE_INDEX, ROW1_FILE_OFFSET)
    row2 = make_row(0x00100000, SHARED_NAME_INDEX, ROW2_NAMESPACE_INDEX, ROW1_FILE_OFFSET + ROW_SIZE)

    # references held by the licensed rows; the targets are quarantined rows
    row1.Extends = base.MDTableIndex(types.SimpleNamespace(name="TypeRef"), 1)
    row2.Extends = base.MDTableIndex(types.SimpleNamespace(name="TypeDef"), 2)

    typedef_table = FakeTable("TypeDef", [row1, row2])
    mdtables = types.SimpleNamespace(tables_list=[typedef_table])
    dn = types.SimpleNamespace(net=types.SimpleNamespace(mdtables=mdtables))
    return dn, row1, row2


def build_policies():
    policy_a = ViewPolicy(
        allowed_rows={"TypeDef": [1]},
        field_rules={
            ("TypeDef", "TypeName"): Disclosure.PUBLIC,
            (None, "TypeNamespace"): Disclosure.SUMMARY,
            ("TypeDef", "Flags"): FieldRule(Disclosure.REDACTED, "flags withheld by audit agreement"),
            ("TypeDef", "Extends"): Disclosure.PUBLIC,
            ("TypeDef", "FieldList"): Disclosure.PUBLIC,
            ("TypeDef", "MethodList"): Disclosure.PUBLIC,
        },
    )
    policy_b = ViewPolicy(
        allowed_rows={"TypeDef": [2]},
        field_rules={
            ("TypeDef", "TypeName"): Disclosure.PUBLIC,
            ("TypeDef", "TypeNamespace"): Disclosure.PUBLIC,
            ("TypeDef", "Extends"): Disclosure.PUBLIC,
        },
    )
    return policy_a, policy_b


def test_shared_heap_entry_exported_under_two_scopes():
    dn, _, _ = build_sample()
    policy_a, policy_b = build_policies()

    view_a = RestrictedView.from_dnfile(dn, policy_a, label="scope-a")
    view_b = RestrictedView.from_dnfile(dn, policy_b, label="scope-b")

    # each view contains exactly the licensed row
    assert [r.rid for r in view_a.rows] == [1]
    assert [r.rid for r in view_b.rows] == [2]

    name_a = view_a.rows[0].get_field("TypeName")
    name_b = view_b.rows[0].get_field("TypeName")

    # both scopes disclose the shared heap entry and can locate the
    # original material at the same position in the source file
    assert name_a.value == "SharedName"
    assert name_b.value == "SharedName"
    assert name_a.source["heap"] == "#Strings"
    assert name_a.source["index"] == SHARED_NAME_INDEX
    assert name_a.source["rva"] == HEAP_RVA + SHARED_NAME_INDEX
    assert name_a.source["file_offset"] == HEAP_FILE_OFFSET + SHARED_NAME_INDEX
    assert name_b.source["file_offset"] == name_a.source["file_offset"]

    # the licensed row itself can be located in the source file
    assert view_a.rows[0].file_offset == ROW1_FILE_OFFSET
    assert view_b.rows[0].file_offset == ROW1_FILE_OFFSET + ROW_SIZE


def test_quarantined_rows_never_leak():
    dn, _, _ = build_sample()
    policy_a, policy_b = build_policies()

    json_a = RestrictedView.from_dnfile(dn, policy_a).to_json()
    json_b = RestrictedView.from_dnfile(dn, policy_b).to_json()

    # scope A may not see row 2's namespace, and vice versa
    assert "BetaNS" not in json_a
    assert "AlphaNS" not in json_b
    # scope A only summarizes row 1's namespace, so it does not appear either
    assert "AlphaNS" not in json_a
    assert "BetaNS" in json_b

    # no quarantined table rows appear in either view
    for view in (RestrictedView.from_json(json_a), RestrictedView.from_json(json_b)):
        assert all(r.table == "TypeDef" for r in view.rows)


def test_field_level_disclosure():
    dn, _, _ = build_sample()
    policy_a, _ = build_policies()

    row = RestrictedView.from_dnfile(dn, policy_a).rows[0]

    # summary-only field: digest and length, but no value
    namespace = row.get_field("TypeNamespace")
    assert namespace.disclosure is Disclosure.SUMMARY
    assert namespace.value is None
    assert namespace.summary["sha256"] == hashlib.sha256(b"AlphaNS").hexdigest()
    assert namespace.summary["length"] == len(b"AlphaNS")
    assert namespace.reason == REASON_SUMMARY_ONLY
    # the underlying material can still be located
    assert namespace.source["file_offset"] == HEAP_FILE_OFFSET + ROW1_NAMESPACE_INDEX

    # redacted field: blank, with the policy reason recorded
    flags = row.get_field("Flags")
    assert flags.disclosure is Disclosure.REDACTED
    assert flags.value is None
    assert flags.reason == "flags withheld by audit agreement"

    # reference to a quarantined row: pointer recorded, content withheld
    extends = row.get_field("Extends")
    assert extends.references == [
        {"table": "TypeRef", "rid": 1, "in_scope": False, "reason": REASON_REF_OUT_OF_SCOPE}
    ]

    # fields whose data is unavailable report their missing-evidence reason
    assert row.get_field("FieldList").reason == REASON_NO_DATA
    assert row.get_field("MethodList").reason == REASON_NO_DATA


def test_in_scope_reference_is_marked():
    dn, _, _ = build_sample()
    _, policy_b = build_policies()

    row = RestrictedView.from_dnfile(dn, policy_b).rows[0]
    extends = row.get_field("Extends")
    assert extends.references == [{"table": "TypeDef", "rid": 2, "in_scope": True}]


def test_reviewer_import_roundtrip():
    dn, _, _ = build_sample()
    policy_a, _ = build_policies()

    exported = RestrictedView.from_dnfile(dn, policy_a, label="scope-a").to_json()
    view = RestrictedView.from_json(exported)

    row = view.get_row("TypeDef", 1)
    assert row is not None

    # authorized fields are readable by the external reviewer
    authorized = row.authorized_fields()
    assert authorized["TypeName"] == "SharedName"
    assert "TypeNamespace" not in authorized
    assert "Flags" not in authorized

    # reasons for missing evidence survive the round trip
    missing = row.missing_evidence()
    assert missing["TypeNamespace"] == REASON_SUMMARY_ONLY
    assert missing["Flags"] == "flags withheld by audit agreement"
    assert missing["FieldList"] == REASON_NO_DATA

    # aggregate view of missing evidence
    assert view.missing_evidence()["TypeDef:1"]["Flags"] == "flags withheld by audit agreement"

    # heap source location survives the round trip
    assert row.get_field("TypeName").source["file_offset"] == HEAP_FILE_OFFSET + SHARED_NAME_INDEX


def test_unparseable_row_reports_missing_evidence():
    dn, _, _ = build_sample()
    policy = ViewPolicy(allowed_rows={"TypeDef": [99], "TypeRef": [1]})

    view = RestrictedView.from_dnfile(dn, policy)
    assert [r.error for r in view.rows] == [REASON_ROW_MISSING, REASON_ROW_MISSING]

    missing = view.missing_evidence()
    assert missing["TypeDef:99"]["<row>"] == REASON_ROW_MISSING
    assert missing["TypeRef:1"]["<row>"] == REASON_ROW_MISSING


def test_default_policy_redacts_unlisted_fields():
    dn, _, _ = build_sample()
    policy = ViewPolicy(allowed_rows={"TypeDef": [1]})

    row = RestrictedView.from_dnfile(dn, policy).rows[0]
    assert row.authorized_fields() == {}
    assert set(row.missing_evidence()) == {
        "Flags", "TypeName", "TypeNamespace", "Extends", "FieldList", "MethodList",
    }


def test_from_dict_rejects_foreign_data():
    with pytest.raises(ValueError):
        RestrictedView.from_dict({"format": "something-else", "version": 1})
    with pytest.raises(ValueError):
        RestrictedView.from_json(json.dumps({"format": "dnfile.restricted-view", "version": 999}))
