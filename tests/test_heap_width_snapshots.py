"""
Mapping cross-check between two legal metadata snapshots of the same logical
content: an archived snapshot with wide (4-byte) heap indexes and duplicated
string/blob entries, and a compacted snapshot with narrow (2-byte) heap
indexes after deduplication of the #Strings and #Blob heaps.

The tests verify that:
  * both snapshots parse cleanly and support the same facts (selected strings,
    signatures, and cross-table references),
  * dedup moves heap positions, so indexes recorded against the old stream
    only resolve to their fact in the old snapshot,
  * an index is scoped to its own heap/table: the same numeric position in
    another heap or table names a different fact and cannot endorse it.
"""

import struct

import pytest

from dnfile import base
from dnfile import stream as dnstream

METADATA_RVA = 0x2000

STRINGS_WIDE_MASK = 0x01
BLOBS_WIDE_MASK = 0x04

# TypeRef=1, TypeDef=2, Field=4, MethodDef=6, MemberRef=10
MASK_VALID = (1 << 1) | (1 << 2) | (1 << 4) | (1 << 6) | (1 << 10)

# field signature: FIELD int32;  method signature: 0 params, returns int32
SIG_FIELD = b"\x06\x08"
SIG_METHOD = b"\x00\x00\x08"


def _stream_struct(name, offset, size):
    fmt = ("IMAGE_CLR_STREAM_HEADER", ("I,Offset", "I,Size", "{0}s,Name".format(len(name))))
    struct_ = base.StreamStruct(fmt)
    struct_.Offset = offset
    struct_.Size = size
    struct_.Name = name
    return struct_


class _StringsArchive:
    """#Strings heap builder.  With dedup=False every add() appends a new copy."""

    def __init__(self, dedup):
        self._dedup = dedup
        self._offsets = {}
        self._buf = bytearray(b"\x00")

    def add(self, text):
        if self._dedup and text in self._offsets:
            return self._offsets[text]
        offset = len(self._buf)
        self._buf += text.encode("utf-8") + b"\x00"
        self._offsets.setdefault(text, offset)
        return offset

    def bytes(self):
        return bytes(self._buf)


class _BlobArchive:
    """#Blob heap builder.  With dedup=False every add() appends a new copy."""

    def __init__(self, dedup):
        self._dedup = dedup
        self._offsets = {}
        self._buf = bytearray(b"\x00")

    def add(self, data):
        if self._dedup and data in self._offsets:
            return self._offsets[data]
        offset = len(self._buf)
        # lengths here are small enough for a one-byte compressed int
        self._buf += bytes([len(data)]) + data
        self._offsets.setdefault(data, offset)
        return offset

    def bytes(self):
        return bytes(self._buf)


class _Snapshot:
    """A self-contained, legal metadata snapshot parsed by dnfile."""

    def __init__(self, heap_flags, dedup):
        strings = _StringsArchive(dedup)
        blobs = _BlobArchive(dedup)

        # fixed insertion order, shared by both snapshots, so that dedup is
        # the only difference between the two heap layouts
        s_widget = strings.add("Widget")
        s_widgets = strings.add("Widgets")
        s_archives_1 = strings.add("Archives")
        s_gadget = strings.add("Gadget")
        s_archives_2 = strings.add("Archives")
        s_widget_2 = strings.add("Widget")
        s_sprocket = strings.add("Sprocket")
        s_archives_3 = strings.add("Archives")
        s_get_value = strings.add("get_Value")
        s_count_1 = strings.add("Count")
        s_count_2 = strings.add("Count")
        s_count_3 = strings.add("Count")
        s_object = strings.add("Object")
        s_system = strings.add("System")

        b_field_1 = blobs.add(SIG_FIELD)
        b_field_2 = blobs.add(SIG_FIELD)
        b_method_1 = blobs.add(SIG_METHOD)
        b_method_2 = blobs.add(SIG_METHOD)

        str_fmt = "I" if heap_flags & STRINGS_WIDE_MASK else "H"
        blob_fmt = "I" if heap_flags & BLOBS_WIDE_MASK else "H"

        extends_object = (2 << 2) | 1  # TypeDefOrRef -> TypeRef row 2
        extends_widget = (1 << 2) | 1  # TypeDefOrRef -> TypeRef row 1
        class_widget = (1 << 3) | 1    # MemberRefParent -> TypeRef row 1

        rows = [
            # TypeRef: ResolutionScope(H), TypeName(s), TypeNamespace(s)
            struct.pack("<H" + str_fmt * 2, 0, s_widget, s_widgets),
            struct.pack("<H" + str_fmt * 2, 0, s_object, s_system),
            # TypeDef: Flags(I), TypeName(s), TypeNamespace(s), Extends(H), FieldList(H), MethodList(H)
            struct.pack("<I" + str_fmt * 2 + "HHH", 0, s_gadget, s_archives_1, extends_object, 1, 1),
            struct.pack("<I" + str_fmt * 2 + "HHH", 0, s_widget_2, s_archives_2, extends_widget, 2, 2),
            struct.pack("<I" + str_fmt * 2 + "HHH", 0, s_sprocket, s_archives_3, extends_object, 3, 2),
            # Field: Flags(H), Name(s), Signature(b)
            struct.pack("<H" + str_fmt + blob_fmt, 0x6, s_count_1, b_field_1),
            struct.pack("<H" + str_fmt + blob_fmt, 0x6, s_count_2, b_field_2),
            # MethodDef: Rva(I), ImplFlags(H), Flags(H), Name(s), Signature(b), ParamList(H)
            struct.pack("<IHH" + str_fmt + blob_fmt + "H", 0, 0, 0, s_get_value, b_method_1, 1),
            # MemberRef: Class(H), Name(s), Signature(b)
            struct.pack("<H" + str_fmt + blob_fmt, class_widget, s_count_3, b_method_2),
        ]

        header = struct.pack("<IBBBBQQ", 0, 1, 1, heap_flags, 1, MASK_VALID, 0)
        row_counts = struct.pack("<IIIII", 2, 3, 2, 1, 1)
        tables_data = header + row_counts + b"".join(rows)

        strings_data = strings.bytes()
        blobs_data = blobs.bytes()

        self.strings = dnstream.StringsHeap(
            METADATA_RVA, _stream_struct(b"#Strings", 0, len(strings_data)), strings_data
        )
        self.blobs = dnstream.BlobHeap(
            METADATA_RVA, _stream_struct(b"#Blob", len(strings_data), len(blobs_data)), blobs_data
        )
        self.mdtables = dnstream.MetaDataTables(
            METADATA_RVA,
            _stream_struct(b"#~", len(strings_data) + len(blobs_data), len(tables_data)),
            tables_data,
        )
        # stand in for PE file offsets so row parsing can compute file positions
        for s in (self.strings, self.blobs, self.mdtables):
            s.file_offset = s.rva
        # raises if the snapshot is not legal
        self.mdtables.parse([self.strings, self.blobs, self.mdtables])


def _old_snapshot():
    # archived snapshot: wide (4-byte) heap indexes, duplicates kept
    return _Snapshot(heap_flags=STRINGS_WIDE_MASK | BLOBS_WIDE_MASK, dedup=False)


def _new_snapshot():
    # compacted snapshot: narrow (2-byte) heap indexes, heaps deduplicated
    return _Snapshot(heap_flags=0, dedup=True)


def _facts(md):
    """The facts a report would record, as plain comparable values."""
    typedefs = md.TypeDef
    fields = md.Field
    method = md.MethodDef.rows[0]
    member_ref = md.MemberRef.rows[0]
    return {
        "typedef_names": [str(r.TypeName) for r in typedefs.rows],
        "typedef_namespaces": [str(r.TypeNamespace) for r in typedefs.rows],
        "typedef_extends": [(r.Extends.table.name, r.Extends.row_index) for r in typedefs.rows],
        "typedef_extends_names": [str(r.Extends.row.TypeName) for r in typedefs.rows],
        "typedef_fieldlists": [[i.row_index for i in r.FieldList] for r in typedefs.rows],
        "typedef_methodlists": [[i.row_index for i in r.MethodList] for r in typedefs.rows],
        "field_names": [str(r.Name) for r in fields.rows],
        "field_signatures": [r.Signature.value for r in fields.rows],
        "method_name": str(method.Name),
        "method_signature": method.Signature.value,
        "memberref_class": (member_ref.Class.table.name, member_ref.Class.row_index),
        "memberref_name": str(member_ref.Name),
        "memberref_signature": member_ref.Signature.value,
    }


def test_compact_snapshot_preserves_strings_and_references():
    old = _old_snapshot()
    new = _new_snapshot()

    # both snapshots are legal, but with different heap widths
    assert old.mdtables.header.HeapOffsetSizes == STRINGS_WIDE_MASK | BLOBS_WIDE_MASK
    assert new.mdtables.header.HeapOffsetSizes == 0
    assert (old.mdtables.strings_offset_size, old.mdtables.blobs_offset_size) == (4, 4)
    assert (new.mdtables.strings_offset_size, new.mdtables.blobs_offset_size) == (2, 2)

    # same logical tables
    for name in ("TypeRef", "TypeDef", "Field", "MethodDef", "MemberRef"):
        assert getattr(old.mdtables, name).num_rows == getattr(new.mdtables, name).num_rows

    # narrower indexes make rows narrower, but the facts survive unchanged
    assert old.mdtables.TypeDef.row_size != new.mdtables.TypeDef.row_size
    assert _facts(old.mdtables) == _facts(new.mdtables)


def test_dedup_shifts_heap_positions_but_not_facts():
    old = _old_snapshot()
    new = _new_snapshot()

    old_typedefs = old.mdtables.TypeDef.rows
    new_typedefs = new.mdtables.TypeDef.rows

    # old stream stores "Archives" as three separate copies
    old_ns_indexes = [r.struct.TypeNamespace_StringIndex for r in old_typedefs]
    assert len(set(old_ns_indexes)) == 3
    # dedup collapses them to a single position in the new stream
    new_ns_indexes = [r.struct.TypeNamespace_StringIndex for r in new_typedefs]
    assert len(set(new_ns_indexes)) == 1
    # both support the same fact
    assert [str(r.TypeNamespace) for r in old_typedefs] == ["Archives"] * 3
    assert [str(r.TypeNamespace) for r in new_typedefs] == ["Archives"] * 3

    # a string shared across tables (TypeRef row 1 and TypeDef row 2) is also
    # stored twice in the old stream and once in the new stream
    old_typeref_name = old.mdtables.TypeRef.rows[0].struct.TypeName_StringIndex
    old_typedef_name = old_typedefs[1].struct.TypeName_StringIndex
    assert old_typeref_name != old_typedef_name
    assert new.mdtables.TypeRef.rows[0].struct.TypeName_StringIndex == new_typedefs[1].struct.TypeName_StringIndex
    assert str(old_typedefs[1].TypeName) == str(new_typedefs[1].TypeName) == "Widget"

    # blob dedup: the two field signatures move to one shared position
    old_fields = old.mdtables.Field.rows
    new_fields = new.mdtables.Field.rows
    assert old_fields[0].struct.Signature_BlobIndex != old_fields[1].struct.Signature_BlobIndex
    assert new_fields[0].struct.Signature_BlobIndex == new_fields[1].struct.Signature_BlobIndex
    assert old_fields[0].Signature == old_fields[1].Signature == SIG_FIELD
    assert new_fields[0].Signature == new_fields[1].Signature == SIG_FIELD

    # entries stored before the first removed duplicate keep their position;
    # every deduplicated copy moves
    assert old_typedefs[0].struct.TypeNamespace_StringIndex == new_typedefs[0].struct.TypeNamespace_StringIndex
    for old_row, new_row in zip(old_typedefs[1:], new_typedefs[1:]):
        assert old_row.struct.TypeNamespace_StringIndex != new_row.struct.TypeNamespace_StringIndex


def test_reported_positions_only_resolve_in_old_snapshot():
    old = _old_snapshot()
    new = _new_snapshot()

    # a "past report": raw heap indexes recorded against the old stream,
    # each paired with the fact it supported
    report = [
        ("strings", old.mdtables.TypeDef.rows[1].struct.TypeNamespace_StringIndex, "Archives"),
        ("strings", old.mdtables.TypeDef.rows[2].struct.TypeNamespace_StringIndex, "Archives"),
        ("strings", old.mdtables.Field.rows[1].struct.Name_StringIndex, "Count"),
        ("strings", old.mdtables.MemberRef.rows[0].struct.Name_StringIndex, "Count"),
        ("blob", old.mdtables.Field.rows[1].struct.Signature_BlobIndex, SIG_FIELD),
        ("blob", old.mdtables.MemberRef.rows[0].struct.Signature_BlobIndex, SIG_METHOD),
    ]

    # the compacted heaps are laid out differently, so the streams moved too
    assert old.blobs.rva != new.blobs.rva

    for heap_name, index, expected in report:
        old_heap = old.strings if heap_name == "strings" else old.blobs
        new_heap = new.strings if heap_name == "strings" else new.blobs

        if heap_name == "strings":
            # the recorded position still supports the fact in the old snapshot
            assert old_heap.get_str(index) == expected
            # and the recorded local stream position matches
            assert old_heap.get(index).rva == old_heap.rva + index
            # the same numeric position in the new stream is either out of
            # range or a different fact -- it never endorses the old report
            try:
                value = new_heap.get_str(index)
            except IndexError:
                value = None
            assert value != expected
        else:
            assert old_heap.get_bytes(index) == expected
            assert old_heap.get(index).rva == old_heap.rva + index
            assert new_heap.get_bytes(index) != expected


def test_indices_do_not_endorse_across_heaps_or_tables():
    old = _old_snapshot()
    md = old.mdtables

    field1 = md.Field.rows[0]

    # a #Blob index is only a fact inside #Blob: the same numeric position in
    # #Strings is an unrelated string, not the signature
    blob_index = field1.struct.Signature_BlobIndex
    assert old.blobs.get_bytes(blob_index) == SIG_FIELD
    assert old.strings.get_str(blob_index) == "Widget"
    assert old.strings.get_str(blob_index) != SIG_FIELD

    # a #Strings index is only a fact inside #Strings
    name_index = field1.struct.Name_StringIndex
    assert old.strings.get_str(name_index) == "Count"
    assert old.blobs.get_bytes(name_index) != SIG_FIELD

    # a coded index carries its target table; the same row number in another
    # table names a different entity and cannot endorse the reference
    extends = md.TypeDef.rows[0].Extends
    assert extends.table.name == "TypeRef"
    assert extends.row_index == 2
    assert str(md.TypeRef.get_with_row_index(2).TypeName) == "Object"
    assert str(md.TypeDef.get_with_row_index(2).TypeName) == "Widget"

    member_ref_class = md.MemberRef.rows[0].Class
    assert member_ref_class.table.name == "TypeRef"
    assert member_ref_class.row_index == 1
    assert str(md.TypeRef.get_with_row_index(1).TypeName) == "Widget"
    assert str(md.MethodDef.get_with_row_index(1).Name) == "get_Value"

    # the raw coded value is not a plain table index either
    assert md.TypeDef.rows[0].struct.Extends_CodedIndex != extends.row_index
    with pytest.raises(IndexError):
        md.TypeRef.get_with_row_index(md.TypeDef.rows[0].struct.Extends_CodedIndex)
