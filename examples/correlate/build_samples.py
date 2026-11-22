#!/usr/bin/env python3
"""Build the two tiny .NET assemblies used by the correlation example.

The fixtures are deliberately metadata-only: there is no import table and the
method bodies contain just ``ret``.  They still contain a real PE/CLR header,
metadata streams and metadata tables, so dnfile parses them exactly like a
normal managed assembly.

The important properties of the pair are:

* ``StableService`` and its ``Compute`` method keep the same structure but
  receive different tokens after the rebuild.
* nested ``Outer+GenericBox`` and its generic constraints keep the same
  semantic identity even though nested types, TypeRefs and GenericParam rows
  are reordered.
* two identical ``Ambiguous.Handle`` methods remain indistinguishable and must
  stay a multi-select.
* ``LegacyApi.Process`` really changes its signature.

Run this file to rewrite the checked-in sample DLLs:

    python examples/correlate/build_samples.py
"""

import os
import struct
import sys


SECTION_RVA = 0x2000
SECTION_FILE_OFFSET = 0x200
FILE_ALIGNMENT = 0x200
SECTION_ALIGNMENT = 0x1000


def align(value, alignment):
    return (value + alignment - 1) // alignment * alignment


def compress_uint(value):
    if value <= 0x7F:
        return bytes((value,))
    if value <= 0x3FFF:
        return bytes((0x80 | (value >> 8), value & 0xFF))
    if value <= 0x1FFFFFFF:
        return bytes(
            (
                0xC0 | (value >> 24),
                (value >> 16) & 0xFF,
                (value >> 8) & 0xFF,
                value & 0xFF,
            )
        )
    raise ValueError("compressed integer too large")


ET_VOID = b"\x01"
ET_BOOLEAN = b"\x02"
ET_CHAR = b"\x03"
ET_I1 = b"\x04"
ET_U1 = b"\x05"
ET_I2 = b"\x06"
ET_U2 = b"\x07"
ET_I4 = b"\x08"
ET_U4 = b"\x09"
ET_I8 = b"\x0a"
ET_U8 = b"\x0b"
ET_R4 = b"\x0c"
ET_R8 = b"\x0d"
ET_STRING = b"\x0e"
ET_PTR = b"\x0f"
ET_BYREF = b"\x10"
ET_VALUETYPE = b"\x11"
ET_CLASS = b"\x12"
ET_VAR = b"\x13"
ET_ARRAY = b"\x14"
ET_GENERICINST = b"\x15"
ET_TYPEDBYREF = b"\x16"
ET_I = b"\x18"
ET_U = b"\x19"
ET_FNPTR = b"\x1b"
ET_OBJECT = b"\x1c"
ET_SZARRAY = b"\x1d"
ET_MVAR = b"\x1e"
ET_CMOD_REQD = b"\x1f"
ET_CMOD_OPT = b"\x20"
ET_PINNED = b"\x45"


def type_ref(rid):
    return ET_CLASS + compress_uint((rid << 2) | 1)


def type_def(rid):
    return ET_CLASS + compress_uint((rid << 2) | 0)


def value_type_def(rid):
    return ET_VALUETYPE + compress_uint((rid << 2) | 0)


def type_spec(rid):
    return ET_CLASS + compress_uint((rid << 2) | 2)


def var(index):
    return ET_VAR + compress_uint(index)


def mvar(index):
    return ET_MVAR + compress_uint(index)


def szarray(item):
    return ET_SZARRAY + item


def generic_instance(kind_byte, base_coded_index, arguments):
    return (
        ET_GENERICINST
        + kind_byte
        + compress_uint(base_coded_index)
        + compress_uint(len(arguments))
        + b"".join(arguments)
    )


def field_sig(field_type):
    return b"\x06" + field_type


def method_sig(return_type, parameters, has_this=True, generic_arity=0):
    first = (0x20 if has_this else 0) | (0x10 if generic_arity else 0)
    data = bytes((first,))
    if generic_arity:
        data += compress_uint(generic_arity)
    data += compress_uint(len(parameters))
    data += return_type
    data += b"".join(parameters)
    return data


def property_sig(property_type, parameters=()):
    return b"\x28" + compress_uint(len(parameters)) + property_type + b"".join(parameters)


def local_sig(types):
    return b"\x07" + compress_uint(len(types)) + b"".join(types)


class Heap:
    def __init__(self):
        self.data = bytearray(b"\x00")
        self._string_index = {"": 0}
        self._blob_index = {b"": 0}

    def string(self, value):
        value = value or ""
        if value in self._string_index:
            return self._string_index[value]
        index = len(self.data)
        if index > 0xFFFF:
            raise ValueError("small sample exceeds a 16-bit #Strings index")
        self.data.extend(value.encode("utf-8") + b"\x00")
        self._string_index[value] = index
        return index

    def blob(self, value):
        value = value or b""
        if value in self._blob_index:
            return self._blob_index[value]
        index = len(self.data)
        if index > 0xFFFF:
            raise ValueError("small sample exceeds a 16-bit #Blob index")
        self.data.extend(compress_uint(len(value)))
        self.data.extend(value)
        self._blob_index[value] = index
        return index


class AssemblySpec:
    """A small, explicit metadata table builder for the sample pair."""

    def __init__(self, assembly_version):
        self.assembly_version = assembly_version
        self.strings = Heap()
        self.blobs = Heap()
        self.guid_heap = b"\x00" * 0
        self.type_refs = []
        # TypeDef row 1 is always <Module>; add it up-front so all later row
        # indexes (and references into them) are final.
        self.type_defs = [
            {
                "namespace": "",
                "name": "<Module>",
                "full_name": "<Module>",
                "flags": 0,
                "extends": None,
                "fields": [],
                "methods": [],
            }
        ]
        self.fields = []
        self.methods = []
        self.params = []
        self.properties = []
        self.property_maps = []
        self.method_semantics = []
        self.standalone_sigs = []
        self.nested_classes = []
        self.generic_params = []
        self.generic_constraints = []
        self.typespecs = []
        self._typespec_cache = {}
        self.type_name_to_rid = {"<Module>": 1}
        self.type_ref_name_to_rid = {}
        self.method_key_to_rid = {}
        self.property_key_to_rid = {}

    def add_type_ref(self, namespace, name):
        rid = len(self.type_refs) + 1
        self.type_refs.append(
            {
                "namespace": namespace,
                "name": name,
                "scope": (1 << 2) | 2,  # ResolutionScope: AssemblyRef row 1
            }
        )
        full = "%s.%s" % (namespace, name) if namespace else name
        self.type_ref_name_to_rid[full] = rid
        return rid

    def add_type_def(self, namespace, name, fields, methods, flags=0x00100001, full_name=None):
        rid = len(self.type_defs) + 1
        full = full_name or ("%s.%s" % (namespace, name) if namespace else name)
        self.type_defs.append(
            {
                "namespace": namespace,
                "name": name,
                "full_name": full,
                "flags": flags,
                "extends": None,
                "fields": fields,
                "methods": methods,
            }
        )
        self.type_name_to_rid[full] = rid
        return rid

    def add_field(self, declaring_full, name, signature, flags):
        rid = len(self.fields) + 1
        self.fields.append(
            {
                "declaring": declaring_full,
                "name": name,
                "signature": signature,
                "flags": flags,
            }
        )
        return rid

    def add_method(self, declaring_full, name, signature, flags, impl_flags=0, params=(), locals_=None):
        rid = len(self.methods) + 1
        self.methods.append(
            {
                "declaring": declaring_full,
                "name": name,
                "signature": signature,
                "flags": flags,
                "impl_flags": impl_flags,
                "params": list(params),
                "locals": locals_,
                "body": b"\x2a",
                "local_sig_rid": None,
            }
        )
        self.method_key_to_rid[(declaring_full, name)] = rid
        return rid

    def add_nested(self, nested_full, enclosing_full):
        self.nested_classes.append(
            (self.type_name_to_rid[nested_full], self.type_name_to_rid[enclosing_full])
        )

    def add_generic_param(self, owner_kind, owner_full, number, name, flags=0, constraints=(), method_name=None):
        if owner_kind == "type":
            owner_token = (self.type_name_to_rid[owner_full] << 1) | 0
        else:
            owner_token = (self.method_key_to_rid[(owner_full, method_name or name)] << 1) | 1
        rid = len(self.generic_params) + 1
        actual_name = name
        constraint_values = [self.coded_type(name_value) for name_value in constraints]
        self.generic_params.append(
            {
                "number": number,
                "flags": flags,
                "owner": owner_token,
                "name": actual_name,
            }
        )
        for value in constraint_values:
            self.generic_constraints.append({"owner": rid, "constraint": value})
        return rid

    def add_property(self, declaring_full, name, signature, getter_method, semantics=0x0002):
        rid = len(self.properties) + 1
        self.properties.append(
            {
                "declaring": declaring_full,
                "name": name,
                "signature": signature,
            }
        )
        self.method_semantics.append(
            {
                "semantics": semantics,
                "method": self.method_key_to_rid[(declaring_full, getter_method)],
                "association": (rid << 1) | 1,
            }
        )
        self.property_key_to_rid[(declaring_full, name)] = rid
        return rid

    def coded_type(self, value):
        if isinstance(value, int):
            return value
        if value.startswith("typeref:"):
            return (self.type_ref_name_to_rid[value[len("typeref:"):]] << 2) | 1
        if value.startswith("typedef:"):
            return (self.type_name_to_rid[value[len("typedef:"):]] << 2) | 0
        raise ValueError("unknown coded type %r" % (value,))

    def typespec(self, blob):
        if blob in self._typespec_cache:
            return self._typespec_cache[blob]
        rid = len(self.typespecs) + 1
        self.typespecs.append(blob)
        self._typespec_cache[blob] = rid
        return rid

    def build(self, path):
        for index, type_def in enumerate(self.type_defs, start=1):
            self.type_name_to_rid[type_def["full_name"]] = index

        self._assign_field_and_method_lists()
        self._assign_standalone_sigs()
        self._assign_param_lists()
        self._assign_property_maps()

        table_data = self._serialize_tables(method_rvas={})
        metadata = self._build_metadata(table_data)
        section_prefix_size = 0x48 + len(metadata)
        body_offsets = {}
        bodies = bytearray()
        for rid, method in enumerate(self.methods, start=1):
            body = self._method_body(method)
            if body is None:
                continue
            while (SECTION_RVA + align(section_prefix_size, 4) + len(bodies)) % 4:
                bodies.append(0)
            rva = SECTION_RVA + align(section_prefix_size, 4) + len(bodies)
            body_offsets[rid] = rva
            bodies.extend(body)
        table_data = self._serialize_tables(method_rvas=body_offsets)
        metadata = self._build_metadata(table_data)
        assert len(metadata) == section_prefix_size - 0x48

        cli_header = self._cli_header(SECTION_RVA + 0x48, len(metadata))
        section = cli_header + metadata + bytes(bodies)
        pe = self._build_pe(section, SECTION_RVA + 0x48, len(metadata))
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with open(path, "wb") as handle:
            handle.write(pe)
        return path

    def _assign_field_and_method_lists(self):
        field_cursor = 1
        method_cursor = 1
        for type_def in self.type_defs:
            type_def["field_list"] = field_cursor
            type_def["method_list"] = method_cursor
            field_cursor += len(type_def["fields"])
            method_cursor += len(type_def["methods"])
        if field_cursor - 1 != len(self.fields) or method_cursor - 1 != len(self.methods):
            raise ValueError("field/method table order does not match TypeDef ownership")

    def _assign_standalone_sigs(self):
        for method in self.methods:
            if method["locals"] is None:
                continue
            blob = local_sig(method["locals"])
            rid = len(self.standalone_sigs) + 1
            self.standalone_sigs.append(blob)
            method["local_sig_rid"] = rid

    def _assign_param_lists(self):
        cursor = 1
        for method in self.methods:
            method["param_list"] = cursor
            for sequence, (name, flags) in enumerate(method["params"], start=1):
                self.params.append(
                    {
                        "flags": flags,
                        "sequence": sequence,
                        "name": name,
                    }
                )
            cursor += len(method["params"])

    def _assign_property_maps(self):
        owner_order = []
        property_by_owner = {}
        for rid, prop in enumerate(self.properties, start=1):
            owner = prop["declaring"]
            if owner not in property_by_owner:
                property_by_owner[owner] = []
                owner_order.append(owner)
            property_by_owner[owner].append(rid)
        cursor = 1
        for owner in owner_order:
            self.property_maps.append(
                {
                    "parent": self.type_name_to_rid[owner],
                    "property_list": cursor,
                }
            )
            cursor += len(property_by_owner[owner])

    def _method_body(self, method):
        if method["locals"] is None:
            return bytes(((1 << 2) | 2,)) + method["body"]
        local_token = (0x11 << 24) | method["local_sig_rid"]
        flags = 0x3003 | 0x10  # fat header, three dwords, init locals
        header = struct.pack("<HHII", flags, 1, len(method["body"]), local_token)
        return header + method["body"]

    def _serialize_tables(self, method_rvas):
        strings = self.strings
        blobs = self.blobs
        tables = {}

        rows = []
        for type_def in self.type_defs:
            extends = 0 if type_def["extends"] is None else type_def["extends"]
            rows.append(
                struct.pack(
                    "<IHHHHH",
                    type_def["flags"],
                    strings.string(type_def["name"]),
                    strings.string(type_def["namespace"]),
                    extends,
                    type_def["field_list"],
                    type_def["method_list"],
                )
            )
        tables[2] = rows

        rows = []
        for type_ref in self.type_refs:
            rows.append(
                struct.pack(
                    "<HHH",
                    type_ref["scope"],
                    strings.string(type_ref["name"]),
                    strings.string(type_ref["namespace"]),
                )
            )
        tables[1] = rows

        rows = []
        for field in self.fields:
            rows.append(
                struct.pack(
                    "<HHH",
                    field["flags"],
                    strings.string(field["name"]),
                    blobs.blob(field["signature"]),
                )
            )
        tables[4] = rows

        rows = []
        for method_rid, method in enumerate(self.methods, start=1):
            rows.append(
                struct.pack(
                    "<IHHHHH",
                    method_rvas.get(method_rid, 0),
                    method["impl_flags"],
                    method["flags"],
                    strings.string(method["name"]),
                    blobs.blob(method["signature"]),
                    method["param_list"],
                )
            )
        tables[6] = rows

        rows = []
        for param in self.params:
            rows.append(
                struct.pack(
                    "<HHH",
                    param["flags"],
                    param["sequence"],
                    strings.string(param["name"]),
                )
            )
        tables[8] = rows

        rows = []
        for rid, blob in enumerate(self.standalone_sigs, start=1):
            rows.append(struct.pack("<H", blobs.blob(blob)))
        tables[17] = rows

        rows = []
        for prop in self.properties:
            rows.append(
                struct.pack(
                    "<HHH",
                    0,
                    strings.string(prop["name"]),
                    blobs.blob(prop["signature"]),
                )
            )
        tables[23] = rows

        rows = []
        for item in self.property_maps:
            rows.append(struct.pack("<HH", item["parent"], item["property_list"]))
        tables[21] = rows

        rows = []
        for item in self.method_semantics:
            rows.append(struct.pack("<HHH", item["semantics"], item["method"], item["association"]))
        tables[24] = rows

        rows = []
        for nested, enclosing in self.nested_classes:
            rows.append(struct.pack("<HH", nested, enclosing))
        tables[41] = rows

        rows = []
        for item in self.generic_params:
            rows.append(
                struct.pack(
                    "<HHHH",
                    item["number"],
                    item["flags"],
                    item["owner"],
                    strings.string(item["name"]),
                )
            )
        tables[42] = rows

        rows = []
        for item in self.generic_constraints:
            rows.append(struct.pack("<HH", item["owner"], item["constraint"]))
        tables[44] = rows

        rows = []
        for blob in self.typespecs:
            rows.append(struct.pack("<H", blobs.blob(blob)))
        tables[27] = rows

        rows = []
        rows.append(
            struct.pack(
                "<HHHHH",
                0,
                strings.string("<Correlate.Sample.dll>"),
                1,
                0,
                0,
            )
        )
        tables[0] = rows

        rows = []
        rows.append(
            struct.pack(
                "<IHHHHIHHH",
                0x8004,  # SHA1
                *self.assembly_version,
                0,
                blobs.blob(b""),
                strings.string("Correlate.Sample"),
                strings.string(""),
            )
        )
        tables[32] = rows

        rows = []
        rows.append(
            struct.pack(
                "<HHHHIHHHH",
                4,
                0,
                0,
                0,
                0,
                blobs.blob(b""),
                strings.string("mscorlib"),
                strings.string(""),
                blobs.blob(b""),
            )
        )
        tables[35] = rows

        return self._pack_tables({number: rows for number, rows in tables.items() if rows})

    def _pack_tables(self, tables):
        numbers = sorted(tables)
        mask = 0
        for number in numbers:
            mask |= 1 << number
        header = b"\x00\x00\x00\x00" + b"\x02\x00" + b"\x00" + b"\x01"  # reserved, major, minor, heap sizes, reserved
        header += struct.pack("<QQ", mask, 0)
        for number in numbers:
            header += struct.pack("<I", len(tables[number]))
        body = b"".join(b"".join(tables[number]) for number in numbers)
        return header + body

    def _build_metadata(self, tables_data):
        version = b"v4.0.30319\x00"
        version_padded = version + b"\x00" * ((4 - len(version) % 4) % 4)
        streams = [
            (b"#~", tables_data),
            (b"#Strings", bytes(self.strings.data)),
            (b"#Blob", bytes(self.blobs.data)),
            (b"#GUID", b"\x5a" * 16),
        ]
        root = bytearray()
        root.extend(struct.pack("<IHHII", 0x424A5342, 1, 1, 0, len(version_padded)))
        root.extend(version_padded)
        root.extend(struct.pack("<HH", 0, len(streams)))
        stream_header_size = sum(8 + align(len(name) + 1, 4) for name, _ in streams)
        cursor = len(root) + stream_header_size
        stream_headers = bytearray()
        payload = bytearray()
        for name, data in streams:
            aligned_cursor = align(cursor + len(payload), 4)
            if aligned_cursor > cursor + len(payload):
                payload.extend(b"\x00" * (aligned_cursor - cursor - len(payload)))
            offset = aligned_cursor
            padded_name = name + b"\x00" * (align(len(name) + 1, 4) - len(name))
            stream_headers.extend(struct.pack("<II", offset, len(data)))
            stream_headers.extend(padded_name)
            payload.extend(data)
        return bytes(root + stream_headers + payload)

    def _cli_header(self, metadata_rva, metadata_size):
        return struct.pack(
            "<IHH" + "I" * 16,
            72,
            2,
            5,
            metadata_rva,
            metadata_size,
            0x00000001,  # COMIMAGE_FLAGS_ILONLY
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        )

    def _build_pe(self, section_data, metadata_rva, metadata_size):
        raw_size = align(len(section_data), FILE_ALIGNMENT)
        optional = bytearray()
        optional.extend(
            struct.pack(
                "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
                0x10B,
                0,
                0,
                raw_size,
                0,
                0,
                0,
                SECTION_RVA,
                SECTION_RVA,
                0x400000,
                SECTION_ALIGNMENT,
                FILE_ALIGNMENT,
                4,
                0,
                0,
                0,
                4,
                0,
                0,
                align(SECTION_RVA + len(section_data), SECTION_ALIGNMENT),
                0x200,
                0,
                3,
                0,
                0x100000,
                0x1000,
                0x100000,
                0x1000,
                0,
                16,
            )
        )
        directories = [(0, 0)] * 16
        directories[14] = (SECTION_RVA, 72)
        for rva, size in directories:
            optional.extend(struct.pack("<II", rva, size))
        coff = struct.pack("<HHIIIHH", 0x14C, 1, 0, 0, 0, 0xE0, 0x2102)
        section = struct.pack(
            "<8sIIIIIIHHI",
            b".text\x00\x00\x00",
            len(section_data),
            SECTION_RVA,
            raw_size,
            SECTION_FILE_OFFSET,
            0,
            0,
            0,
            0,
            0x60000020,
        )
        headers = bytearray(b"\x00" * SECTION_FILE_OFFSET)
        headers[0:2] = b"MZ"
        struct.pack_into("<I", headers, 0x3C, 0x80)
        headers[0x80:0x84] = b"PE\x00\x00"
        cursor = 0x84
        headers[cursor:cursor + len(coff)] = coff
        cursor += len(coff)
        headers[cursor:cursor + len(optional)] = optional
        cursor += len(optional)
        headers[cursor:cursor + len(section)] = section
        payload = bytes(section_data) + b"\x00" * (raw_size - len(section_data))
        return bytes(headers) + payload


def build_pair(output_dir):
    os.makedirs(output_dir, exist_ok=True)
    build_old(os.path.join(output_dir, "old", "Correlate.Sample.dll"))
    build_new(os.path.join(output_dir, "new", "Correlate.Sample.dll"))


def _common_type_refs(spec, order):
    for namespace, name in order:
        spec.add_type_ref(namespace, name)


def build_old(path):
    spec = AssemblySpec((1, 0, 0, 0))
    _common_type_refs(
        spec,
        [
            ("System", "Object"),
            ("System", "String"),
            ("System", "Int32"),
            ("System", "IComparable"),
            ("System.Collections.Generic", "IComparable"),
            ("System", "IDisposable"),
            ("System", "Byte"),
        ],
    )
    object_ref = (spec.type_ref_name_to_rid["System.Object"] << 2) | 1
    string_ref = (spec.type_ref_name_to_rid["System.String"] << 2) | 1
    int_ref = (spec.type_ref_name_to_rid["System.Int32"] << 2) | 1
    comparable_ref = (spec.type_ref_name_to_rid["System.IComparable"] << 2) | 1
    disposable_ref = (spec.type_ref_name_to_rid["System.IDisposable"] << 2) | 1

    stable_rid = spec.add_type_def(
        "Contoso.Incident",
        "StableService",
        ["_cache", "VersionTag"],
        [".ctor", "Compute", "get_Status"],
    )
    outer_rid = spec.add_type_def(
        "Contoso.Incident",
        "Outer",
        ["BoxOfInt"],
        [".ctor"],
    )
    box_rid = spec.add_type_def(
        "",
        "GenericBox",
        ["Value"],
        ["Map"],
        flags=0x00100002,
        full_name="Contoso.Incident.Outer+GenericBox",
    )
    legacy_rid = spec.add_type_def(
        "Contoso.Incident",
        "LegacyApi",
        [],
        [".ctor", "Process", "get_ErrorCode"],
    )
    ambiguous_rid = spec.add_type_def(
        "Contoso.Incident",
        "Ambiguous",
        [],
        ["Handle", "Handle"],
    )
    spec.type_defs[stable_rid - 1]["extends"] = object_ref
    spec.type_defs[outer_rid - 1]["extends"] = object_ref
    spec.type_defs[box_rid - 1]["extends"] = object_ref
    spec.type_defs[legacy_rid - 1]["extends"] = object_ref
    spec.type_defs[ambiguous_rid - 1]["extends"] = object_ref
    spec.add_nested("Contoso.Incident.Outer+GenericBox", "Contoso.Incident.Outer")

    box_field_signature = field_sig(generic_instance(ET_CLASS, (box_rid << 2) | 0, [ET_I4]))
    generic_comparable_ref = (spec.type_ref_name_to_rid["System.Collections.Generic.IComparable"] << 2) | 1
    comparable_typespec = spec.typespec(
        generic_instance(ET_CLASS, generic_comparable_ref, [ET_I4])
    )
    spec.add_field("Contoso.Incident.StableService", "_cache", field_sig(ET_STRING), 0x0001)
    spec.add_field("Contoso.Incident.StableService", "VersionTag", field_sig(ET_STRING), 0x0016)
    spec.add_field(
        "Contoso.Incident.Outer",
        "BoxOfInt",
        box_field_signature,
        0x0001,
    )
    spec.add_field("Contoso.Incident.Outer+GenericBox", "Value", field_sig(var(0)), 0x0001)

    spec.add_method(
        "Contoso.Incident.StableService",
        ".ctor",
        method_sig(ET_VOID, []),
        0x1886,
    )
    spec.add_method(
        "Contoso.Incident.StableService",
        "Compute",
        method_sig(ET_I4, [ET_I4, ET_STRING]),
        0x0086,
        params=(("seed", 0), ("label", 0)),
        locals_=[ET_STRING, ET_I4],
    )
    spec.add_method(
        "Contoso.Incident.StableService",
        "get_Status",
        method_sig(ET_STRING, []),
        0x0886,
    )
    spec.add_method("Contoso.Incident.Outer", ".ctor", method_sig(ET_VOID, []), 0x1886)
    spec.add_method(
        "Contoso.Incident.Outer+GenericBox",
        "Map",
        method_sig(ET_VOID, [var(0), mvar(0)], generic_arity=1),
        0x0086,
        params=(("value", 0), ("transform", 0)),
    )
    spec.add_method(
        "Contoso.Incident.LegacyApi",
        ".ctor",
        method_sig(ET_VOID, []),
        0x1886,
    )
    spec.add_method(
        "Contoso.Incident.LegacyApi",
        "Process",
        method_sig(ET_STRING, [ET_STRING]),
        0x0086,
        params=(("path", 0),),
    )
    spec.add_method(
        "Contoso.Incident.LegacyApi",
        "get_ErrorCode",
        method_sig(ET_I4, []),
        0x0886,
    )
    spec.add_method(
        "Contoso.Incident.Ambiguous",
        "Handle",
        method_sig(ET_VOID, [ET_I4]),
        0x0086,
        params=(("value", 0),),
    )
    spec.add_method(
        "Contoso.Incident.Ambiguous",
        "Handle",
        method_sig(ET_VOID, [ET_I4]),
        0x0086,
        params=(("value", 0),),
    )

    spec.add_property(
        "Contoso.Incident.StableService",
        "Status",
        property_sig(ET_STRING),
        "get_Status",
    )
    spec.add_property(
        "Contoso.Incident.LegacyApi",
        "ErrorCode",
        property_sig(ET_I4),
        "get_ErrorCode",
    )

    spec.add_generic_param(
        "type",
        "Contoso.Incident.Outer+GenericBox",
        0,
        "T",
        constraints=((comparable_typespec << 2) | 2,),
    )
    spec.add_generic_param(
        "method",
        "Contoso.Incident.Outer+GenericBox",
        0,
        "U",
        constraints=("typeref:System.IDisposable",),
        method_name="Map",
    )

    # Keep references live so the sample remains explicit about the token
    # values used by its signatures.
    assert string_ref and int_ref and comparable_ref and disposable_ref
    return spec.build(path)


def build_new(path):
    spec = AssemblySpec((1, 0, 0, 1))
    _common_type_refs(
        spec,
        [
            ("System", "String"),
            ("System", "IComparable"),
            ("System.Collections.Generic", "IComparable"),
            ("System", "Object"),
            ("System", "IDisposable"),
            ("System", "Int32"),
            ("System", "Byte"),
        ],
    )
    object_ref = (spec.type_ref_name_to_rid["System.Object"] << 2) | 1
    comparable_ref = (spec.type_ref_name_to_rid["System.IComparable"] << 2) | 1
    disposable_ref = (spec.type_ref_name_to_rid["System.IDisposable"] << 2) | 1

    legacy_rid = spec.add_type_def(
        "Contoso.Incident",
        "LegacyApi",
        [],
        [".ctor", "Process", "get_ErrorCode"],
    )
    outer_rid = spec.add_type_def(
        "Contoso.Incident",
        "Outer",
        ["BoxOfInt"],
        [".ctor"],
    )
    ambiguous_rid = spec.add_type_def(
        "Contoso.Incident",
        "Ambiguous",
        [],
        ["Handle", "Handle"],
    )
    stable_rid = spec.add_type_def(
        "Contoso.Incident",
        "StableService",
        ["_cache", "VersionTag"],
        [".ctor", "Compute", "get_Status"],
    )
    box_rid = spec.add_type_def(
        "",
        "GenericBox",
        ["Value"],
        ["Map"],
        flags=0x00100002,
        full_name="Contoso.Incident.Outer+GenericBox",
    )
    for rid in (legacy_rid, outer_rid, ambiguous_rid, stable_rid, box_rid):
        spec.type_defs[rid - 1]["extends"] = object_ref
    spec.add_nested("Contoso.Incident.Outer+GenericBox", "Contoso.Incident.Outer")

    box_field_signature = field_sig(generic_instance(ET_CLASS, (box_rid << 2) | 0, [ET_I4]))
    generic_comparable_ref = (spec.type_ref_name_to_rid["System.Collections.Generic.IComparable"] << 2) | 1
    comparable_typespec = spec.typespec(
        generic_instance(ET_CLASS, generic_comparable_ref, [ET_I4])
    )
    spec.add_field(
        "Contoso.Incident.Outer",
        "BoxOfInt",
        box_field_signature,
        0x0001,
    )
    spec.add_field("Contoso.Incident.StableService", "_cache", field_sig(ET_STRING), 0x0001)
    spec.add_field("Contoso.Incident.StableService", "VersionTag", field_sig(ET_STRING), 0x0016)
    spec.add_field("Contoso.Incident.Outer+GenericBox", "Value", field_sig(var(0)), 0x0001)

    spec.add_method("Contoso.Incident.LegacyApi", ".ctor", method_sig(ET_VOID, []), 0x1886)
    spec.add_method(
        "Contoso.Incident.LegacyApi",
        "Process",
        method_sig(ET_VOID, [ET_I4, ET_STRING]),
        0x0086,
        params=(("code", 0), ("label", 0)),
        locals_=[ET_STRING, ET_I4],
    )
    spec.add_method(
        "Contoso.Incident.LegacyApi",
        "get_ErrorCode",
        method_sig(ET_I4, []),
        0x0886,
    )
    spec.add_method("Contoso.Incident.Outer", ".ctor", method_sig(ET_VOID, []), 0x1886)
    spec.add_method(
        "Contoso.Incident.Ambiguous",
        "Handle",
        method_sig(ET_VOID, [ET_I4]),
        0x0086,
        params=(("value", 0),),
    )
    spec.add_method(
        "Contoso.Incident.Ambiguous",
        "Handle",
        method_sig(ET_VOID, [ET_I4]),
        0x0086,
        params=(("value", 0),),
    )
    spec.add_method(
        "Contoso.Incident.StableService",
        ".ctor",
        method_sig(ET_VOID, []),
        0x1886,
    )
    spec.add_method(
        "Contoso.Incident.StableService",
        "Compute",
        method_sig(ET_I4, [ET_I4, ET_STRING]),
        0x0086,
        params=(("seed", 0), ("label", 0)),
        locals_=[ET_STRING, ET_I4],
    )
    spec.add_method(
        "Contoso.Incident.StableService",
        "get_Status",
        method_sig(ET_STRING, []),
        0x0886,
    )
    spec.add_method(
        "Contoso.Incident.Outer+GenericBox",
        "Map",
        method_sig(ET_VOID, [var(0), mvar(0)], generic_arity=1),
        0x0086,
        params=(("value", 0), ("transform", 0)),
    )

    spec.add_property(
        "Contoso.Incident.LegacyApi",
        "ErrorCode",
        property_sig(ET_I4),
        "get_ErrorCode",
    )
    spec.add_property(
        "Contoso.Incident.StableService",
        "Status",
        property_sig(ET_STRING),
        "get_Status",
    )

    # Deliberately swap GenericParam row order: method parameter first, then
    # the type parameter.  A token-based implementation would be fooled.
    spec.add_generic_param(
        "method",
        "Contoso.Incident.Outer+GenericBox",
        0,
        "U",
        constraints=("typeref:System.IDisposable",),
        method_name="Map",
    )
    spec.add_generic_param(
        "type",
        "Contoso.Incident.Outer+GenericBox",
        0,
        "T",
        constraints=((comparable_typespec << 2) | 2,),
    )

    assert comparable_ref and disposable_ref
    return spec.build(path)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv:
        output_dir = argv[0]
    else:
        output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "samples")
    build_pair(output_dir)
    print("wrote %s" % output_dir)
    return 0


if __name__ == "__main__":
    sys.exit(main())
