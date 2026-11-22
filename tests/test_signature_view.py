# -*- coding: utf-8 -*-
"""Tests for the heap-layout independent signature view and PE builder."""
from __future__ import annotations

import pytest

import dnfile
from dnfile.signature import (
    FieldSignature, MethodSignature, build_signature_view, compare_views,
    parse_signature,
)
from support.pebuild import (
    ELEMENT_I4, ELEMENT_VOID, AssemblyRefSpec, AssemblySpec, FieldSpec,
    GenericParamSpec, MetadataModel, MethodSpec, ParamSpec, TypeDefSpec,
    TypeRefSpec, array_shape, build_pe, class_ref, generic_inst, mvar,
    szarray, var,
)


def _view(model, layout="canonical"):
    pe = dnfile.dnPE(data=build_pe(model, layout))
    return build_signature_view(pe), pe


# ---------------------------------------------------------------------------
# Low-level blob parser
# ---------------------------------------------------------------------------


def test_parse_basic_method_signature():
    sig = parse_signature(bytes([0x20, 0x02, ELEMENT_VOID, ELEMENT_I4, 0x1D, 0x0E]))
    assert isinstance(sig, MethodSignature)
    assert sig.has_this is True
    assert len(sig.params) == 2
    assert sig.params[1].type.kind == 0x1D


def test_parse_generic_method_signature():
    sig = parse_signature(bytes([0x30, 0x01, 0x01, ELEMENT_VOID, 0x1E, 0x00]))
    assert sig.is_generic is True
    assert sig.generic_param_count == 1
    assert sig.params[0].type.var_index == 0


def test_parse_general_array_keeps_rank_and_bounds():
    sig = parse_signature(bytes([0x06, 0x14, ELEMENT_I4, 0x02, 0x01, 0x05, 0x01, 0x00]))
    assert isinstance(sig, FieldSignature)
    shape = sig.type.array_shape
    assert shape.rank == 2
    assert shape.sizes == (5,)
    assert shape.lo_bounds == (0,)


def test_parse_custom_modifier_and_pinned():
    sig = parse_signature(bytes([0x06, 0x20, 0x02, 0x45, ELEMENT_I4]))
    assert sig.type.pinned is True
    assert sig.type.modifiers[0].required is False


def test_parse_rejects_garbage():
    with pytest.raises(ValueError):
        parse_signature(bytes([0x99]))


# ---------------------------------------------------------------------------
# Synthetic PE integration
# ---------------------------------------------------------------------------


def _rich_model(constraint_rid=4, param_element=None):
    if param_element is None:
        param_element = szarray(mvar(0))
    map_signature = (
        bytes([0x20 | 0x10, 0x01, 0x02])
        + generic_inst("TypeDef", 2, [mvar(0)])
        + var(0)
        + param_element
    )
    return MetadataModel(
        assembly=AssemblySpec("HeapSwapApi"),
        assembly_refs=[AssemblyRefSpec("mscorlib")],
        type_refs=[
            TypeRefSpec("Object", "System", "mscorlib"),
            TypeRefSpec("Int32", "System", "mscorlib"),
            TypeRefSpec("String", "System", "mscorlib"),
            TypeRefSpec("IComparable", "System", "mscorlib"),
            TypeRefSpec("IConvertible", "System", "mscorlib"),
        ],
        type_specs=[szarray(class_ref("TypeRef", 3))],
        type_defs=[
            TypeDefSpec(
                "Container", "Api", 0x000001, ("TypeRef", 1),
                fields=[
                    FieldSpec("Matrix", bytes([0x06]) + array_shape(bytes([ELEMENT_I4]), 2, [3, 4], [0, 0])),
                    FieldSpec("Names", bytes([0x06]) + szarray(class_ref("TypeRef", 3))),
                ],
                methods=[
                    MethodSpec("Map", map_signature, [ParamSpec("input"), ParamSpec("buffer")]),
                ],
            )
        ],
        generic_params=[
            GenericParamSpec(0, "T", 0, ("TypeDef", 2), [("TypeRef", constraint_rid)]),
            GenericParamSpec(0, "U", 0, ("MethodDef", 1), []),
        ],
    )


def test_synthetic_pe_parses_without_warnings():
    module_view, pe = _view(_rich_model())
    table_names = {table.name for table in pe.net.mdtables.tables_list}
    assert module_view is not None
    assert {"TypeDef", "MethodDef", "Field", "GenericParam", "GenericParamConstraint"} <= table_names
    assert not [w for w in pe.get_warnings() if "Byte 0x00" not in w]


def test_heap_only_swap_produces_identical_fingerprints():
    model = _rich_model()
    canonical, pe_a = _view(model, "canonical")
    shuffled, pe_b = _view(model, "shuffled")
    # the raw heap indices really did change
    assert pe_a.net.mdtables.MethodDef[0].struct.Signature_BlobIndex != pe_b.net.mdtables.MethodDef[0].struct.Signature_BlobIndex
    # but the comparable fingerprints are identical
    assert canonical.fingerprints() == shuffled.fingerprints()
    assert compare_views(canonical, shuffled) == ()


def test_parameter_change_is_pinpointed():
    baseline, _ = _view(_rich_model(param_element=szarray(mvar(0))), "shuffled")
    changed, _ = _view(_rich_model(param_element=bytes([ELEMENT_I4])), "shuffled")
    diffs = {change.member: change for change in compare_views(baseline, changed)}
    assert "Api.Container#M#Map" in diffs
    assert "szarray" in diffs["Api.Container#M#Map"].left
    assert "prim:System.Int32" in diffs["Api.Container#M#Map"].right
    # the field and unrelated structure stay untouched
    assert "Api.Container#F#Matrix" not in diffs


def test_generic_constraint_change_is_pinpointed():
    baseline, _ = _view(_rich_model(constraint_rid=4), "shuffled")
    changed, _ = _view(_rich_model(constraint_rid=5), "shuffled")
    diffs = compare_views(baseline, changed)
    type_change = next(change for change in diffs if change.member == "Api.Container")
    assert "IComparable" in type_change.left
    assert "IConvertible" in type_change.right


def test_array_rank_and_bounds_are_preserved():
    view, _ = _view(_rich_model())
    field_fp = view.fingerprints()["Api.Container#F#Matrix"]
    assert "rank=2" in field_fp
    assert "sizes=(3,4)" in field_fp
    assert "lobounds=(0,0)" in field_fp


def test_generic_parameter_owner_is_part_of_identity():
    view, _ = _view(_rich_model())
    method_fp = view.fingerprints()["Api.Container#M#Map"]
    # MVAR belongs to the method, VAR belongs to the enclosing type
    assert "genvar:method:Map!0" in method_fp
    assert "genvar:typedef:Api.Container!0" in method_fp


def test_generic_instantiation_arguments_are_typed():
    view, _ = _view(_rich_model())
    method_fp = view.fingerprints()["Api.Container#M#Map"]
    assert "geninst class typedef:Api.Container<genvar:method:Map!0>" in method_fp


def test_unresolved_reference_does_not_shadow_same_named_type():
    model = MetadataModel(
        assembly=AssemblySpec("Shadow"),
        assembly_refs=[AssemblyRefSpec("mscorlib")],
        type_refs=[TypeRefSpec("Object", "System", "mscorlib")],
        type_defs=[
            TypeDefSpec(
                "Int32", "Local", 0x000001, ("TypeRef", 1),
                fields=[FieldSpec("Broken", bytes([0x06]) + class_ref("TypeRef", 99))],
            )
        ],
    )
    view, _ = _view(model)
    assert view.unresolved_keys() == ("unresolved:TypeRef/99(row missing)",)
    field_fp = view.fingerprints()["Local.Int32#F#Broken"]
    assert "unresolved:TypeRef/99" in field_fp
    assert "typedef:Local.Int32" not in field_fp


def test_primitive_and_typeref_identities_never_collide():
    model = MetadataModel(
        assembly=AssemblySpec("Prim"),
        assembly_refs=[AssemblyRefSpec("mscorlib")],
        type_refs=[
            TypeRefSpec("Object", "System", "mscorlib"),
            TypeRefSpec("Int32", "System", "mscorlib"),
        ],
        type_defs=[
            TypeDefSpec(
                "Box", "", 0x000001, ("TypeRef", 1),
                fields=[FieldSpec("Value", bytes([0x06, ELEMENT_I4]))],
            )
        ],
    )
    view, _ = _view(model)
    field_fp = view.fingerprints()["Box#F#Value"]
    assert "prim:System.Int32" in field_fp
    assert "typeref:" not in field_fp
