# -*- coding: utf-8 -*-
"""Comparable signature views across a metadata heap swap.

Builds minimal managed images without a .NET toolchain and demonstrates that
heap-index-only changes produce no API diff while a real parameter/constraint
change is pinpointed.
"""
from __future__ import annotations

import dnfile

from dnfile.signature import build_signature_view, compare_views
from tests.support.pebuild import (
    AssemblyRefSpec, AssemblySpec, FieldSpec, GenericParamSpec, MetadataModel,
    MethodSpec, ParamSpec, TypeDefSpec, TypeRefSpec, array_shape, build_pe,
    class_ref, generic_inst, mvar, szarray, var,
)


def build_model(constraint_rid: int, param_element: bytes) -> MetadataModel:
    type_refs = [
        TypeRefSpec("Object", "System", "mscorlib"),
        TypeRefSpec("Int32", "System", "mscorlib"),
        TypeRefSpec("String", "System", "mscorlib"),
        TypeRefSpec("IComparable", "System", "mscorlib"),
        TypeRefSpec("IConvertible", "System", "mscorlib"),
    ]
    map_signature = (
        bytes([0x20 | 0x10, 0x01, 0x02])
        + generic_inst("TypeDef", 2, [mvar(0)])
        + var(0)
        + param_element
    )
    return MetadataModel(
        assembly=AssemblySpec("HeapSwapApi"),
        assembly_refs=[AssemblyRefSpec("mscorlib")],
        type_refs=type_refs,
        type_specs=[szarray(class_ref("TypeRef", 3))],
        type_defs=[
            TypeDefSpec(
                "Container", "Api", 0x000001, ("TypeRef", 1),
                fields=[
                    FieldSpec("Matrix", bytes([0x06]) + array_shape(bytes([0x08]), 2, [3, 4], [0, 0])),
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


def view_for(model: MetadataModel, layout: str):
    pe = dnfile.dnPE(data=build_pe(model, layout))
    return build_signature_view(pe)


def main() -> None:
    from tests.support.pebuild import ELEMENT_I4, ELEMENT_STRING

    baseline = build_model(constraint_rid=4, param_element=szarray(mvar(0)))
    changed = build_model(constraint_rid=5, param_element=bytes([ELEMENT_I4]))

    view_a = view_for(baseline, "canonical")
    view_b = view_for(baseline, "shuffled")
    view_c = view_for(changed, "shuffled")

    print("== A (canonical) vs B (heap-only swap) ==")
    diff_ab = compare_views(view_a, view_b)
    print("changes:", [change.describe() for change in diff_ab] or "none - API identical")

    print()
    print("== B (heap-only swap) vs C (parameter type + generic constraint) ==")
    for change in compare_views(view_b, view_c):
        print("-", change.kind, change.member)

    print()
    print("unresolved references in B:", view_b.unresolved_keys() or "none")


if __name__ == "__main__":
    main()
