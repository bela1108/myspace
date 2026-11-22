# -*- coding: utf-8 -*-
"""Shared in-memory assembly factories for ABI checker tests."""
from __future__ import annotations

from typing import List, Optional, Tuple

from abicheck.synthetic import (
    AssemblyModel,
    AssemblyRefModel,
    ELEMENT_TYPE_BOOLEAN,
    ELEMENT_TYPE_I4,
    ELEMENT_TYPE_STRING,
    FieldSpec,
    MethodSpec,
    ParamSpec,
    TypeRefModel,
    TypeSpecModel,
    build_assembly_bytes,
    fdPublic,
    mdPublic,
    field_signature,
    tdBeforeFieldInit,
    tdNotPublic,
    tdPublic,
    type_ref_blob,
)

I4 = bytes((ELEMENT_TYPE_I4,))
BOOL = bytes((ELEMENT_TYPE_BOOLEAN,))
STRING = bytes((ELEMENT_TYPE_STRING,))

# ResolutionScope AssemblyRef is coded tag 2, row 1 (single AssemblyRef).
SCOPE_MSCORLIB = (2, 1)


def object_ref() -> TypeRefModel:
    return TypeRefModel("Object", "System", SCOPE_MSCORLIB)


def string_ref_blob(typeref_row: int = 2) -> bytes:
    # TypeDefOrRef tag 1 == TypeRef.
    return type_ref_blob(1, typeref_row)


def calculator_methods(visibility: int = mdPublic) -> List[MethodSpec]:
    return [
        MethodSpec(
            "Add",
            visibility,
            I4,
            [ParamSpec("a", I4), ParamSpec("b", I4)],
        ),
        MethodSpec(
            "Describe",
            visibility,
            STRING,
            [ParamSpec("id", I4), ParamSpec("label", STRING)],
        ),
    ]


def make_calculator(
    *,
    type_visibility: int = tdPublic,
    method_visibility: int = mdPublic,
    methods: Optional[List[MethodSpec]] = None,
    extra_type_refs: Optional[List[TypeRefModel]] = None,
    type_order: Tuple[str, ...] = ("Calculator",),
    rename: Optional[str] = None,
    base_ref_row: int = 1,
    assembly_name: str = "Contra.Legacy",
) -> bytes:
    type_refs = [object_ref()]
    if extra_type_refs:
        type_refs.extend(extra_type_refs)

    calc = TypeSpecModel(
        name=rename or "Calculator",
        namespace="Acme",
        flags=type_visibility | tdBeforeFieldInit,
        extends=(1, base_ref_row),
        methods=methods if methods is not None else calculator_methods(method_visibility),
        fields=[FieldSpec("MaxValue", fdPublic, field_signature(I4))],
    )
    placeholder = TypeSpecModel(
        name="Placeholder",
        namespace="Acme",
        flags=tdNotPublic | tdBeforeFieldInit,
        extends=(1, base_ref_row),
        methods=[],
    )
    by_name = {"Calculator": calc, "Placeholder": placeholder}
    types = [by_name[key] for key in type_order]
    model = AssemblyModel(
        name=assembly_name,
        assembly_refs=[AssemblyRefModel("mscorlib", (4, 0, 0, 0))],
        type_refs=type_refs,
        types=types,
    )
    return build_assembly_bytes(model)


def make_two_type_assembly(
    first: str, second: str, *, visibility_first: int = tdPublic, visibility_second: int = tdPublic
) -> bytes:
    types = [
        TypeSpecModel(
            name=name,
            namespace="Acme",
            flags=visibility | tdBeforeFieldInit,
            extends=(1, 1),
            methods=calculator_methods() if name == "Calculator" else [],
        )
        for name, visibility in ((first, visibility_first), (second, visibility_second))
    ]
    model = AssemblyModel(
        name="Contra.Legacy",
        assembly_refs=[AssemblyRefModel("mscorlib")],
        type_refs=[object_ref()],
        types=types,
    )
    return build_assembly_bytes(model)


def make_calculator_with_contracts_ref(
    *,
    component_name: str = "Acme.Contracts",
    include_assembly_ref: bool = True,
) -> bytes:
    """Build Calculator.ThrowIt(error: ServiceException).

    When ``include_assembly_ref`` is False the TypeRef still names the
    component through its ResolutionScope, but the referenced AssemblyRef row
    is absent, simulating an upgrade package that dropped the component.
    """
    contracts_ref = TypeRefModel("ServiceException", "Acme.Contracts", SCOPE_MSCORLIB)
    methods = [
        MethodSpec(
            "ThrowIt",
            mdPublic,
            bytes((0x01,)),
            [ParamSpec("error", type_ref_blob(1, 2))],
        ),
    ]
    refs = [AssemblyRefModel(component_name)] if include_assembly_ref else []
    model = AssemblyModel(
        name="Contra.Legacy",
        assembly_refs=refs,
        type_refs=[object_ref(), contracts_ref],
        types=[
            TypeSpecModel(
                name="Calculator",
                namespace="Acme",
                flags=tdPublic | tdBeforeFieldInit,
                extends=(1, 1),
                methods=methods,
            )
        ],
    )
    return build_assembly_bytes(model)
