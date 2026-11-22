# -*- coding: utf-8 -*-
"""End-to-end ABI responsibility checks on ordinary synthetic assemblies.

The scenarios mirror the maintenance-team brief:

* an old interface that remains provably supported;
* a public interface whose identity demonstrably changed;
* an entry whose evidence is incomplete because a referenced component is
  missing or not on the approved type-source list.

Row reordering is exercised explicitly so table-index movement can never be
misreported as an interface difference.
"""
from __future__ import annotations

import dnfile
import pytest

from abicheck import (
    AbiReport,
    EntrySpec,
    SupportedTypeSource,
    Verdict,
    compare_assemblies,
)
from abicheck.checker import AssemblyView
from abicheck.synthetic import (
    MethodSpec,
    ParamSpec,
    mdAssem,
    mdPublic,
    tdNotPublic,
    tdPublic,
)

from factory import (
    BOOL,
    I4,
    SCOPE_MSCORLIB,
    STRING,
    TypeRefModel,
    calculator_methods,
    make_calculator,
    make_calculator_with_contracts_ref,
    make_two_type_assembly,
)

APPROVED = (SupportedTypeSource(assembly_name="mscorlib"),)
ADD_ENTRY = EntrySpec("Acme.Calculator", "Add", ("int32", "int32"))
DESCRIBE_ENTRY = EntrySpec("Acme.Calculator", "Describe", ("int32", "string"))
TYPE_ENTRY = EntrySpec("Acme.Calculator")


def _verdict(report: AbiReport, entry: EntrySpec) -> Verdict:
    matches = [item for item in report.verdicts if item.entry == entry]
    assert len(matches) == 1
    return matches[0].verdict


# ---------------------------------------------------------------------------
# evidence material: the synthetic PE must remain an ordinary, parseable image
# ---------------------------------------------------------------------------

def test_synthetic_assembly_is_ordinary_managed_pe():
    data = make_calculator()
    pe = dnfile.dnPE(data=data)
    assert pe._warnings == []
    assert pe.net is not None
    assert pe.net.mdtables is not None
    names = {str(row.TypeName) for row in pe.net.mdtables.TypeDef.rows}
    assert "Calculator" in names
    method_names = {str(row.Name) for row in pe.net.mdtables.MethodDef.rows}
    assert {"Add", "Describe"}.issubset(method_names)
    assert [row.Name for row in pe.net.mdtables.AssemblyRef.rows] == ["mscorlib"]


def test_checker_never_writes_to_input_bytes():
    old = make_calculator()
    new = make_calculator()
    old_before, new_before = bytes(old), bytes(new)
    compare_assemblies(old, new, [ADD_ENTRY], APPROVED)
    assert bytes(old) == old_before
    assert bytes(new) == new_before


# ---------------------------------------------------------------------------
# supported contracts
# ---------------------------------------------------------------------------

def test_unchanged_entry_is_proven_supported():
    report = compare_assemblies(
        make_calculator(), make_calculator(), [ADD_ENTRY, DESCRIBE_ENTRY], APPROVED
    )
    assert _verdict(report, ADD_ENTRY) is Verdict.SUPPORTED
    assert _verdict(report, DESCRIBE_ENTRY) is Verdict.SUPPORTED


def test_table_row_reordering_is_not_an_interface_difference():
    # The second type occupies row 1 in the new build, pushing Calculator to
    # row 2; every member row index moves as well, but names and signatures
    # stay identical.
    old = make_two_type_assembly("Calculator", "Placeholder")
    new = make_two_type_assembly("Placeholder", "Calculator")
    report = compare_assemblies(old, new, [ADD_ENTRY, TYPE_ENTRY], APPROVED)
    assert _verdict(report, ADD_ENTRY) is Verdict.SUPPORTED
    assert _verdict(report, TYPE_ENTRY) is Verdict.SUPPORTED
    supported = report.by_verdict(Verdict.SUPPORTED)
    assert all("row position ignored" in " ".join(item.reasons) for item in supported)


def test_type_entry_supported_when_base_and_visibility_match():
    report = compare_assemblies(
        make_calculator(), make_calculator(), [TYPE_ENTRY], APPROVED
    )
    assert _verdict(report, TYPE_ENTRY) is Verdict.SUPPORTED


def test_widened_visibility_keeps_public_contract_supported():
    old = make_calculator(method_visibility=mdAssem)
    new = make_calculator(method_visibility=mdPublic)
    report = compare_assemblies(old, new, [ADD_ENTRY], APPROVED)
    assert _verdict(report, ADD_ENTRY) is Verdict.SUPPORTED
    assert any("widened" in reason for reason in report.verdicts[0].reasons)


# ---------------------------------------------------------------------------
# identity changes
# ---------------------------------------------------------------------------

def test_narrowed_visibility_changes_public_identity():
    report = compare_assemblies(
        make_calculator(method_visibility=mdPublic),
        make_calculator(method_visibility=mdAssem),
        [ADD_ENTRY],
        APPROVED,
    )
    item = report.verdicts[0]
    assert item.verdict is Verdict.IDENTITY_CHANGED
    assert any("visibility narrowed" in reason for reason in item.reasons)


def test_type_visibility_narrowing_is_an_identity_change():
    report = compare_assemblies(
        make_calculator(type_visibility=tdPublic),
        make_calculator(type_visibility=tdNotPublic),
        [TYPE_ENTRY],
        APPROVED,
    )
    assert report.verdicts[0].verdict is Verdict.IDENTITY_CHANGED


def test_renamed_type_breaks_method_and_type_identities():
    old = make_calculator()
    new = make_calculator(rename="CalculatorV2")
    report = compare_assemblies(
        old, new, [ADD_ENTRY, TYPE_ENTRY], APPROVED
    )
    assert all(item.verdict is Verdict.IDENTITY_CHANGED for item in report.verdicts)


def test_changed_parameter_type_changes_signature_identity():
    changed = [
        MethodSpec("Add", mdPublic, I4, [ParamSpec("a", I4), ParamSpec("b", BOOL)]),
        *calculator_methods()[1:],
    ]
    report = compare_assemblies(
        make_calculator(), make_calculator(methods=changed), [ADD_ENTRY], APPROVED
    )
    item = report.verdicts[0]
    assert item.verdict is Verdict.IDENTITY_CHANGED
    assert any("signature" in reason for reason in item.reasons)


def test_changed_return_type_changes_signature_identity():
    methods = calculator_methods()
    methods[0] = MethodSpec(
        "Add", mdPublic, STRING, [ParamSpec("a", I4), ParamSpec("b", I4)]
    )
    report = compare_assemblies(
        make_calculator(), make_calculator(methods=methods), [ADD_ENTRY], APPROVED
    )
    assert report.verdicts[0].verdict is Verdict.IDENTITY_CHANGED


def test_removed_member_is_an_identity_change():
    surviving = calculator_methods()[1:]
    report = compare_assemblies(
        make_calculator(), make_calculator(methods=surviving), [ADD_ENTRY], APPROVED
    )
    assert report.verdicts[0].verdict is Verdict.IDENTITY_CHANGED
    assert "missing" in report.verdicts[0].reasons[0]


def test_inheritance_change_is_reported_on_type_entry():
    # Old base: System.Object (TypeRef row 1). New base: a different TypeRef.
    new = make_calculator(
        extra_type_refs=[TypeRefModel("Component", "System", SCOPE_MSCORLIB)],
        base_ref_row=2,
    )
    report = compare_assemblies(make_calculator(), new, [TYPE_ENTRY], APPROVED)
    item = report.verdicts[0]
    assert item.verdict is Verdict.IDENTITY_CHANGED
    assert any("base type changed" in reason for reason in item.reasons)


# ---------------------------------------------------------------------------
# unresolved evidence
# ---------------------------------------------------------------------------

def test_unapproved_external_parameter_type_is_unresolved():
    # The parameter type comes from an assembly that is not on the approved
    # source list, so its identity cannot be accepted as evidence.
    data = make_calculator_with_contracts_ref(component_name="Acme.Contracts")
    entry = EntrySpec(
        "Acme.Calculator", "ThrowIt", ("class Acme.Contracts.ServiceException",)
    )
    report = compare_assemblies(data, data, [entry], APPROVED)
    item = report.verdicts[0]
    assert item.verdict is Verdict.UNRESOLVED
    assert any("unapproved component" in reason for reason in item.reasons)


def test_approved_source_promotes_external_type_to_resolved():
    data = make_calculator_with_contracts_ref(component_name="Acme.Contracts")
    sources = APPROVED + (SupportedTypeSource(assembly_name="Acme.Contracts"),)
    entry = EntrySpec(
        "Acme.Calculator", "ThrowIt", ("class Acme.Contracts.ServiceException",)
    )
    report = compare_assemblies(data, data, [entry], sources)
    assert report.verdicts[0].verdict is Verdict.SUPPORTED


def test_missing_resolution_scope_cannot_be_decided():
    # The TypeRef names a component but the AssemblyRef row it points at is
    # absent from the metadata (the upgrade package dropped the component).
    data = make_calculator_with_contracts_ref(include_assembly_ref=False)
    pe = dnfile.dnPE(data=data)
    view = AssemblyView(pe, "probe", APPROVED)
    ghost = pe.net.mdtables.TypeRef.rows[-1]
    name, ok, _ = view.resolve_typeref(ghost)
    assert name == "Acme.Contracts.ServiceException"
    assert ok is False
    assert view.unresolved_notes()


def test_reference_into_missing_component_is_unresolved_not_changed():
    # Both versions carry the dangling TypeRef; the checker must not turn the
    # missing component into a positive or a negative interface verdict.
    old = make_calculator_with_contracts_ref(include_assembly_ref=False)
    new = make_calculator_with_contracts_ref(include_assembly_ref=False)
    entry = EntrySpec(
        "Acme.Calculator", "ThrowIt", ("class Acme.Contracts.ServiceException",)
    )
    report = compare_assemblies(old, new, [entry], APPROVED)
    assert report.verdicts[0].verdict is Verdict.UNRESOLVED
    assert any("missing" in reason for reason in report.verdicts[0].reasons)


def test_unresolved_base_type_blocks_type_verdict():
    old = make_calculator()
    new = make_calculator(
        extra_type_refs=[TypeRefModel("Ghost", "Acme.Missing", (2, 99))],
        base_ref_row=2,
    )
    report = compare_assemblies(old, new, [TYPE_ENTRY], APPROVED)
    item = report.verdicts[0]
    assert item.verdict is Verdict.UNRESOLVED
    assert any("missing or unapproved component" in reason for reason in item.reasons)


# ---------------------------------------------------------------------------
# signature interpretation details
# ---------------------------------------------------------------------------

def test_signature_interpreter_distinguishes_byref_and_array():
    view = AssemblyView(dnfile.dnPE(data=make_calculator()), "probe", APPROVED)
    byref_sig = bytes([0x20, 0x01, 0x01, 0x10, 0x08])  # static, 1 byref int32 -> void
    array_sig = bytes([0x20, 0x01, 0x01, 0x1D, 0x08])  # static, 1 int32[] -> void
    from abicheck.checker import _BlobReader

    byref = view.read_type(_BlobReader(byref_sig[3:]))
    array = view.read_type(_BlobReader(array_sig[3:]))
    assert byref.text == "int32&"
    assert array.text == "int32[]"
    assert byref.text != array.text


def test_generic_instantiation_is_interpreted_textually():
    view = AssemblyView(dnfile.dnPE(data=make_calculator()), "probe", APPROVED)
    # GENERICINST CLASS <TypeDefOrRef coded token> <arg count> int32.
    # Coded token (row << 2) | tag, tag 1 == TypeRef; row 1 exists (System.Object).
    coded = (1 << 2) | 1
    blob = bytes([0x15, 0x12]) + bytes([coded]) + bytes([0x01, 0x08])
    from abicheck.checker import _BlobReader

    ref = view.read_type(_BlobReader(blob))
    assert "System.Object" in ref.text
    assert "<int32>" in ref.text


def test_report_groups_verdicts_for_callers():
    old = make_calculator()
    new = make_calculator(method_visibility=mdAssem)
    report = compare_assemblies(
        old, new, [ADD_ENTRY, DESCRIBE_ENTRY], APPROVED
    )
    assert {item.verdict for item in report.verdicts} == {Verdict.IDENTITY_CHANGED}
    assert len(report.by_verdict(Verdict.SUPPORTED)) == 0
    assert len(report.by_verdict(Verdict.IDENTITY_CHANGED)) == 2


def test_byref_parameter_direction_changes_identity():
    # Same parameter type name but a different calling direction (byref)
    # must not be treated as an unchanged signature.
    from abicheck.synthetic import ELEMENT_TYPE_I4 as ET_I4

    byref_blob = bytes([0x10, ET_I4])
    changed = [
        MethodSpec(
            "Add",
            mdPublic,
            I4,
            [ParamSpec("a", I4), ParamSpec("b", byref_blob)],
        ),
        *calculator_methods()[1:],
    ]
    report = compare_assemblies(
        make_calculator(), make_calculator(methods=changed), [ADD_ENTRY], APPROVED
    )
    item = report.verdicts[0]
    assert item.verdict is Verdict.IDENTITY_CHANGED
    assert any("signature" in reason for reason in item.reasons)


def test_entry_absent_from_old_assembly_is_unresolved_not_asserted():
    ghost = EntrySpec("Acme.DoesNotExist", "Whatever")
    report = compare_assemblies(make_calculator(), make_calculator(), [ghost], APPROVED)
    assert report.verdicts[0].verdict is Verdict.UNRESOLVED


def test_overloads_are_distinguished_by_parameter_key():
    overloads = calculator_methods() + [
        MethodSpec(
            "Add",
            mdPublic,
            BOOL,
            [ParamSpec("flag", BOOL)],
        )
    ]
    data = make_calculator(methods=overloads)
    int_entry = EntrySpec("Acme.Calculator", "Add", ("int32", "int32"))
    bool_entry = EntrySpec("Acme.Calculator", "Add", ("bool",))
    report = compare_assemblies(data, data, [int_entry, bool_entry], APPROVED)
    assert all(item.verdict is Verdict.SUPPORTED for item in report.verdicts)
