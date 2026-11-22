"""Parser registries, unsupported-rule detection and constant folding."""

from __future__ import annotations

import pytest

from abi_layout_audit.errors import AuditError, LayoutUnsupportedError
from abi_layout_audit.evaluator import ConstantEvaluator
from abi_layout_audit.parser import parse_c_source


def test_registries_index_typedefs_composites_and_enums():
    unit = parse_c_source(
        "typedef int my_int; enum color { RED, GREEN = 5 };"
        "struct A { my_int x; }; union B { int a; char b; };")
    assert "my_int" in unit.typedef_nodes
    assert "A" in unit.composites and "B" in unit.composites
    assert unit.enum_constants["RED"] == 0
    assert unit.enum_constants["GREEN"] == 5


def test_forward_composite_definition_is_resolved():
    unit = parse_c_source(
        "struct node; struct node { int value; };"
        "struct holder { struct node child; };")
    definition = unit.composites["node"]
    assert definition.decls is not None
    holder = unit.composites["holder"]
    assert holder.decls is not None


def test_pack_pragma_is_detected_with_location():
    unit = parse_c_source(
        "#pragma pack(1)\nstruct S { char a; int b; };")
    kinds = {rule.kind for rule in unit.unsupported}
    assert "pack_pragma" in kinds
    pragma = next(rule for rule in unit.unsupported
                  if rule.kind == "pack_pragma")
    assert pragma.location.line == 1


def test_c23_packed_attribute_is_detected():
    unit = parse_c_source(
        "struct S { char a; int b; } [[gnu::packed]];")
    kinds = {rule.kind for rule in unit.unsupported}
    assert "packed_attribute" in kinds


def test_invalid_declarations_raise_audit_error():
    with pytest.raises(AuditError):
        parse_c_source("struct S { ;;; ")


def test_constant_evaluator_folds_enum_arithmetic():
    evaluator = ConstantEvaluator({"N": 3})
    from pycparser import c_parser

    ast = c_parser.CParser(dialect="c23").parse("int x[N * 2 + 1];")
    decl = ast.ext[0]
    dim = decl.type.dim
    assert evaluator.evaluate(dim) == 7


def test_constant_evaluator_rejects_unknown_identifier():
    evaluator = ConstantEvaluator({})
    from pycparser import c_parser

    ast = c_parser.CParser(dialect="c23").parse("int x[unknown_macro];")
    with pytest.raises(LayoutUnsupportedError):
        evaluator.evaluate(ast.ext[0].type.dim)
