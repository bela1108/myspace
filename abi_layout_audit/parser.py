"""Parse preprocessed C declarations and detect unsupported layout rules.

The input is expected to already be preprocessed (cpp -P / gcc -E output):
pycparser has no preprocessor of its own.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from pycparser import c_ast, c_parser

from .config import canonical_type_name
from .errors import AuditError, Location


@dataclass(frozen=True)
class UnsupportedRule:
    """A packing/alignment rule the layout engine does not claim to model."""

    kind: str
    message: str
    location: Location


@dataclass
class ParsedUnit:
    ast: c_ast.FileAST
    filename: str
    unsupported: list[UnsupportedRule] = field(default_factory=list)
    typedef_nodes: dict = field(default_factory=dict)
    composites: dict = field(default_factory=dict)
    enum_constants: dict = field(default_factory=dict)

    def type_text(self, node: c_ast.IdentifierType) -> str:
        return canonical_type_name(node.names)


_PACKED_NAMES = {"packed", "__packed__"}
_ALIGN_ATTRIBUTE_NAMES = {"aligned", "__aligned__", "align"}
_PACK_PRAGMA_RE = re.compile(r"^\s*pack\s*(?:\(|$)")


def parse_c_source(source: str, filename: str = "<input>") -> ParsedUnit:
    """Parse preprocessed C text with the C23 dialect enabled."""

    parser = c_parser.CParser(dialect="c23")
    try:
        ast = parser.parse(source, filename=filename)
    except c_parser.ParseError as exc:
        raise AuditError(
            f"failed to parse {filename}: {exc}. The input must be valid, "
            "fully preprocessed C declarations; GNU __attribute__ spellings "
            "not understood by pycparser must be removed by preprocessing."
        ) from exc
    unit = ParsedUnit(ast=ast, filename=filename)
    unit.unsupported = _scan_unsupported(ast, filename)
    _build_registries(ast, unit)
    return unit


def read_c_file(path: str) -> ParsedUnit:
    with open(path, encoding="utf-8") as handle:
        return parse_c_source(handle.read(), filename=path)


parse_source = parse_c_source


def _coordinate(coord, fallback_file: str) -> Location:
    if coord is None or getattr(coord, "line", None) is None:
        return Location(fallback_file, 0, 0)
    return Location(coord.file or fallback_file, coord.line,
                    coord.column or 0)


def _build_registries(ast: c_ast.FileAST, unit: ParsedUnit) -> None:
    def walk(node: c_ast.Node) -> None:
        if isinstance(node, c_ast.Typedef):
            unit.typedef_nodes[node.name] = node.type
        elif (isinstance(node, (c_ast.Struct, c_ast.Union))
              and node.name and node.decls is not None):
            unit.composites[node.name] = node
        elif isinstance(node, c_ast.Enum) and node.values:
            for enumerator in node.values.enumerators:
                unit.enum_constants[enumerator.name] = _enumerator_value(
                    enumerator, unit.enum_constants)
        for child in node:
            walk(child)

    walk(ast)


def _enumerator_value(enumerator: c_ast.Enumerator, known: dict) -> int:
    if enumerator.value is None:
        return (max(known.values()) + 1) if known else 0
    from .evaluator import ConstantEvaluator

    return ConstantEvaluator(known).evaluate(enumerator.value)


def _scan_unsupported(ast: c_ast.FileAST,
                      filename: str) -> list[UnsupportedRule]:
    findings: list[UnsupportedRule] = []
    seen: set[tuple[str, int, str]] = set()

    def add(kind: str, message: str, coord) -> None:
        location = _coordinate(coord, filename)
        key = (kind, location.line, message)
        if key not in seen:
            seen.add(key)
            findings.append(UnsupportedRule(kind, message, location))

    def visit(node: c_ast.Node) -> None:
        if isinstance(node, c_ast.Pragma):
            text = node.string or ""
            if _PACK_PRAGMA_RE.match(text):
                add("pack_pragma",
                    f"#pragma {text} overrides ordinary ABI packing",
                    node.coord)
            elif "ms_struct" in text or "gcc_struct" in text:
                add("layout_pragma",
                    f"#pragma {text} changes member layout rules",
                    node.coord)
        elif isinstance(node, c_ast.AttributedType):
            for specifier in node.attributes or []:
                for attribute in _iter_attributes(specifier):
                    if attribute.name in _PACKED_NAMES:
                        add("packed_attribute",
                            f"attribute {_format_attribute(attribute)} "
                            "requests packed layout",
                            attribute.coord or specifier.coord)
                    elif attribute.name in _ALIGN_ATTRIBUTE_NAMES:
                        add("aligned_attribute",
                            f"attribute {_format_attribute(attribute)} "
                            "forces alignment",
                            attribute.coord or specifier.coord)
        elif isinstance(node, c_ast.Struct) and node.attributes:
            add("struct_attribute",
                "struct carries GNU-style layout attributes", node.coord)
        for child in node:
            visit(child)

    visit(ast)
    findings.sort(key=lambda item: (item.location.line, item.kind))
    return findings


def _iter_attributes(specifier: c_ast.AttributeSpecifier):
    for attribute in specifier.attributes or []:
        if isinstance(attribute, c_ast.Attribute):
            yield attribute


def _format_attribute(attribute: c_ast.Attribute) -> str:
    namespace = f"{attribute.namespace}::" if attribute.namespace else ""
    return f"[[{namespace}{attribute.name}]]"


def iter_pragmas(ast: c_ast.FileAST):
    """Yield every surviving pragma node in document order."""

    def walk(node: c_ast.Node):
        if isinstance(node, c_ast.Pragma):
            yield node
        for child in node:
            yield from walk(child)

    yield from walk(ast)
