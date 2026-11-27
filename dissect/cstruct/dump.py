from __future__ import annotations

import json
import os
import pprint
import re
import string
from collections.abc import Mapping
from enum import Enum
from fnmatch import fnmatchcase
from itertools import pairwise
from typing import TYPE_CHECKING, Any, Literal

from dissect.cstruct.expression import Expression
from dissect.cstruct.lexer import Lexer, TokenType
from dissect.cstruct.types.base import BaseArray
from dissect.cstruct.types.enum import EnumMetaType
from dissect.cstruct.types.pointer import Pointer
from dissect.cstruct.types.structure import Structure, Union, UnionProxy

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

    from dissect.cstruct.types.base import BaseType


# Regular ANSI colors
COLOR_RED = "\033[0;31m"
COLOR_GREEN = "\033[0;32m"
COLOR_YELLOW = "\033[0;93m"
COLOR_BLUE = "\033[0;34m"
COLOR_PURPLE = "\033[0;35m"
COLOR_CYAN = "\033[0;36m"
COLOR_WHITE = "\033[0;37m"
COLOR_BLACK = "\033[0;30m"
COLOR_GREY = "\033[0;90m"

# Bold ANSI colors
COLOR_RED_BOLD = "\033[1;31m"
COLOR_GREEN_BOLD = "\033[1;32m"
COLOR_YELLOW_BOLD = "\033[1;33m"
COLOR_BLUE_BOLD = "\033[1;34m"
COLOR_PURPLE_BOLD = "\033[1;35m"
COLOR_CYAN_BOLD = "\033[1;36m"
COLOR_WHITE_BOLD = "\033[1;37m"
COLOR_BLACK_BOLD = "\033[1;30m"
COLOR_GREY_BOLD = "\033[1;90m"

# Background ANSI colors
COLOR_BG_RED = "\033[1;41m\033[1;37m"
COLOR_BG_GREEN = "\033[1;42m\033[1;37m"
COLOR_BG_YELLOW = "\033[1;43m\033[1;37m"
COLOR_BG_BLUE = "\033[1;44m\033[1;37m"
COLOR_BG_PURPLE = "\033[1;45m\033[1;37m"
COLOR_BG_CYAN = "\033[1;46m\033[1;37m"
COLOR_BG_WHITE = "\033[1;47m\033[1;30m"

# Reset ANSI codes
COLOR_CLEAR = "\033[0m"

PRINTABLE = string.digits + string.ascii_letters + string.punctuation + " "


Palette = list[tuple[int, str]]


def _human_colors() -> dict[str, str]:
    """Generates a dictionary of characters with a human-readable ANSI color they should be in a hexdump.

    Coloring logic implementation derived from HexFriend and ImHex.
    """
    # Make all characters not in any rules below light green
    colors = {chr(char): COLOR_GREEN for char in range(256)}

    # Make all 7-bit ASCII characters yellow
    for char in colors:
        if ord(char) & 0x80 == 0:
            colors[char] = COLOR_YELLOW

    # Make null bytes grey
    colors["\00"] = COLOR_GREY

    # Make printable ASCII characters bold white (0x32-0x7E)
    for char in PRINTABLE:
        colors[char] = COLOR_WHITE_BOLD

    # Make ASCII whitespace characters green bold (0x9, 0xA, 0xB, 0xC, 0xD, 0x20)
    for char in ("\t", "\n", "\v", "\f", "\r", " "):
        colors[char] = COLOR_GREEN_BOLD

    return colors


HUMAN_COLORS = _human_colors()


def _hexdump(
    data: bytes,
    *,
    palette: Palette | None = None,
    offset: int = 0,
    prefix: str = "",
    pretty: bool | None = False,
    autoskip: bool = False,
) -> Iterator[str]:
    """Hexdump some data.

    Args:
        data: Bytes to hexdump.
        palette: Colorize the hexdump using this color pattern. An empty color leaves those bytes uncolored.
        offset: Byte offset of the hexdump.
        prefix: Optional prefix.
        pretty: Use pretty colors, mutual exclusive with palette.
        autoskip: A single '*' replaces NUL-lines in the output.
    """
    if palette:
        palette = palette[::-1]

    # only happy little accidents
    if pretty and palette:
        raise ValueError("Cannot use argument 'pretty' in combination with 'palette', please pick one")

    remaining = 0
    active = None
    in_null_run = False
    in_collapsed_null_run = False
    last_offset = len(data) - 16

    for i in range(0, len(data), 16):
        values = ""
        chars = []

        for j in range(16):
            if remaining <= 0 and palette:
                remaining, active = palette.pop()
                while remaining == 0:
                    if len(palette) == 0:
                        # Last palette tuple is empty: print remaining whitespaces
                        active = ""
                        break
                    else:
                        remaining, active = palette.pop()
                values += active
            elif active and j == 0:
                values += active

            if i + j >= len(data):
                values += "  "
            else:
                char = data[i + j]
                char = chr(char)

                print_char = char if char in PRINTABLE else "."

                if active:
                    values += f"{ord(char):02x}"
                    chars.append(active + print_char + COLOR_CLEAR)
                else:
                    if pretty and (color := HUMAN_COLORS.get(char, "")):
                        values += f"{color}{ord(char):02x}{COLOR_CLEAR}"
                        chars.append(color + print_char + COLOR_CLEAR)
                    else:
                        values += f"{ord(char):02x}"
                        chars.append(print_char)

                remaining -= 1
                if remaining == 0:
                    active = None

                    if palette is not None:
                        values += COLOR_CLEAR

                if j == 15 and palette is not None:
                    values += COLOR_CLEAR

            values += " "
            if j == 7:
                values += " "

        if autoskip and 0 < i < last_offset and data[i : i + 16] == b"\x00" * 16:
            if in_null_run:
                if not in_collapsed_null_run:
                    yield "*"
                    in_collapsed_null_run = True
                continue

            # Keep the first interior NUL line visible, collapse from the second onwards.
            in_null_run = True
        else:
            in_null_run = False
            in_collapsed_null_run = False

        chars = "".join(chars)
        yield f"{prefix}{offset + i:08x}  {values:48s}  {chars}"


def hexdump(
    data: bytes,
    *,
    palette: Palette | None = None,
    offset: int = 0,
    prefix: str = "",
    output: Literal["print", "generator", "string"] = "print",
    pretty: bool | None = None,
    autoskip: bool = False,
) -> Iterator[str] | str | None:
    """Hexdump some data.

    Uses colored ANSI output with output type "print" by default. Disable with ``pretty=False``
    or set the environment variable ``NO_COLOR``.

    Args:
        data: Bytes to hexdump.
        palette: Colorize the hexdump using this color pattern.
        offset: Byte offset of the hexdump.
        prefix: Optional prefix.
        output: Output format, can be 'print', 'generator' or 'string'.
        pretty: Use pretty colors for improved human readability.
        autoskip: A single '*' replaces NUL-lines in the output.
    """
    # Enable pretty colors by default if ...
    if (
        output == "print"  # the output type is set to 'print'
        and not palette  # no palette is given (structdump only)
        and pretty is not False  # pretty was not explicitly set to False
        and not os.environ.get("NO_COLOR")  # and the environment allows colors
    ):
        pretty = True

    generator = _hexdump(data, palette=palette, offset=offset, prefix=prefix, pretty=pretty, autoskip=autoskip)
    if output == "print":
        print("\n".join(generator))
        return None
    if output == "generator":
        return generator
    if output == "string":
        return "\n".join(list(generator))
    raise ValueError(f"Invalid output argument: {output!r} (should be 'print', 'generator' or 'string').")


def _format_value(value: Any) -> str | None:
    """Format a structure field value for human-readable display."""
    if value is None:
        return None
    if isinstance(value, (str, Pointer, Enum)):
        return repr(value)
    if isinstance(value, int):
        return hex(value)
    if isinstance(value, list):
        return pprint.pformat(value)
    return str(value)


def _describe_fields(structure: Structure, start: int | None) -> list[dict[str, Any]]:
    """Describe the fields of ``structure`` as nodes, with offsets into the dumped data.

    The offsets follow ``Structure._read``: explicit field offsets, alignment padding and bit fields sharing a
    storage unit. They are ``None`` after a field of unknown size, e.g. a dynamic field of a structure that
    wasn't parsed.
    """
    nodes: list[dict[str, Any]] = []
    sizes = structure.__sizes__
    is_union = isinstance(structure, Union)

    offset = start
    bits_type = None
    bits_offset = None
    bits_remaining = 0

    for field in structure.__class__.__fields__:
        if field.offset is not None and start is not None:
            offset = start + field.offset
        elif is_union:
            offset = start
        elif structure.__align__ and offset is not None:
            offset += -offset & (field.alignment - 1)

        # Of fields with a repeated name ("_"), a structure only keeps the value and size of the last one
        if structure.__class__.__lookup__[field._name] is field:
            value, size = getattr(structure, field._name), sizes.get(field._name)
        else:
            value, size = None, field.type.__size__

        if field.bits:
            field_type = field.type.__type__ if isinstance(field.type, EnumMetaType) else field.type
            # Like BitBuffer, start a new storage unit when the current one is full or the type changes
            if bits_remaining == 0 or field_type != bits_type:
                bits_type = field_type
                bits_offset = offset
                bits_remaining = field_type.__size__ * 8
                if offset is not None:
                    offset += field_type.__size__

            bits_remaining -= field.bits
            nodes.append(
                {
                    "name": field._name,
                    "type": field.type.__name__,
                    "offset": bits_offset,
                    "size": field_type.__size__,
                    "bits": field.bits,
                    "display": _format_value(value),
                }
            )
            continue

        bits_type = None

        # Anonymous struct/union members have no name, their fields are accessed on the parent
        name = None if field.name is None else f"{field.name}{_array_dimensions(field.type)[1]}"
        nodes.append(_describe_value(name, field.type, value, offset, size))

        if offset is not None:
            offset = None if size is None else offset + size

    return nodes


def _describe_value(
    name: str | None, type_: type[BaseType], value: Any, offset: int | None, size: int | None
) -> dict[str, Any]:
    """Describe a field or array element as a node.

    Structures and unions, and arrays of them, get their fields or elements as child nodes. Other values, including
    arrays of other types, are formatted as a human-readable ``display``.
    """
    if isinstance(value, UnionProxy):
        # Nested Structure members inside a Union are proxied; unwrap to the real Structure
        value = value.__target__

    base_type = _array_dimensions(type_)[0]
    is_structure = issubclass(base_type, Structure)
    node = {
        "name": name,
        "type": None if is_structure and base_type.__anonymous__ else base_type.__name__,
        "offset": offset,
        "size": size,
    }

    if isinstance(value, Structure):
        node["kind"] = "union" if isinstance(value, Union) else "struct"
        node["fields"] = _describe_fields(value, offset)
    elif is_structure and isinstance(value, list):
        node["kind"] = "array"
        node["fields"] = []
        element_type = type_.__type__
        for i, element in enumerate(value):
            element_node = _describe_value(f"[{i}]", element_type, element, offset, element_type.__size__)
            node["fields"].append(element_node)
            if offset is not None:
                offset = None if element_node["size"] is None else offset + element_node["size"]
    else:
        node["display"] = _format_value(value)

    if size is None and node["offset"] is not None and "fields" in node:
        # Parsing doesn't record the sizes of array elements, so a dynamic element ends where its last field ends
        ends = [
            child["offset"] + child["size"] for child in node["fields"] if None not in (child["offset"], child["size"])
        ]
        if len(ends) == len(node["fields"]):
            end = max(ends, default=node["offset"])
            if isinstance(value, Structure) and value.__align__:
                end += -end & (value.__alignment__ - 1)
            node["size"] = end - node["offset"]

    return node


def _array_dimensions(type_: type[BaseType]) -> tuple[type[BaseType], str]:
    """Return the element type of a (multi-dimensional) array type and its dimensions in C order, e.g. ``[2][3]``."""
    dimensions = ""
    while issubclass(type_, BaseArray):
        count = type_.__num_entries__
        dimensions += f"[{'' if count is None else count}]"
        type_ = type_.__type__
    return type_, dimensions


DUMP_COLORS = [
    (COLOR_RED_BOLD, COLOR_BG_RED),
    (COLOR_GREEN_BOLD, COLOR_BG_GREEN),
    (COLOR_YELLOW_BOLD, COLOR_BG_YELLOW),
    (COLOR_BLUE_BOLD, COLOR_BG_BLUE),
    (COLOR_PURPLE_BOLD, COLOR_BG_PURPLE),
    (COLOR_CYAN_BOLD, COLOR_BG_CYAN),
    (COLOR_WHITE_BOLD, COLOR_BG_WHITE),
]


def _render_fields(
    nodes: list[dict[str, Any]],
    indent: int,
    lines: list[tuple[int, str, str | None]],
    palette: Palette,
    colored_end: int,
) -> int:
    """Add an ``(indent, name, value)`` line per field to ``lines``, and the hexdump colors to ``palette``.

    Line ``i`` gets color ``i`` of ``DUMP_COLORS``. The bytes of a value or a union get the background color of
    their (first) line, unless they overlap bytes that are already colored, such as union members and bit fields
    after the first one in a storage unit. A struct leaves the coloring to its fields.

    Returns the end offset of the colored bytes.
    """
    for node in nodes:
        offset, size = node["offset"], node["size"]
        if ("display" in node or node["kind"] == "union") and offset is not None and size and offset >= colored_end:
            if offset > colored_end:
                # Leave padding uncolored
                palette.append((offset - colored_end, ""))
            palette.append((size, DUMP_COLORS[len(lines) % len(DUMP_COLORS)][1]))
            colored_end = offset + size

        if "fields" not in node:
            lines.append((indent, node["name"], node["display"]))
        elif node["name"] is None:
            colored_end = _render_fields(node["fields"], indent, lines, palette, colored_end)
        else:
            lines.append((indent, node["name"], None))
            colored_end = _render_fields(node["fields"], indent + 1, lines, palette, colored_end)

    return colored_end


def _unique_path(path: str, used: set[str]) -> str:
    """Return ``path``, suffixed with a counter if it was already used."""
    if path not in used:
        used.add(path)
        return path

    counter = 2
    while f"{path}#{counter}" in used:
        counter += 1

    path = f"{path}#{counter}"
    used.add(path)
    return path


def _node_aliases(node: dict[str, Any]) -> set[str]:
    """Return the names an approval entry can use to select a member."""
    aliases = set()

    if path := node.get("path"):
        aliases.add(path)
        aliases.add(re.sub(r"\[[^\]]*\]", "", path))
        aliases.add(path.rsplit(".", 1)[-1])

    if name := node.get("name"):
        aliases.add(name)

    if field := node.get("_field"):
        aliases.add(field._name)
        if field.name:
            aliases.add(field.name)

    return aliases


def _approval_match(node: dict[str, Any], allowlist: Iterable[str] | Mapping[str, bool]) -> bool | None:
    """Return the explicit approval for ``node``, or ``None`` if the allowlist doesn't mention it."""
    aliases = _node_aliases(node)

    if isinstance(allowlist, Mapping):
        result = None
        specificity = -1

        for pattern, approved in allowlist.items():
            if any(_matches_name(alias, pattern) for alias in aliases) and len(pattern) > specificity:
                result = bool(approved)
                specificity = len(pattern)

        return result

    if any(_matches_name(alias, pattern) for pattern in allowlist for alias in aliases):
        return True

    return None


def _matches_name(alias: str, pattern: str) -> bool:
    """Match a member name against an approval pattern, treating array brackets literally."""
    if alias == pattern:
        return True

    # fnmatch treats ``[`` and ``]`` as a character class; array indices are literal names here.
    pattern = pattern.replace("[*]", "*")
    pattern = pattern.replace("[", "[[]").replace("]", "[]]")
    return fnmatchcase(alias, pattern)


def _is_approved(node: dict[str, Any], allowlist: Iterable[str] | Mapping[str, bool] | None) -> bool:
    """Return whether ``node`` is approved, inheriting approval from its closest matching parent."""
    if allowlist is None:
        return True

    current = node
    while current is not None:
        if (match := _approval_match(current, allowlist)) is not None:
            return match
        current = current.get("_parent")

    return False


def _walk_nodes(nodes: list[dict[str, Any]]) -> Iterator[dict[str, Any]]:
    """Yield all nodes depth-first."""
    for node in nodes:
        yield node
        yield from _walk_nodes(node.get("fields", []))


def _is_ancestor(parent: dict[str, Any], child: dict[str, Any]) -> bool:
    """Return whether ``parent`` contains ``child`` in the member tree."""
    current = child.get("_parent")
    while current is not None:
        if current is parent:
            return True
        current = current.get("_parent")

    return False


def _fix_dynamic_size(node: dict[str, Any], value: Any) -> None:
    """Fill in an unknown size using the end of the last child, if all child sizes are known."""
    if node["size"] is not None or node["offset"] is None or "fields" not in node:
        return

    children = node["fields"]
    ends = [child["offset"] + child["size"] for child in children if None not in (child["offset"], child["size"])]
    if len(ends) != len(children):
        return

    end = max(ends, default=node["offset"])
    if isinstance(value, Structure) and value.__align__:
        end += -end & (value.__alignment__ - 1)

    node["size"] = end - node["offset"]


def _build_value_node(
    field: Any,
    value: Any,
    offset: int | None,
    size: int | None,
    prefix: str,
    parent: dict[str, Any] | None,
    used_paths: set[str],
) -> dict[str, Any]:
    """Build a member node for a structure field."""
    if isinstance(value, UnionProxy):
        value = value.__target__

    base_type, dimensions = _array_dimensions(field.type)
    is_structure = issubclass(base_type, Structure)
    path = None if field.name is None else _unique_path(f"{prefix}{field._name}", used_paths)
    child_prefix = f"{path}." if path else prefix

    node = {
        "name": None if field.name is None else f"{field.name}{dimensions}",
        "path": path,
        "type": None if is_structure and base_type.__anonymous__ else base_type.__name__,
        "offset": offset,
        "size": size,
        "_field": field,
        "_value": value,
        "_parent": parent,
        "_scope": None,
        "_order": None,
        "_is_element": False,
    }

    if isinstance(value, Structure):
        node["kind"] = "union" if isinstance(value, Union) else "struct"
        nested, _ = _build_nodes(value, offset, child_prefix, node, used_paths)
        node["fields"] = nested
        _fix_dynamic_size(node, value)
    elif is_structure and isinstance(value, list):
        node["kind"] = "array"
        node["fields"] = []
        element_type = field.type.__type__
        element_offset = offset

        for i, element in enumerate(value):
            if isinstance(element, UnionProxy):
                element = element.__target__

            element_path = _unique_path(f"{path or prefix}[{i}]", used_paths)
            element_node = {
                "name": f"[{i}]",
                "path": element_path,
                "type": None
                if issubclass(element_type, Structure) and element_type.__anonymous__
                else element_type.__name__,
                "offset": element_offset,
                "size": element_type.__size__,
                "_field": None,
                "_value": element,
                "_parent": node,
                "_scope": None,
                "_order": None,
                "_is_element": True,
            }

            if isinstance(element, Structure):
                element_node["kind"] = "union" if isinstance(element, Union) else "struct"
                nested, _ = _build_nodes(element, element_offset, f"{element_path}.", element_node, used_paths)
                element_node["fields"] = nested
                _fix_dynamic_size(element_node, element)

            node["fields"].append(element_node)
            if element_offset is not None:
                element_offset = None if element_node["size"] is None else element_offset + element_node["size"]

        _fix_dynamic_size(node, value)

    return node


def _build_nodes(
    structure: Structure,
    start: int | None,
    prefix: str,
    parent: dict[str, Any] | None,
    used_paths: set[str],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Build member nodes with absolute offsets for ``structure``."""
    nodes: list[dict[str, Any]] = []
    scope: dict[str, Any] = {"structure": structure, "by_name": {}, "nodes": []}
    sizes = structure.__sizes__
    is_union = isinstance(structure, Union)

    offset = start
    bits_type = None
    bits_offset = None
    bits_remaining = 0

    for order, field in enumerate(structure.__class__.__fields__):
        if field.offset is not None and start is not None:
            offset = start + field.offset
        elif is_union:
            offset = start
        elif structure.__align__ and offset is not None:
            offset += -offset & (field.alignment - 1)

        if structure.__class__.__lookup__[field._name] is field:
            value, size = getattr(structure, field._name), sizes.get(field._name)
        else:
            value, size = None, field.type.__size__

        if field.bits:
            field_type = field.type.__type__ if isinstance(field.type, EnumMetaType) else field.type
            if bits_remaining == 0 or field_type != bits_type:
                bits_type = field_type
                bits_offset = offset
                bits_remaining = field_type.__size__ * 8
                if offset is not None:
                    offset += field_type.__size__

            bits_remaining -= field.bits
            node = {
                "name": field._name,
                "path": _unique_path(f"{prefix}{field._name}", used_paths),
                "type": field.type.__name__,
                "offset": bits_offset,
                "size": field_type.__size__,
                "bits": field.bits,
                "_field": field,
                "_value": value,
                "_parent": parent,
                "_scope": scope,
                "_order": order,
                "_is_element": False,
            }
            nodes.append(node)
            scope["nodes"].append(node)
            scope["by_name"].setdefault(field._name, []).append((order, node))
            continue

        bits_type = None

        node = _build_value_node(field, value, offset, size, prefix, parent, used_paths)
        node["_scope"] = scope
        node["_order"] = order
        nodes.append(node)
        scope["nodes"].append(node)
        scope["by_name"].setdefault(field._name, []).append((order, node))

        if offset is not None:
            offset = None if size is None else offset + size

    return nodes, scope


def _expression_identifiers(expression: Expression) -> list[str]:
    """Return identifiers used by an array size expression, excluding ``sizeof`` and ``offsetof`` arguments."""
    tokens = Lexer(expression.expression).tokenize()
    identifiers = []
    i = 0

    while i < len(tokens):
        token = tokens[i]
        if token.type in (TokenType.SIZEOF, TokenType.OFFSETOF):
            i += 1
            if i < len(tokens) and tokens[i].type == TokenType.LPAREN:
                depth = 0
                while i < len(tokens):
                    if tokens[i].type == TokenType.LPAREN:
                        depth += 1
                    elif tokens[i].type == TokenType.RPAREN:
                        depth -= 1
                        if depth == 0:
                            i += 1
                            break
                    i += 1
            continue

        if token.type == TokenType.IDENTIFIER:
            identifiers.append(token.value)

        i += 1

    return identifiers


def _find_descendant(node: dict[str, Any], relative: str) -> dict[str, Any] | None:
    """Find a descendant of ``node`` by its path relative to that node."""
    if not node.get("path"):
        return None

    expected = f"{node['path']}.{relative}"
    for candidate in _walk_nodes(node.get("fields", [])):
        if candidate.get("path") == expected:
            return candidate

    return None


def _resolve_count_dependencies(node: dict[str, Any], expression: Expression) -> list[str]:
    """Resolve the fields a size expression references to their member paths."""
    scope = node.get("_scope")
    if scope is None:
        return []

    dependencies = []
    for identifier in _expression_identifiers(expression):
        if identifier == "EOF":
            continue

        parts = identifier.split(".")
        candidates = [
            candidate
            for candidate_order, candidate in scope["by_name"].get(parts[0], [])
            if candidate_order < node["_order"]
        ]
        if not candidates:
            continue

        candidate = max(candidates, key=lambda entry: entry["_order"])
        if len(parts) > 1:
            candidate = _find_descendant(candidate, ".".join(parts[1:])) or candidate

        if path := candidate.get("path"):
            dependencies.append(path)

    return dependencies


def _compute_dependencies(node: dict[str, Any], inherited: list[str] | None = None) -> list[str]:
    """Compute count dependencies for a node and its children, returning the node's dependencies."""
    direct = list(inherited or [])

    if (field := node.get("_field")) is not None and not field.bits:
        field_type = field.type
        while issubclass(field_type, BaseArray):
            if isinstance(field_type.__num_entries__, Expression):
                direct.extend(_resolve_count_dependencies(node, field_type.__num_entries__))
            field_type = field_type.__type__

    dependencies = list(direct)

    def _add(value: str) -> None:
        if value not in dependencies:
            dependencies.append(value)

    for child in node.get("fields", []):
        # Elements of an array inherit its count, but not the lengths of their sibling elements.
        child_inherited = direct if child.get("_is_element") else None
        for dependency in _compute_dependencies(child, child_inherited):
            _add(dependency)

    node["_dependencies"] = dependencies
    enough = bool(dependencies)
    node["_depends_on_count"] = enough

    return dependencies


def _restoration_status(node: dict[str, Any], nodes_by_path: dict[str, dict[str, Any]]) -> tuple[bool, str | None]:
    """Return whether an approved node can be interpreted from the approved slices, and why not."""
    if not node.get("_approved"):
        return False, None

    if node["offset"] is None:
        return False, "cannot be restored: the offset is unknown because a preceding member has an unknown length"

    if node["size"] is None:
        return (
            False,
            "cannot be restored: the size is unknown because the structure was not parsed and no byte length "
            "was recorded for this member",
        )

    missing = []
    for dependency in node.get("_dependencies", []):
        dependency_node = nodes_by_path.get(dependency)
        if (
            dependency_node is None
            or not dependency_node.get("_approved")
            or dependency_node["offset"] is None
            or dependency_node["size"] is None
        ):
            missing.append(dependency)

    if missing:
        names = ", ".join(repr(name) for name in missing)
        noun = "dependency" if len(missing) == 1 else "dependencies"
        return (
            False,
            f"cannot be restored: count {noun} {names} not included in the approved slices",
        )

    return True, None


def _collect_slices(nodes: list[dict[str, Any]], start: int, end: int) -> list[dict[str, int]]:
    """Return merged absolute byte ranges of all approved members."""
    intervals = []
    for node in nodes:
        if not node.get("_approved") or node["offset"] is None or node["size"] is None:
            continue

        node_start = max(node["offset"], start)
        node_end = min(node["offset"] + node["size"], end)
        if node_end > node_start:
            intervals.append((node_start, node_end))

    merged = []
    for interval_start, interval_end in sorted(intervals):
        if merged and interval_start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], interval_end))
        else:
            merged.append((interval_start, interval_end))

    return [
        {"offset": interval_start, "size": interval_end - interval_start} for interval_start, interval_end in merged
    ]


def _collect_shared(nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return byte segments shared by two or more members, excluding parent/child containment."""
    ranges = [
        (node, node["offset"], node["offset"] + node["size"])
        for node in nodes
        if node["offset"] is not None and node["size"] is not None and node["size"] > 0
    ]
    if len(ranges) < 2:
        return []

    boundaries = sorted({boundary for _, range_start, range_end in ranges for boundary in (range_start, range_end)})
    segments = []

    for segment_start, segment_end in pairwise(boundaries):
        active = [
            node for node, range_start, range_end in ranges if range_start < segment_end and range_end > segment_start
        ]
        visible = [
            node for node in active if not any(_is_ancestor(node, other) for other in active if other is not node)
        ]
        paths = [node["path"] for node in visible if node.get("path")]
        if len(paths) < 2:
            continue

        if segments and segments[-1][1] == segment_start and segments[-1][2] == paths:
            segments[-1] = (segments[-1][0], segment_end, paths)
        else:
            segments.append((segment_start, segment_end, paths))

    return [
        {"offset": segment_start, "size": segment_end - segment_start, "members": paths}
        for segment_start, segment_end, paths in segments
    ]


def _public_node(node: dict[str, Any]) -> dict[str, Any]:
    """Return the public form of a member node."""
    result = {
        "name": node["name"],
        "path": node["path"],
        "type": node["type"],
        "offset": node["offset"],
        "size": node["size"],
        "approved": bool(node.get("_approved")),
        "depends_on_count": bool(node.get("_depends_on_count")),
        "dependencies": list(node.get("_dependencies", [])),
        "shared_with": list(node.get("_shared_with", [])),
        "restorable": bool(node.get("_restorable")),
        "reason": node.get("_reason"),
    }

    if "bits" in node:
        result["bits"] = node["bits"]
    if "kind" in node:
        result["kind"] = node["kind"]
    if "fields" in node:
        result["fields"] = [_public_node(child) for child in node["fields"]]

    return result


def manifest(
    obj: Structure | type[Structure],
    data: bytes | None = None,
    offset: int = 0,
    allowlist: Iterable[str] | Mapping[str, bool] | None = None,
) -> dict[str, Any]:
    """Summarize the byte ranges, count dependencies and shared bytes of a structure.

    The returned member ranges are absolute positions in the complete local record: ``offset`` is added to every
    member, and the same positions are used for the returned ``slices``.  An allowlist selects which members may be
    released.  A member inherits approval from a matching parent, and patterns (e.g. ``items[*].length``) can select
    multiple members.  A mapping can be used to explicitly approve (``True``) or withhold (``False``) entries.

    Members whose size is derived from a count field record that field in ``dependencies``.  If the count is not
    approved, the member's bytes can still be located from the complete record, but the member cannot be interpreted
    from the approved slices alone; ``restorable`` is then ``False`` and ``reason`` explains the missing dependency.
    ``shared`` identifies byte ranges claimed by multiple members, such as union alternatives and bit fields.  When no
    allowlist is given, every member is approved.

    Args:
        obj: Parsed :class:`~dissect.cstruct.types.structure.Structure`, or a structure class with ``data``.
        data: Bytes of the complete local record, if ``obj`` is not already a parsed structure.
        offset: Absolute offset of the record in the complete local record.
        allowlist: Iterable of member names or patterns, or a mapping of names to approval status.

    Returns:
        A dictionary with the member tree, approved ``slices``, ``shared`` byte ranges and unrestorable members.
    """
    if isinstance(obj, Structure):
        data = obj.dumps() if data is None else data
    elif isinstance(obj, type) and issubclass(obj, Structure) and data is not None:
        obj = obj(data)
    else:
        raise ValueError("Invalid arguments: expected a Structure instance, or a Structure class with data.")

    if allowlist is not None and not isinstance(allowlist, Mapping):
        allowlist = [allowlist] if isinstance(allowlist, str) else list(allowlist)

    nodes, _ = _build_nodes(obj, offset, "", None, set())
    for node in nodes:
        _compute_dependencies(node)

    all_nodes = list(_walk_nodes(nodes))
    nodes_by_path = {node["path"]: node for node in all_nodes if node.get("path")}

    for node in all_nodes:
        node["_approved"] = _is_approved(node, allowlist)
        node["_shared_with"] = []

    shared = _collect_shared(all_nodes)
    for segment in shared:
        for path in segment["members"]:
            if node := nodes_by_path.get(path):
                for other in segment["members"]:
                    if other != path and other not in node["_shared_with"]:
                        node["_shared_with"].append(other)

    for node in all_nodes:
        node["_restorable"], node["_reason"] = _restoration_status(node, nodes_by_path)

    return {
        "type": obj.__class__.__name__,
        "kind": "union" if isinstance(obj, Union) else "struct",
        "offset": offset,
        "size": len(data),
        "fields": [_public_node(node) for node in nodes],
        "slices": _collect_slices(all_nodes, offset, offset + len(data)),
        "shared": shared,
        "unrestorable": [
            {"path": node["path"], "reason": node["_reason"]}
            for node in all_nodes
            if node.get("_approved") and not node.get("_restorable") and node.get("path")
        ],
    }


def _render_manifest(result: dict[str, Any]) -> str:
    """Render a :func:`manifest` result as human-readable text."""
    lines = [f"{result['kind']} {result['type']} at {result['offset']:#x} ({result['size']} bytes):"]

    def _add_fields(fields: list[dict[str, Any]], indent: int) -> None:
        for field in fields:
            label = field["path"] or field["name"] or "<anonymous>"
            status = "approved" if field["approved"] else "withheld"
            offsets = f"offset={field['offset']} size={field['size']}"
            details = [offsets, status]
            if field["dependencies"]:
                details.append(f"depends on {', '.join(field['dependencies'])}")
            if field["shared_with"]:
                details.append(f"shares bytes with {', '.join(field['shared_with'])}")
            if field["reason"]:
                details.append(field["reason"])

            lines.append(f"{'  ' * indent}- {label}: {', '.join(details)}")
            if "fields" in field:
                _add_fields(field["fields"], indent + 1)

    _add_fields(result["fields"], 1)
    slices = ", ".join(f"[{item['offset']:#x}, {item['offset'] + item['size']:#x})" for item in result["slices"])
    lines.append(f"slices: {slices or '(none)'}")

    lines.extend(
        [
            f"shared [{segment['offset']:#x}, {segment['offset'] + segment['size']:#x}): "
            f"{', '.join(segment['members'])}"
            for segment in result["shared"]
        ]
    )

    return "\n".join(lines) + "\n"


dumpstruct_manifest = manifest


def dumpstruct(
    obj: Structure | type[Structure],
    data: bytes | None = None,
    offset: int = 0,
    color: bool = True,
    autoskip: bool = False,
    output: Literal["print", "string", "dict", "json"] = "print",
    allowlist: Iterable[str] | Mapping[str, bool] | None = None,
) -> str | dict[str, Any] | None:
    """Dump a structure or parsed structure instance.

    Prints a colorized hexdump and parsed structure output.

    The ``dict`` and ``json`` output formats describe the structure as a tree:
        - bytes: hex string of the raw data
        - type: type name of the structure
        - kind: ``struct`` or ``union``
        - fields: list of field nodes

    A field node has a ``name``, ``type``, ``offset`` and ``size``, where ``offset`` is the position in ``bytes``.
    Values have a human-readable ``display``. Bit fields also have ``bits``, and share the ``offset`` and ``size`` of
    their storage unit. Nested structs and unions have a ``kind`` and ``fields`` instead of a ``display``, and so do
    arrays of them: ``kind`` is ``array`` and ``fields`` are the elements, named ``[0]``, ``[1]``, etc.
    Anonymous struct/union members (``struct { ... };``) have no ``name``, anonymous types have no ``type``.
    ``offset`` and ``size`` are ``None`` when they're unknown, and so is the ``display`` of a field the structure
    doesn't keep (all but the last of repeated ``_`` fields).

    For an array, ``name`` includes the dimensions as written in the definition and ``type`` is the element type,
    e.g. ``uint8 matrix[2][3];`` has ``name`` ``matrix[2][3]`` and ``type`` ``uint8``.

    Args:
        obj: :class:`~dissect.cstruct.types.structure.Structure` to dump.
        data: Bytes to parse the :class:`~dissect.cstruct.types.structure.Structure` on,
            if obj is not a parsed :class:`~dissect.cstruct.types.structure.Structure` already.
        offset: Byte offset of the hexdump.
        color: Colorize the hexdump and structure output.
        autoskip: A single '*' replaces NUL-lines in the output.
        output: Output format, can be ``print``, ``string``, ``dict`` or ``json``.
        allowlist: When given, return a :func:`manifest` of the members that may be released instead of a display
            dump. Members inherit approval from matching parents, and a mapping can explicitly withhold entries.

    Returns:
        Formatted string when ``output="string"``, a dict when ``output="dict"``,
        a JSON string when ``output="json"``, or ``None`` when ``output="print"``.
    """
    if output not in ("print", "string", "dict", "json"):
        raise ValueError(f"Invalid output argument: {output!r} (should be 'print', 'string', 'dict' or 'json').")

    if allowlist is not None:
        result = manifest(obj, data, offset, allowlist)
        if output == "dict":
            return result
        if output == "json":
            return json.dumps(result, indent=4)

        rendered = _render_manifest(result)
        if output == "print":
            print(rendered, end="")
            return None

        return rendered

    if isinstance(obj, Structure):
        data = obj.dumps() if data is None else data
    elif isinstance(obj, type) and issubclass(obj, Structure) and data is not None:
        obj = obj(data)
    else:
        raise ValueError("Invalid arguments: expected a Structure instance, or a Structure class with data.")

    result = {
        "bytes": data.hex(),
        "type": obj.__class__.__name__,
        "kind": "union" if isinstance(obj, Union) else "struct",
        "fields": _describe_fields(obj, 0),
    }

    if output in ("dict", "json"):
        return result if output == "dict" else json.dumps(result, indent=4)

    lines: list[tuple[int, str, str | None]] = []
    palette: Palette = []
    _render_fields(result["fields"], 0, lines, palette, 0)

    out = [f"{result['kind']} {result['type']}:"]
    for ci, (indent, name, value) in enumerate(lines):
        pad = "  " * indent
        value = "" if value is None else f" {value}"
        if "\n" in value:
            # Align continuation lines of multi-line values with the value start
            value = value.replace("\n", f"\n{pad}{' ' * (len(name) + 4)}")

        if color:
            foreground, _ = DUMP_COLORS[ci % len(DUMP_COLORS)]
            out.append(f"{pad}- {foreground}{name}{COLOR_CLEAR}:{value}")
        else:
            out.append(f"{pad}- {name}:{value}")

    out = "\n".join(out)
    palette = palette if color else None

    if output == "print":
        print()
        hexdump(data, palette=palette, offset=offset, autoskip=autoskip)
        print()
        print(out)
        return None

    return f"\n{hexdump(data, palette=palette, offset=offset, output='string', autoskip=autoskip)}\n\n{out}"
