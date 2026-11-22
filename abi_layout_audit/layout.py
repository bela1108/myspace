"""Static ABI layout engine.

Computes sizes, alignments and byte-level region tables for a parsed C
translation unit under an explicit, caller-supplied AbiConfig. Nothing in
this module executes the audited code; every primitive size and alignment
comes from the ABI configuration, never from the host machine.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from pycparser import c_ast

from .config import AbiConfig
from .errors import LayoutUnsupportedError, Location
from .evaluator import ConstantEvaluator
from .parser import ParsedUnit, UnsupportedRule


@dataclass
class Region:
    """A contiguous byte range inside a laid-out composite type."""

    offset: int
    size: int
    kind: str
    path: tuple[str, ...]
    location: Location | None
    type_text: str = ""
    note: str = ""

    @property
    def end(self) -> int:
        return self.offset + self.size

    def to_dict(self) -> dict:
        data = {
            "offset": self.offset,
            "size": self.size,
            "kind": self.kind,
            "path": list(self.path),
            "location": self.location.to_dict() if self.location else None,
        }
        if self.type_text:
            data["type"] = self.type_text
        if self.note:
            data["note"] = self.note
        return data


@dataclass
class MemberLayout:
    name: str
    offset: int
    size: int
    alignment: int
    location: Location | None
    type_text: str
    path: tuple[str, ...]
    is_bitfield: bool = False
    bit_size: int | None = None

    def to_dict(self) -> dict:
        data = {
            "name": self.name,
            "offset": self.offset,
            "size": self.size,
            "alignment": self.alignment,
            "path": list(self.path),
            "location": self.location.to_dict() if self.location else None,
            "type": self.type_text,
        }
        if self.is_bitfield:
            data["bitfield"] = True
            data["bit_size"] = self.bit_size
        return data


@dataclass
class TypeLayout:
    kind: str
    name: str
    size: int
    alignment: int
    location: Location | None
    members: list[MemberLayout] = field(default_factory=list)
    regions: list[Region] = field(default_factory=list)
    has_bitfields: bool = False
    unsupported: list[UnsupportedRule] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "name": self.name,
            "size": self.size,
            "alignment": self.alignment,
            "location": self.location.to_dict() if self.location else None,
            "has_bitfields": self.has_bitfields,
            "members": [m.to_dict() for m in self.members],
            "regions": [r.to_dict() for r in self.regions],
            "unsupported": [
                {"kind": u.kind, "message": u.message,
                 "location": u.location.to_dict()}
                for u in self.unsupported
            ],
        }


class LayoutEngine:
    """Lays out named composite types using the supplied ABI config."""

    def __init__(self, unit: ParsedUnit, config: AbiConfig):
        self.unit = unit
        self.config = config
        self._cache: dict[str, TypeLayout] = {}
        self.evaluator = ConstantEvaluator(unit.enum_constants)

    def layout_named(self, name: str) -> TypeLayout:
        if name in self._cache:
            return self._cache[name]
        node = self.unit.composites.get(name)
        if node is None:
            typedef = self.unit.typedef_nodes.get(name)
            if typedef is not None:
                node = self._unwrap(
                    typedef.type if isinstance(typedef, c_ast.TypeDecl)
                    else typedef)
        if node is None or not isinstance(
                node, (c_ast.Struct, c_ast.Union)):
            raise LayoutUnsupportedError(f"unknown composite type: {name!r}")
        layout = self._layout_composite(node, ())
        self._cache[name] = layout
        return layout

    def _unwrap(self, node):
        while isinstance(node, c_ast.AttributedType):
            node = node.type
        return node

    def _loc(self, coord):
        return Location.from_coord(coord, self.unit.filename)

    def _record(self, layout, kind, message, coord):
        location = self._loc(coord)
        for item in layout.unsupported:
            if item.kind == kind and item.location == location:
                return
        layout.unsupported.append(UnsupportedRule(kind, message, location))

    def _align_up(self, offset, alignment):
        if alignment <= 1:
            return offset
        return ((offset + alignment - 1) // alignment) * alignment

    def _alignas(self, decl):
        values = []
        for spec in getattr(decl, "align", None) or ():
            values.append(self.evaluator.evaluate(spec.alignment))
        return max(values, default=None)

    def _array_count(self, array_decl):
        if array_decl.dim is None:
            raise LayoutUnsupportedError(
                "unsized arrays cannot be laid out",
                Location.from_coord(array_decl.coord, self.unit.filename))
        count = self.evaluator.evaluate(array_decl.dim)
        if count <= 0:
            raise LayoutUnsupportedError(
                f"array dimension must be positive, got {count}",
                Location.from_coord(array_decl.coord, self.unit.filename))
        return count

    def _scalar_size(self, node):
        if isinstance(node, c_ast.IdentifierType):
            target = self._resolve_typedef(node)
            if target is not None:
                return self._size_of_type(target, ())
            canonical = self.unit.type_text(node)
            return self.config.primitive(canonical)
        if isinstance(node, c_ast.Enum):
            if self.config.enum_size is not None:
                return self.config.enum_geometry()
            return self.config.primitive("int")
        raise LayoutUnsupportedError(
            f"cannot size node {type(node).__name__}",
            self._loc(getattr(node, "coord", None)))

    def _resolve_typedef(self, identifier):
        if len(identifier.names) != 1:
            return None
        node = self.unit.typedef_nodes.get(identifier.names[0])
        if node is None:
            return None
        return node.type if isinstance(node, c_ast.TypeDecl) else node

    def _size_of_type(self, typ, path):
        if isinstance(typ, c_ast.TypeDecl):
            return self._size_of_type(typ.type, path)
        if isinstance(typ, c_ast.AttributedType):
            return self._size_of_type(typ.type, path)
        if isinstance(typ, c_ast.PtrDecl):
            return self.config.pointer_size, self.config.pointer_alignment
        if isinstance(typ, c_ast.FuncDecl):
            return self.config.pointer_size, self.config.pointer_alignment
        if isinstance(typ, c_ast.ArrayDecl):
            count = self._array_count(typ)
            inner_size, inner_align = self._size_of_type(typ.type, path)
            return inner_size * count, inner_align
        if isinstance(typ, (c_ast.Struct, c_ast.Union)):
            resolved = self._composite_base(typ)
            sub = self._layout_composite(resolved, path)
            return sub.size, sub.alignment
        return self._scalar_size(typ)

    def _layout_composite(self, node, path):
        if isinstance(node, c_ast.Struct):
            return self._layout_struct(node, path)
        return self._layout_union(node, path)

    def _layout_struct(self, node, path):
        loc = self._loc(node.coord)
        layout = TypeLayout("struct", node.name or "anonymous", 0, 1, loc)
        self._attach_global_rules(layout)
        cursor = 0
        max_align = 1
        for decl in node.decls or []:
            if isinstance(decl, c_ast.Pragma):
                self._record(layout, "pack_pragma",
                             f"#pragma {decl.string} appears inside the struct body",
                             decl.coord)
                continue
            member_path = path + (decl.name,)
            member_loc = self._loc(decl.coord)
            size, alignment = self._size_of_type(decl.type, member_path)
            forced = self._alignas(decl)
            if forced is not None:
                alignment = max(alignment, forced)
            if decl.bitsize is not None:
                cursor = self._layout_bitfield(
                    layout, decl, member_path, member_loc,
                    size, alignment, cursor)
                layout.has_bitfields = True
                max_align = max(max_align, alignment)
                continue
            offset = self._align_up(cursor, alignment)
            if offset > cursor:
                layout.regions.append(Region(
                    cursor, offset - cursor, "padding", member_path,
                    member_loc, note="alignment padding before member"))
            layout.members.append(MemberLayout(
                decl.name, offset, size, alignment, member_loc,
                self._type_text(decl.type), member_path))
            layout.regions.extend(self._member_regions(
                decl.type, member_path, offset, size, member_loc))
            cursor = offset + size
            max_align = max(max_align, alignment)
        total = self._align_up(cursor, max_align)
        if total > cursor:
            layout.regions.append(Region(
                cursor, total - cursor, "padding", path, loc,
                note="tail padding to struct alignment"))
        layout.size = total
        layout.alignment = max_align
        return layout

    def _layout_bitfield(self, layout, decl, member_path, member_loc,
                         size, alignment, cursor):
        bit_width = self.evaluator.evaluate(decl.bitsize)
        if bit_width < 0:
            raise LayoutUnsupportedError(
                f"negative bitfield width in {decl.name!r}", member_loc)
        offset = self._align_up(cursor, alignment)
        if offset > cursor:
            layout.regions.append(Region(
                cursor, offset - cursor, "padding", member_path,
                member_loc, note="alignment padding before bitfield"))
        layout.members.append(MemberLayout(
            decl.name, offset, size, alignment, member_loc,
            self._type_text(decl.type), member_path,
            is_bitfield=True, bit_size=bit_width))
        if bit_width == 0:
            note = "zero-width bitfield; placement is ABI defined"
            region_size = 0
        else:
            note = (f"{bit_width}-bit field; intra-storage-unit placement "
                    "is ABI defined")
            region_size = size
        layout.regions.append(Region(
            offset, region_size, "bitfield", member_path, member_loc,
            note=note))
        self._record(
            layout, "bitfield",
            f"member {decl.name!r} is a {bit_width}-bit field; bit packing "
            "order and storage-unit overlap are not modeled", decl.coord)
        return offset + size if bit_width else offset

    def _layout_union(self, node, path):
        loc = self._loc(node.coord)
        layout = TypeLayout("union", node.name or "anonymous", 0, 1, loc)
        self._attach_global_rules(layout)
        max_size = 0
        max_align = 1
        for decl in node.decls or []:
            if isinstance(decl, c_ast.Pragma):
                self._record(layout, "pack_pragma",
                             f"#pragma {decl.string} appears inside the union body",
                             decl.coord)
                continue
            member_path = path + (decl.name,)
            member_loc = self._loc(decl.coord)
            size, alignment = self._size_of_type(decl.type, member_path)
            forced = self._alignas(decl)
            if forced is not None:
                alignment = max(alignment, forced)
            if decl.bitsize is not None:
                bit_width = self.evaluator.evaluate(decl.bitsize)
                layout.has_bitfields = True
                layout.members.append(MemberLayout(
                    decl.name, 0, size, alignment, member_loc,
                    self._type_text(decl.type), member_path,
                    is_bitfield=True, bit_size=bit_width))
                layout.regions.append(Region(
                    0, size, "bitfield", member_path, member_loc,
                    note="bitfield inside union; placement is ABI defined"))
                self._record(layout, "bitfield",
                             f"union member {decl.name!r} is a bitfield",
                             decl.coord)
            else:
                layout.members.append(MemberLayout(
                    decl.name, 0, size, alignment, member_loc,
                    self._type_text(decl.type), member_path))
                layout.regions.extend(self._member_regions(
                    decl.type, member_path, 0, size, member_loc))
            max_size = max(max_size, size)
            max_align = max(max_align, alignment)
        total = self._align_up(max_size, max_align)
        layout.size = total
        layout.alignment = max_align
        return layout

    def _attach_global_rules(self, layout):
        for rule in self.unit.unsupported:
            if rule.kind in {"pack_pragma", "packed_attribute",
                             "aligned_attribute", "layout_pragma",
                             "struct_attribute"}:
                if rule not in layout.unsupported:
                    layout.unsupported.append(rule)

    def _member_regions(self, typ, path, offset, size, member_loc):
        array_dims = []
        node = typ
        while isinstance(node, c_ast.ArrayDecl):
            array_dims.append(self._array_count(node))
            node = node.type
        element_size, _ = self._size_of_type(node, path)
        base = self._composite_base(node)
        if not array_dims or not isinstance(
                base, (c_ast.Struct, c_ast.Union)):
            return self._scalar_or_composite_regions(
                typ, path, offset, member_loc)
        regions = []
        element_count = 1
        for dim in array_dims:
            element_count *= dim
        for index in range(element_count):
            element_path = path + (f"[{index}]",)
            element_offset = offset + index * element_size
            regions.extend(self._scalar_or_composite_regions(
                node, element_path, element_offset, member_loc))
        covered = element_count * element_size
        if covered < size:
            regions.append(Region(
                offset + covered, size - covered, "padding", path,
                member_loc, note="tail padding after array storage"))
        return regions

    def _composite_base(self, typ):
        base = typ
        while isinstance(base, (c_ast.TypeDecl, c_ast.AttributedType)):
            base = base.type
        base = self._unwrap(base)
        if isinstance(base, (c_ast.Struct, c_ast.Union)):
            if base.decls is None and base.name:
                definition = self.unit.composites.get(base.name)
                if definition is not None and definition is not base:
                    return definition
            return base
        if isinstance(base, c_ast.IdentifierType):
            target = self._resolve_typedef(base)
            if target is not None:
                return self._composite_base(target)
        return base

    def _scalar_or_composite_regions(self, typ, path, offset, member_loc):
        base = self._composite_base(typ)
        if isinstance(base, (c_ast.Struct, c_ast.Union)):
            sub = self._layout_composite(base, ())
            return [
                Region(offset + region.offset, region.size, region.kind,
                       path + tuple(segment for segment in region.path
                                    if segment),
                       region.location, region.type_text, region.note)
                for region in sub.regions
            ]
        size, _ = self._size_of_type(typ, path)
        return [Region(offset, size, "field", path, member_loc,
                       self._type_text(typ))]

    def _decl_base(self, typ):
        while isinstance(typ, (c_ast.PtrDecl, c_ast.ArrayDecl)):
            typ = typ.type
        return typ

    def _type_text(self, typ):
        if isinstance(typ, c_ast.ArrayDecl):
            return f"{self._type_text(typ.type)}[{self._array_count(typ)}]"
        if isinstance(typ, c_ast.PtrDecl):
            return self._type_text(typ.type) + "*"
        if isinstance(typ, c_ast.TypeDecl):
            return self._type_text(typ.type)
        if isinstance(typ, c_ast.AttributedType):
            return self._type_text(typ.type)
        if isinstance(typ, c_ast.IdentifierType):
            return " ".join(typ.names)
        if isinstance(typ, (c_ast.Struct, c_ast.Union)):
            keyword = "struct" if isinstance(typ, c_ast.Struct) else "union"
            label = typ.name if typ.name else "anonymous"
            return f"{keyword} {label}"
        if isinstance(typ, c_ast.Enum):
            label = typ.name if typ.name else "anonymous"
            return f"enum {label}"
        if isinstance(typ, c_ast.FuncDecl):
            return "function"
        return type(typ).__name__
