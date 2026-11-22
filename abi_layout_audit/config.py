"""ABI description model.

The auditor never assumes a target machine: every primitive size and
alignment is supplied by the caller through an :class:`AbiConfig`.  Two
configs can be checked against the same declarations to review a static
release for more than one ABI.
"""

from __future__ import annotations

from dataclasses import dataclass
import re


_SIGNED_INT = {
    "char": "signed char",
    "short": "short",
    "short int": "short",
    "int": "int",
    "long": "long",
    "long int": "long",
    "long long": "long long",
    "long long int": "long long",
}

_UNSIGNED_INT = {
    "unsigned char": "unsigned char",
    "unsigned short": "unsigned short",
    "unsigned short int": "unsigned short",
    "unsigned": "unsigned int",
    "unsigned int": "unsigned int",
    "unsigned long": "unsigned long",
    "unsigned long int": "unsigned long",
    "unsigned long long": "unsigned long long",
    "unsigned long long int": "unsigned long long",
}


def canonical_type_name(names: list[str]) -> str:
    """Normalize an ``IdentifierType.names`` sequence to a canonical spelling.

    pycparser keeps the declaration spelling (``unsigned long int`` vs
    ``unsigned long``); layout only depends on the canonical family.
    """

    key = " ".join(n.strip() for n in names if n.strip())
    if key in _UNSIGNED_INT:
        return _UNSIGNED_INT[key]
    if key in _SIGNED_INT:
        return _SIGNED_INT[key]
    if key in {"float", "double", "long double", "_Bool", "bool"}:
        return "_Bool" if key == "bool" else key
    return key


def default_integer_types() -> dict[str, dict[str, int]]:
    """The integer/floating families every config must describe."""

    families = [
        "_Bool",
        "signed char",
        "short",
        "int",
        "long",
        "long long",
        "unsigned char",
        "unsigned short",
        "unsigned int",
        "unsigned long",
        "unsigned long long",
        "float",
        "double",
        "long double",
    ]
    return {name: {"size": 0, "alignment": 0} for name in families}


@dataclass(frozen=True)
class AbiConfig:
    """Caller-supplied ABI geometry.

    ``primitive_types`` maps canonical primitive names (see
    :func:`canonical_type_name`) to ``{"size", "alignment"}`` byte values.
    Pointer size and alignment are stated separately because pointers are the
    same width regardless of the pointee.
    """

    name: str
    pointer_size: int
    pointer_alignment: int
    primitive_types: dict[str, dict[str, int]]
    enum_size: int | None = None
    enum_alignment: int | None = None
    description: str = ""

    @classmethod
    def from_dict(cls, data: dict) -> "AbiConfig":
        required = ("name", "pointer_size", "pointer_alignment", "primitive_types")
        missing = [key for key in required if key not in data]
        if missing:
            raise AbiConfigError(f"ABI config is missing keys: {', '.join(missing)}")

        primitives = default_integer_types()
        provided = data["primitive_types"]
        if not isinstance(provided, dict):
            raise AbiConfigError("primitive_types must be an object")
        for type_name, geometry in provided.items():
            canonical = canonical_type_name(type_name.split())
            if not isinstance(geometry, dict):
                raise AbiConfigError(f"primitive_types.{type_name} must be an object")
            size = geometry.get("size")
            alignment = geometry.get("alignment")
            if not isinstance(size, int) or not isinstance(alignment, int):
                raise AbiConfigError(
                    f"primitive_types.{type_name} needs integer size and alignment"
                )
            if size <= 0 or alignment <= 0 or size % alignment != 0:
                raise AbiConfigError(
                    f"primitive_types.{type_name} has invalid size/alignment"
                )
            primitives[canonical] = {"size": size, "alignment": alignment}

        unresolved = [
            name
            for name, geometry in primitives.items()
            if geometry["size"] == 0
        ]
        if unresolved:
            raise AbiConfigError(
                "ABI config does not define required primitives: "
                + ", ".join(sorted(unresolved))
            )

        pointer_size = data["pointer_size"]
        pointer_alignment = data["pointer_alignment"]
        if not isinstance(pointer_size, int) or not isinstance(pointer_alignment, int):
            raise AbiConfigError("pointer size/alignment must be integers")
        if pointer_size <= 0 or pointer_alignment <= 0:
            raise AbiConfigError("pointer size/alignment must be positive")

        enum_size = data.get("enum_size")
        enum_alignment = data.get("enum_alignment")
        if (enum_size is None) != (enum_alignment is None):
            raise AbiConfigError("enum_size and enum_alignment must be set together")
        if enum_size is not None and (
            not isinstance(enum_size, int) or not isinstance(enum_alignment, int)
            or enum_size <= 0 or enum_alignment <= 0
        ):
            raise AbiConfigError("enum size/alignment must be positive integers")

        return cls(
            name=str(data["name"]),
            pointer_size=pointer_size,
            pointer_alignment=pointer_alignment,
            primitive_types=primitives,
            enum_size=enum_size,
            enum_alignment=enum_alignment,
            description=str(data.get("description", "")),
        )

    def primitive(self, canonical_name: str) -> tuple[int, int]:
        try:
            geometry = self.primitive_types[canonical_name]
        except KeyError:
            raise AbiConfigError(
                f"ABI {self.name!r} does not define primitive {canonical_name!r}"
            ) from None
        return geometry["size"], geometry["alignment"]

    def enum_geometry(self) -> tuple[int, int]:
        if self.enum_size is None or self.enum_alignment is None:
            raise AbiConfigError(
                f"ABI {self.name!r} must set enum_size/enum_alignment because the "
                "declarations contain an enum"
            )
        return self.enum_size, self.enum_alignment


class AbiConfigError(ValueError):
    """Raised when an ABI description is incomplete or malformed."""


_RANGE_RE = re.compile(r"^\s*(\d+)\s*(?:-|–|\.\.)\s*(\d+)\s*$")


def parse_byte_range(spec: str) -> tuple[int, int]:
    """Parse inclusive byte offsets such as ``0-15`` or ``0..15``."""

    match = _RANGE_RE.match(spec)
    if not match:
        raise AbiConfigError(
            f"invalid byte range {spec!r}; expected inclusive offsets like '0-15'"
        )
    start, end = int(match.group(1)), int(match.group(2))
    if end < start:
        raise AbiConfigError(f"byte range {spec!r} has an end before its start")
    return start, end
