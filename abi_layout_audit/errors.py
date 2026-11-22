"""Location records and exceptions for the ABI layout audit."""

from __future__ import annotations

from dataclasses import dataclass

from pycparser.c_ast import Node


@dataclass(frozen=True)
class Location:
    """A concrete declaration position inside the preprocessed input."""

    file: str
    line: int
    column: int

    @classmethod
    def from_coord(cls, coord, default_file: str) -> "Location":
        if coord is None or getattr(coord, "line", None) is None:
            return cls(default_file, 0, 0)
        return cls(
            coord.file or default_file,
            int(coord.line),
            int(getattr(coord, "column", 0) or 0),
        )

    def to_dict(self) -> dict:
        return {"file": self.file, "line": self.line, "column": self.column}

    def __str__(self) -> str:
        if self.line <= 0:
            return self.file
        if self.column > 0:
            return f"{self.file}:{self.line}:{self.column}"
        return f"{self.file}:{self.line}"


class AuditError(Exception):
    """Base class for audit failures."""


class ConfigError(AuditError):
    """The caller supplied an invalid ABI or audit configuration."""


class LayoutUnsupportedError(AuditError):
    """A type cannot be laid out under the declared generic ABI rules."""

    def __init__(self, message: str, node: Node | None = None):
        super().__init__(message)
        self.node = node


def loc(node: Node | None, default_file: str) -> Location:
    return Location.from_coord(getattr(node, "coord", None), default_file)
