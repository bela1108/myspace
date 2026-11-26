"""Consume the generation identifier of offline managed samples with dnfile.

The "generation identifier" of a managed artifact is the Mvid (module
version identifier) stored in the CLR metadata Module table.  dnfile
already resolves it through the existing heap parsing: the module name
comes from the #Strings heap and the Mvid from the #GUID heap.

Everything in this module is strictly read-only: sample bytes are only
ever read, never written.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Union

import dnfile

PathLike = Union[str, Path]


class GenerationUnreadable(Exception):
    """The sample cannot be consumed as a normal .NET module.

    Raised when the file is not a parseable PE/CLR image, has no CLR
    metadata, no Module table, or no resolvable Mvid.  Such samples are
    not "normal samples" and yield no usable generation identifier.
    """


@dataclass(frozen=True)
class ModuleIdentity:
    """Identity of a managed module, consumed from its CLR metadata."""

    name: Optional[str]
    """Module name from the Module table (resolved via the #Strings heap)."""

    mvid: str
    """Canonical (lowercase) Mvid from the Module table (via the #GUID heap)."""


def normalize_mvid(value: object) -> Optional[str]:
    """Normalize an Mvid to its canonical lowercase UUID string.

    Accepts UUID-like strings with or without braces and in any case, so
    records from different links of the external archive chain compare
    equal when they denote the same generation.  Returns None when the
    value is not a well-formed UUID.
    """
    if value is None:
        return None
    text = str(value).strip().strip("{}").strip()
    try:
        return str(uuid.UUID(text))
    except (ValueError, AttributeError, TypeError):
        return None


def read_module_identity(path: PathLike) -> ModuleIdentity:
    """Read the module identity of a normal sample, read-only.

    Parses the file at "path" with dnfile and consumes the first (and,
    for well-formed modules, only) Module table row: Name via the
    #Strings heap and Mvid via the #GUID heap.

    Raises:
        FileNotFoundError: the referenced external file is absent.
        GenerationUnreadable: the sample cannot be consumed as a normal
            .NET module or carries no resolvable generation identifier.
    """
    sample_path = Path(path)
    data = sample_path.read_bytes()
    try:
        pe = dnfile.dnPE(data=data)
    except Exception as exc:  # pefile.PEFormatError and friends
        raise GenerationUnreadable(
            f"{sample_path}: not a parseable PE image ({exc})"
        ) from exc

    net = getattr(pe, "net", None)
    if net is None:
        raise GenerationUnreadable(f"{sample_path}: no CLR header")
    mdtables = getattr(net, "mdtables", None)
    module_table = getattr(mdtables, "Module", None) if mdtables else None
    if module_table is None:
        raise GenerationUnreadable(f"{sample_path}: no Module metadata table")

    rows = [row for row in module_table.rows if row is not None]
    if not rows:
        raise GenerationUnreadable(f"{sample_path}: Module table is empty")
    row = rows[0]

    mvid = normalize_mvid(getattr(row, "Mvid", None))
    if mvid is None:
        raise GenerationUnreadable(
            f"{sample_path}: Module.Mvid not resolvable from the #GUID heap"
        )

    return ModuleIdentity(name=_module_name(row), mvid=mvid)


def _module_name(row: object) -> Optional[str]:
    """Extract the module name from a Module row across dnfile versions.

    Recent dnfile resolves Name to a HeapItemString (decoded value in
    .value); older releases exposed a plain str.
    """
    raw = getattr(row, "Name", None)
    if raw is None:
        return None
    if isinstance(raw, str):
        return raw
    value = getattr(raw, "value", None)
    if isinstance(value, str):
        return value
    text = str(raw)
    return text or None
