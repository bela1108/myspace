from typing import Any, NamedTuple, Optional, Sequence, Tuple

from . import imphash_oleaut32, imphash_ws2_32, oleaut32, ws2_32, wsock32

"""
A small module containing a database of ordinal to symbol mappings for DLLs
which frequently get linked without symbolic information.
"""

ords = {
    b"oleaut32.dll": oleaut32.ord_names,
    b"ws2_32.dll": ws2_32.ord_names,
    b"wsock32.dll": wsock32.ord_names,
}


class OrdinalTable(NamedTuple):
    """An ordinal-to-name table and the library versions it is valid for.

    ``min_version`` / ``max_version`` are numeric version tuples. ``None``
    means the bound is open ended. A table only claims to resolve ordinals
    for library versions inside its range; callers must not let a name stay
    attached once the evidence leaves that range.
    """

    name: str
    mappings: dict
    min_version: Optional[Tuple[int, ...]] = None
    max_version: Optional[Tuple[int, ...]] = None


def normalize_version(version: Any) -> Optional[Tuple[int, ...]]:
    """Convert a version string or sequence into a numeric version tuple."""

    if version is None:
        return None
    if isinstance(version, bytes):
        version = version.decode("ascii", "ignore")
    if isinstance(version, str):
        parts = []
        for part in version.split("."):
            digits = ""
            for char in part:
                if char.isdigit():
                    digits += char
                else:
                    break
            if not digits:
                break
            parts.append(int(digits))
        return tuple(parts) if parts else None
    try:
        return tuple(int(part) for part in version)
    except (TypeError, ValueError):
        return None


def version_in_range(
    version: Optional[Tuple[int, ...]],
    min_version: Optional[Tuple[int, ...]],
    max_version: Optional[Tuple[int, ...]],
) -> bool:
    """Return whether a version is covered by an (open-ended) version range."""

    if version is None:
        return True
    if min_version is not None and version < min_version:
        return False
    if max_version is not None and version > max_version:
        return False
    return True


def _candidate_tables(
    libname: bytes,
    version: Any = None,
    tables: Optional[Sequence[OrdinalTable]] = None,
):
    if tables is None:
        tables = default_ordinal_tables
    normalized_name = libname.lower()
    normalized_version = normalize_version(version)
    candidates = []
    for table in tables:
        mappings = table.mappings.get(normalized_name)
        if mappings is None:
            continue
        if not version_in_range(
            normalized_version, table.min_version, table.max_version
        ):
            continue
        candidates.append((table, mappings))
    return candidates


def ordinal_lookup_candidates(
    libname: bytes,
    ord_val: int,
    version: Any = None,
    tables: Optional[Sequence[OrdinalTable]] = None,
) -> Tuple[Optional[bytes], Tuple[bytes, ...]]:
    """Return every in-range interpretation of an ordinal.

    The first item is the preferred resolution (``None`` when no table covers
    the ordinal). The second item contains every distinct name produced by
    tables valid for the given library version, in table order. When more than
    one name is returned the ordinal has several legitimate interpretations
    and the caller must keep all of them instead of collapsing the evidence to
    a single name.
    """

    if tables is None:
        tables = default_ordinal_tables
    names = []
    for _table, mappings in _candidate_tables(libname, version, tables):
        name = mappings.get(ord_val)
        if name is not None and name not in names:
            names.append(name)
    preferred = names[0] if names else None
    return preferred, tuple(names)


def format_ordinal(ord_val):
    return f"ord{ord_val}".encode()


def ordinal_lookup(libname, ord_val, make_name=False):
    """Lookup a name for the given ordinal if it's in our database."""
    names = ords.get(libname.lower())
    if names is None:
        if make_name is True:
            return format_ordinal(ord_val)
        return None
    name = names.get(ord_val)
    if name is None:
        return format_ordinal(ord_val)
    return name


# Imphash-specific ordinal tables must remain frozen to the state when the original
# implementation was written so that imphash values remain compatible with YARA,
# YARA-X, and other tools based on the original pefile implementation. wsock32 is
# mapped to the same table as ws2_32 because that was the original pefile behaviour.
imphash_ords = {
    b"oleaut32.dll": imphash_oleaut32.ord_names,
    b"ws2_32.dll": imphash_ws2_32.ord_names,
    b"wsock32.dll": imphash_ws2_32.ord_names,
}


# The default registry deliberately keeps the historically frozen tables used
# by the imphash implementation next to the current tables. Version ranges are
# explicit so a name resolved from an ordinal can never be treated as valid
# outside the library version the table was captured from.
default_ordinal_tables = (
    OrdinalTable("current", ords, None, None),
    OrdinalTable(
        "imphash-frozen",
        imphash_ords,
        None,
        (5, 1, 2600),
    ),
)


def imphash_format_ordinal(ord_val):
    return f"ord{ord_val}".encode()


def imphash_ordinal_lookup(libname, ord_val, make_name=False):
    """
    Lookup a name for the given ordinal using the imphash-specific database.

    This uses ordinal tables that are frozen to the state when the original
    implementation was written so that imphash values remain compatible with
    YARA, YARA-X, VirusTotal, and other tools based on the original pefile
    implementation.
    """
    names = imphash_ords.get(libname.lower())
    if names is None:
        if make_name is True:
            return imphash_format_ordinal(ord_val)
        return None
    name = names.get(ord_val)
    if name is None:
        return imphash_format_ordinal(ord_val)
    return name
