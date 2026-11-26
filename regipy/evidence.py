"""Optional evidence-location references for registry export rows.

A reference deliberately contains only three locator components:

* the acquisition file identity,
* the physical NK-record offset in that file, and
* the zero-based sample index assigned during the export traversal.

Values, timestamps and paths are not part of the locator.  A value can change
in place without invalidating the physical record reference, while sorting an
export by key path changes where a row appears but does not rewrite the sample
index stored on the row.

This module is opt-in: the default ``Subkey`` and CLI serializers do not emit
references unless the caller asks for them.
"""

import json
import os
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Optional, Union

from construct import ConstError, StreamError

from regipy.exceptions import (
    AmbiguousLegacyReferenceException,
    EvidenceReferenceException,
    UnmappedLegacyReferenceException,
)
from regipy.structs import CM_KEY_NODE

if TYPE_CHECKING:
    from regipy.registry import NKRecord, RegistryHive

__all__ = [
    "EvidenceReference",
    "EvidenceVerification",
    "build_evidence_reference",
    "find_reference_in_export",
    "legacy_csv_reference_id",
    "legacy_csv_reference_key",
    "reference_from_entry",
    "resolve_legacy_csv_reference",
    "verify_evidence_reference",
    "verify_reference_in_export",
]


@dataclass(frozen=True)
class EvidenceReference:
    """Stable locator for one NK record in one acquisition file.

    ``record_offset`` is the absolute byte offset of the NK record's ``flags``
    field (the same position exposed by ``NKRecord.cell_offset``).  It is not a
    traversal index, so two keys with the same name remain distinguishable.

    ``sample_index`` is zero-based and follows the unsorted traversal order of
    the export that produced the reference.  Keep this value on the row when
    sorting or joining exports; recomputing it after sorting defeats its
    purpose.
    """

    acquisition_file: str
    record_offset: int
    sample_index: int

    def __post_init__(self) -> None:
        if not self.acquisition_file:
            raise ValueError("acquisition_file must not be empty")
        if self.record_offset < 0:
            raise ValueError("record_offset must be non-negative")
        if self.sample_index < 0:
            raise ValueError("sample_index must be non-negative")

    @property
    def record_offset_hex(self) -> str:
        return f"0x{self.record_offset:x}"

    @property
    def physical_record_location(self) -> int:
        """Alias for the physical NK-record offset."""
        return self.record_offset

    @property
    def sample_number(self) -> int:
        """One-based rendering of :attr:`sample_index` for human reports."""
        return self.sample_index + 1

    @property
    def sampling_sequence_number(self) -> int:
        """Alias for the zero-based sampling sequence stored in the reference."""
        return self.sample_index

    def to_dict(self) -> dict[str, Union[str, int]]:
        return {
            "acquisition_file": self.acquisition_file,
            "record_offset": self.record_offset,
            "sample_index": self.sample_index,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "EvidenceReference":
        """Build a reference from a dictionary, accepting a few legacy aliases."""
        try:
            acquisition_file = value.get(
                "acquisition_file",
                value.get("acquisition_file_path", value.get("file_path", value.get("file"))),
            )
            record_offset = value.get(
                "record_offset",
                value.get("physical_record_location", value.get("offset")),
            )
            sample_index = value.get(
                "sample_index",
                value.get("sampling_sequence_number", value.get("sample_number")),
            )
        except AttributeError as ex:
            raise EvidenceReferenceException("evidence reference must be a mapping") from ex
        if acquisition_file is None or record_offset is None or sample_index is None:
            raise EvidenceReferenceException("evidence reference requires acquisition_file, record_offset and sample_index")
        if value.get("sample_index") is None and value.get("sample_number") is not None:
            # ``sample_number`` is a one-based alias; convert it to the canonical
            # zero-based field.
            sample_index = int(sample_index) - 1
        try:
            record_offset_value = int(record_offset, 0) if isinstance(record_offset, str) else int(record_offset)
            sample_index_value = int(sample_index, 0) if isinstance(sample_index, str) else int(sample_index)
            return cls(
                acquisition_file=str(acquisition_file),
                record_offset=record_offset_value,
                sample_index=sample_index_value,
            )
        except (TypeError, ValueError) as ex:
            raise EvidenceReferenceException(f"invalid evidence reference: {ex}") from ex

    @classmethod
    def from_string(cls, value: str) -> "EvidenceReference":
        """Parse the compact ``file@0xoffset#sample_index`` form."""
        try:
            acquisition_file, location = value.rsplit("@", 1)
            record_offset, sample_index = location.rsplit("#", 1)
            return cls(
                acquisition_file=acquisition_file,
                record_offset=int(record_offset, 0),
                sample_index=int(sample_index),
            )
        except (AttributeError, TypeError, ValueError) as ex:
            raise EvidenceReferenceException(f"invalid compact evidence reference: {value!r}") from ex

    def to_string(self) -> str:
        return str(self)

    def __str__(self) -> str:
        return f"{self.acquisition_file}@0x{self.record_offset:x}#{self.sample_index}"


@dataclass(frozen=True)
class EvidenceVerification:
    """Component-by-component result of checking a reference on a later export."""

    acquisition_file_holds: bool
    physical_record_holds: bool
    sample_order_holds: Optional[bool]
    entry_matches: Optional[bool] = None
    key_name: Optional[str] = None
    key_path: Optional[str] = None
    reason: Optional[str] = None

    @property
    def locator_holds(self) -> bool:
        """Whether the file + physical record components still locate the key."""
        return self.acquisition_file_holds and self.physical_record_holds

    @property
    def all_components_hold(self) -> bool:
        """Whether all three components, including sample order, still match."""
        return self.locator_holds and self.sample_order_holds in (True, None) and self.entry_matches in (True, None)

    @property
    def row_matches(self) -> bool:
        """Whether the compared export row is the exact row the reference locates."""
        return self.locator_holds and self.entry_matches is not False and self.sample_order_holds is not False

    def explain(self) -> str:
        parts = [
            "acquisition file: " + ("holds" if self.acquisition_file_holds else "does not hold"),
            "physical record: " + ("holds" if self.physical_record_holds else "does not hold"),
        ]
        if self.entry_matches is not None:
            parts.append("compared row: " + ("matches" if self.entry_matches else "does not match"))
        if self.sample_order_holds is None:
            parts.append("sample order: not checked")
        else:
            parts.append("sample order: " + ("holds" if self.sample_order_holds else "does not hold"))
        if self.reason:
            parts.append(self.reason)
        return "; ".join(parts)

    def to_dict(self) -> dict[str, Any]:
        return {
            "acquisition_file_holds": self.acquisition_file_holds,
            "physical_record_holds": self.physical_record_holds,
            "sample_order_holds": self.sample_order_holds,
            "entry_matches": self.entry_matches,
            "locator_holds": self.locator_holds,
            "all_components_hold": self.all_components_hold,
            "row_matches": self.row_matches,
            "key_name": self.key_name,
            "key_path": self.key_path,
            "reason": self.reason,
        }


def _canonical_path(path: Union[str, os.PathLike[str]]) -> str:
    return os.path.realpath(os.path.abspath(os.fspath(path)))


def _acquisition_matches(reference: EvidenceReference, hive_path: Union[str, os.PathLike[str]]) -> bool:
    """Compare acquisition identities without silently accepting a different file."""
    referenced = os.fspath(reference.acquisition_file)
    actual = os.fspath(hive_path)
    try:
        if os.path.exists(referenced) and os.path.exists(actual) and os.path.samefile(referenced, actual):
            return True
    except OSError:
        pass

    if _canonical_path(referenced) == _canonical_path(actual):
        return True

    # Portable exports sometimes preserve only the acquisition file name.  That
    # is still an explicit file component, unlike guessing from a key name.
    return os.path.dirname(referenced) == "" and os.path.basename(actual) == referenced


def _read_nk_record_at(path: Union[str, os.PathLike[str]], offset: int) -> tuple[str, int]:
    """Validate and parse the NK record at an absolute ``flags`` offset.

    Returns ``(key_name, cell_size)``.  Raises ``EvidenceReferenceException``
    when the location is not an allocated NK cell.
    """
    file_path = os.fspath(path)
    with open(file_path, "rb") as f:
        f.seek(0, os.SEEK_END)
        file_size = f.tell()
        if offset < 6 or offset >= file_size:
            raise EvidenceReferenceException(f"record offset {offset:#x} is outside {file_path}")

        f.seek(offset - 6)
        cell_size_bytes = f.read(4)
        signature = f.read(2)
        if len(cell_size_bytes) != 4 or signature != b"nk":
            raise EvidenceReferenceException(f"no NK signature at record offset {offset:#x}")

        cell_size = int.from_bytes(cell_size_bytes, "little", signed=True)
        if cell_size >= 0:
            raise EvidenceReferenceException(f"cell at record offset {offset:#x} is not allocated")
        cell_size = -cell_size
        if offset - 6 + cell_size > file_size:
            raise EvidenceReferenceException(f"cell at record offset {offset:#x} extends beyond {file_path}")

        f.seek(offset)
        record_bytes = f.read(offset - 6 + cell_size - offset)

    try:
        header = CM_KEY_NODE.parse(record_bytes)
    except (ConstError, StreamError) as ex:
        raise EvidenceReferenceException(f"could not parse NK record at {offset:#x}: {ex}") from ex

    if header.flags.KEY_COMP_NAME:
        key_name = header.key_name_string.decode("ascii", errors="replace")
    else:
        key_name = header.key_name_string.decode("utf-16-le", errors="replace")
    return key_name, cell_size


def build_evidence_reference(
    registry_hive: "RegistryHive",
    nk_record: "NKRecord",
    sample_index: int,
) -> EvidenceReference:
    """Build a reference for an NK record during an export traversal."""
    acquisition_file = getattr(registry_hive, "hive_path", None)
    if not acquisition_file:
        raise EvidenceReferenceException("registry hive does not expose its acquisition file path")
    record_offset = getattr(nk_record, "cell_offset", getattr(nk_record, "offset", None))
    if record_offset is None:
        raise EvidenceReferenceException("NK record does not expose a physical cell offset")
    return EvidenceReference(
        acquisition_file=os.fspath(acquisition_file),
        record_offset=int(record_offset),
        sample_index=int(sample_index),
    )


def reference_from_entry(entry: Any) -> Optional[EvidenceReference]:
    """Return the evidence reference attached to an export entry, if any."""
    if isinstance(entry, Mapping):
        value = entry.get("evidence_reference")
        if isinstance(value, EvidenceReference):
            return value
        if isinstance(value, Mapping):
            return EvidenceReference.from_dict(value)
        if isinstance(value, str):
            return EvidenceReference.from_string(value)
        if {"acquisition_file", "record_offset", "sample_index"}.issubset(entry):
            return EvidenceReference.from_dict(entry)
        return None
    value = getattr(entry, "evidence_reference", None)
    if isinstance(value, EvidenceReference):
        return value
    if isinstance(value, Mapping):
        return EvidenceReference.from_dict(value)
    return None


def _entry_value(entry: Any, name: str) -> Any:
    if isinstance(entry, Mapping):
        return entry.get(name)
    return getattr(entry, name, None)


def verify_evidence_reference(
    reference: Union[EvidenceReference, Mapping[str, Any]],
    registry_hive: Optional["RegistryHive"] = None,
    hive_path: Optional[Union[str, os.PathLike[str]]] = None,
    entry: Optional[Any] = None,
    sample_index: Optional[int] = None,
) -> EvidenceVerification:
    """Check a reference against a hive and/or a row from the next export.

    The acquisition file and physical NK record are checked independently from
    the sample index.  Consequently, reordering a later export can invalidate
    only ``sample_order_holds`` while the file/offset locator still identifies
    the same record.  Values are intentionally not compared: they are not part
    of a locator reference.
    """
    if not isinstance(reference, EvidenceReference):
        reference = EvidenceReference.from_dict(reference)

    actual_path: Optional[Union[str, os.PathLike[str]]] = hive_path
    if actual_path is None and registry_hive is not None:
        actual_path = getattr(registry_hive, "hive_path", None)
    if actual_path is None:
        # The acquisition file is part of the reference itself; use it when the
        # caller did not supply a separate hive path.
        actual_path = reference.acquisition_file

    acquisition_holds = _acquisition_matches(reference, actual_path)
    key_name: Optional[str] = None
    cell_size: Optional[int] = None
    reasons: list[str] = []
    try:
        key_name, cell_size = _read_nk_record_at(actual_path, reference.record_offset)
    except (OSError, EvidenceReferenceException) as ex:
        reasons.append(str(ex))

    if registry_hive is None:
        from regipy.registry import RegistryHive

        try:
            registry_hive = RegistryHive(actual_path)
        except Exception as ex:  # pragma: no cover - only on corrupt replacement files
            registry_hive = None
            reasons.append(str(ex))

    key_path = _entry_value(entry, "path")
    expected_name = _entry_value(entry, "subkey_name")
    record_holds = key_name is not None
    entry_matches: Optional[bool] = None if entry is None else record_holds
    if record_holds and expected_name is not None and key_name != expected_name:
        entry_matches = False
        reasons.append(f"offset {reference.record_offset:#x} contains {key_name!r}, not {expected_name!r}")

    if record_holds and key_path is not None and registry_hive is not None:
        try:
            located = registry_hive.get_key(key_path)
            located_offset = getattr(located, "cell_offset", getattr(located, "offset", None))
        except Exception as ex:
            entry_matches = False
            reasons.append(f"could not resolve export path {key_path!r}: {ex}")
        else:
            if located_offset is None or int(located_offset) != reference.record_offset:
                entry_matches = False
                reasons.append(f"path {key_path!r} now resolves to record offset {located_offset!r}")

    current_sample_index = sample_index
    if current_sample_index is None:
        entry_reference = reference_from_entry(entry) if entry is not None else None
        if entry_reference is not None:
            current_sample_index = entry_reference.sample_index
        elif entry is not None:
            raw_sample = _entry_value(entry, "sample_index")
            if raw_sample is not None:
                current_sample_index = int(raw_sample)
    sample_order_holds: Optional[bool] = None
    if current_sample_index is not None:
        sample_order_holds = current_sample_index == reference.sample_index
        if not sample_order_holds:
            reasons.append(f"sample index {reference.sample_index} now belongs to a different export position")

    return EvidenceVerification(
        acquisition_file_holds=acquisition_holds,
        physical_record_holds=record_holds,
        sample_order_holds=sample_order_holds,
        entry_matches=entry_matches,
        key_name=key_name,
        key_path=key_path,
        reason="; ".join(reasons) if reasons else None,
    )


def find_reference_in_export(
    reference: Union[EvidenceReference, Mapping[str, Any]],
    entries: Iterable[Any],
    *,
    match_sample_index: bool = False,
) -> list[Any]:
    """Find later-export rows whose reference has the same file and offset.

    Matching is by the physical locator, not by key name or path.  Set
    ``match_sample_index`` to require the original sampling position too.
    """
    if not isinstance(reference, EvidenceReference):
        reference = EvidenceReference.from_dict(reference)
    matches = []
    for entry in entries:
        candidate = reference_from_entry(entry)
        if candidate is None:
            continue
        if not _acquisition_matches(reference, candidate.acquisition_file):
            continue
        if candidate.record_offset != reference.record_offset:
            continue
        if match_sample_index and candidate.sample_index != reference.sample_index:
            continue
        matches.append(entry)
    return matches


def verify_reference_in_export(
    reference: Union[EvidenceReference, Mapping[str, Any]],
    entries: Iterable[Any],
    *,
    registry_hive: Optional["RegistryHive"] = None,
    hive_path: Optional[Union[str, os.PathLike[str]]] = None,
) -> EvidenceVerification:
    """Check an old reference against rows from the next export.

    Rows are joined by acquisition file and physical record offset, never by
    key name.  The row's own ``sample_index`` is then compared with the stored
    one, so a later export that re-ordered its sampling reports the sample
    component as lost while the file/record locator can still hold.  Export
    values are not compared.
    """
    if not isinstance(reference, EvidenceReference):
        reference = EvidenceReference.from_dict(reference)
    matches = find_reference_in_export(reference, entries)
    if matches:
        return verify_evidence_reference(
            reference,
            registry_hive=registry_hive,
            hive_path=hive_path,
            entry=matches[0],
        )
    return verify_evidence_reference(reference, registry_hive=registry_hive, hive_path=hive_path)


def legacy_csv_reference_key(row: Mapping[str, Any]) -> tuple[tuple[str, str], ...]:
    """Canonical hashable identity for an old CSV row.

    Only identity-bearing columns are used; value columns are deliberately
    excluded because values may change between exports.
    """
    fields = ("path", "subkey_name", "timestamp", "values_count", "sample_index")
    items = []
    for field in fields:
        if field in row and row[field] is not None:
            items.append((field, _stable_legacy_value(row[field])))
    return tuple(items)


def _stable_legacy_value(value: Any) -> str:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return str(value)
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    except TypeError:
        return repr(value)


def legacy_csv_reference_id(row: Mapping[str, Any]) -> str:
    """Stable string form of :func:`legacy_csv_reference_key` for mapping files."""
    return json.dumps(legacy_csv_reference_key(row), separators=(",", ":"), default=str)


def _coerce_reference(value: Any) -> EvidenceReference:
    if isinstance(value, EvidenceReference):
        return value
    if isinstance(value, Mapping):
        return EvidenceReference.from_dict(value)
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)) and len(value) == 3:
        return EvidenceReference(
            acquisition_file=str(value[0]),
            record_offset=int(value[1]),
            sample_index=int(value[2]),
        )
    raise EvidenceReferenceException(f"mapping value is not an evidence reference: {value!r}")


def resolve_legacy_csv_reference(
    row: Mapping[str, Any],
    mapping: Mapping[Any, Any],
    *,
    key: Any = None,
) -> EvidenceReference:
    """Resolve an old CSV row only through an explicit mapping.

    ``mapping`` may be keyed by the caller-supplied ``key``, by
    :func:`legacy_csv_reference_key`, by :func:`legacy_csv_reference_id`, or by
    an explicit ``path``/``subkey_name`` value from the row.  The function never
    searches a new export and never chooses a record by matching names, so an
    ambiguous old row cannot silently attach to the wrong physical key.
    """
    candidates: list[Any] = []
    if key is not None:
        candidates.append(key)
    candidates.append(legacy_csv_reference_key(row))
    candidates.append(legacy_csv_reference_id(row))
    for field in ("path", "subkey_name"):
        value = row.get(field)
        if value is not None:
            candidates.append(value)

    found: list[EvidenceReference] = []
    for candidate in candidates:
        try:
            if candidate in mapping:
                found.append(_coerce_reference(mapping[candidate]))
        except TypeError:
            continue

    unique = list(dict.fromkeys(found))
    if not unique:
        raise UnmappedLegacyReferenceException(
            "legacy CSV row has no explicit evidence-reference mapping; "
            "provide the row key, canonical key/id, or an explicit path mapping"
        )
    if len(unique) > 1:
        raise AmbiguousLegacyReferenceException(f"legacy CSV row maps to multiple evidence references: {unique!r}")
    return unique[0]
