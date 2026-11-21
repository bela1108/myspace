# -*- coding: utf-8 -*-
"""
Static type-reference attribution.

This module resolves TypeRef rows against a caller-supplied set of .NET
assemblies.  It never searches outside that set and never loads an assembly
implicitly from an AssemblyRef.

Resolution uses the metadata relations that matter for attribution:

* TypeRef.ResolutionScope (AssemblyRef, nested TypeRef, Module/ModuleRef)
* ExportedType.Implementation (AssemblyRef, nested ExportedType, File)
* NestedClass (enclosing TypeDef)

Every result and every graph edge keeps the 1-based metadata row that produced
it, so conclusions can be traced back to the input assembly.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Mapping, Optional, Set, Tuple


_IMPLEMENTATION_TABLES = ("File", "AssemblyRef", "ExportedType")
_RESOLUTION_SCOPE_TABLES = ("Module", "ModuleRef", "AssemblyRef", "TypeRef")
_IMPLEMENTATION_TAG_BITS = 2
_RESOLUTION_SCOPE_TAG_BITS = 2
_ASSEMBLY_REF_PUBLIC_KEY = 0x0001


class AttributionStatus(str, Enum):
    """Outcome of resolving one reference against one candidate assembly."""

    RESOLVED = "resolved"
    MISSING_ASSEMBLY = "missing-assembly"
    MISSING_TYPE = "missing-type"
    MISSING_MODULE = "missing-module"
    CYCLE = "cycle"
    INVALID = "invalid"

    def __str__(self) -> str:
        return self.value


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="backslashreplace")
    return str(value)


def _as_bytes(value: Any) -> bytes:
    if value is None:
        return b""
    if isinstance(value, bytes):
        return value
    raw = getattr(value, "value", None)
    if isinstance(raw, bytes):
        return raw
    try:
        return bytes(value)
    except (TypeError, ValueError):
        return b""


def public_key_token(public_key: Optional[bytes], *, contains_public_key: bool = True) -> Optional[bytes]:
    """
    Return the ECMA-335 public key token.

    An Assembly table always stores a full public key.  An AssemblyRef stores
    either a full key or an already-computed token, depending on
    ClrAssemblyFlags.afPublicKey.
    """

    if not public_key:
        return None
    if not contains_public_key or len(public_key) == 8:
        return bytes(public_key)
    digest = hashlib.sha1(public_key).digest()
    return digest[-1:-9:-1]


@dataclass(frozen=True)
class AssemblyIdentity:
    """The identity fields shared by Assembly and AssemblyRef rows."""

    name: str
    version: Tuple[int, int, int, int] = (0, 0, 0, 0)
    culture: Optional[str] = None
    public_key: Optional[bytes] = None
    public_key_token: Optional[bytes] = None
    flags: int = 0

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", _as_text(self.name))
        object.__setattr__(self, "version", tuple(int(x) for x in self.version))
        culture = _as_text(self.culture)
        object.__setattr__(self, "culture", culture or None)
        if self.public_key is not None:
            object.__setattr__(self, "public_key", bytes(self.public_key))
        if self.public_key_token is not None:
            object.__setattr__(self, "public_key_token", bytes(self.public_key_token))

    @property
    def version_string(self) -> str:
        return ".".join(str(x) for x in self.version)

    @property
    def token_hex(self) -> Optional[str]:
        if self.public_key_token is None:
            return None
        return "".join("%02x" % b for b in self.public_key_token)

    @property
    def full_name(self) -> str:
        parts = [self.name, "Version=%s" % self.version_string]
        if self.culture:
            parts.append("Culture=%s" % self.culture)
        if self.public_key_token:
            parts.append("PublicKeyToken=%s" % self.token_hex)
        return ", ".join(parts)

    def matches(self, other: Optional["AssemblyIdentity"], *, strict: bool = False) -> bool:
        if other is None:
            return False
        if self.name.casefold() != other.name.casefold():
            return False
        if strict and self.version != other.version:
            return False
        if self.culture and other.culture and self.culture.casefold() != other.culture.casefold():
            return False
        if self.public_key_token and other.public_key_token and self.public_key_token != other.public_key_token:
            return False
        return True


@dataclass(frozen=True)
class TypeIdentity:
    """A namespace/name pair, recursively qualified for nested types."""

    namespace: str = ""
    name: str = ""
    declaring_type: Optional["TypeIdentity"] = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "namespace", _as_text(self.namespace))
        object.__setattr__(self, "name", _as_text(self.name))

    @property
    def full_name(self) -> str:
        if self.declaring_type is not None:
            return "%s+%s" % (self.declaring_type.full_name, self.name)
        if self.namespace:
            return "%s.%s" % (self.namespace, self.name)
        return self.name

    def nested(self, name: str) -> "TypeIdentity":
        return TypeIdentity(name=name, declaring_type=self)


@dataclass(frozen=True)
class RowRef:
    """A stable reference to one physical metadata row (row indexes are 1-based)."""

    sample: str
    table: str
    row_index: int
    file_offset: Optional[int] = None

    def __post_init__(self) -> None:
        if self.row_index < 1:
            raise ValueError("metadata row indexes are 1-based")
        object.__setattr__(self, "sample", _as_text(self.sample))
        object.__setattr__(self, "table", _as_text(self.table))

    @property
    def path(self) -> str:
        return self.sample

    @property
    def table_name(self) -> str:
        return self.table

    @property
    def rid(self) -> int:
        return self.row_index


@dataclass(frozen=True)
class GraphEdge:
    """
    One metadata relation.

    ``source`` and ``target`` describe the logical relation.  ``table`` and
    ``row_index`` identify the physical row that encoded it; this is why the
    source may differ from the row for relations stored in a side table such
    as NestedClass.
    """

    kind: str
    sample: str
    table: str
    row_index: int
    source: Optional[RowRef] = None
    target: Optional[RowRef] = None
    file_offset: Optional[int] = None
    detail: str = ""

    def __post_init__(self) -> None:
        if self.row_index < 1:
            raise ValueError("metadata row indexes are 1-based")
        object.__setattr__(self, "sample", _as_text(self.sample))
        object.__setattr__(self, "table", _as_text(self.table))
        object.__setattr__(self, "kind", _as_text(self.kind))

    @property
    def provenance(self) -> RowRef:
        return RowRef(self.sample, self.table, self.row_index, self.file_offset)

    @property
    def source_row(self) -> RowRef:
        return self.provenance

    @property
    def target_table(self) -> Optional[str]:
        return self.target.table if self.target is not None else None

    @property
    def target_row_index(self) -> Optional[int]:
        return self.target.row_index if self.target is not None else None

    @property
    def origin(self) -> RowRef:
        return self.provenance


@dataclass(frozen=True)
class TypeReference:
    """The identity and static scope of one TypeRef row."""

    identity: TypeIdentity
    assembly: Optional[AssemblyIdentity] = None
    source: Optional[RowRef] = None
    assembly_ref_source: Optional[RowRef] = None
    scope: Tuple[RowRef, ...] = ()
    scope_kind: str = ""
    source_assembly: Optional[str] = None

    @property
    def namespace(self) -> str:
        return self.identity.namespace

    @property
    def name(self) -> str:
        return self.identity.name

    @property
    def full_name(self) -> str:
        return self.identity.full_name

    @property
    def assembly_ref(self) -> Optional[AssemblyIdentity]:
        return self.assembly


@dataclass(frozen=True)
class MissingEvidence:
    """Evidence retained when attribution cannot reach a definition."""

    reason: str
    reference: TypeReference
    expected_assembly: Optional[AssemblyIdentity] = None
    source: Optional[RowRef] = None
    searched_samples: Tuple[str, ...] = ()
    detail: str = ""

    @property
    def kind(self) -> str:
        return self.reason

    @property
    def assembly_ref(self) -> Optional[AssemblyIdentity]:
        return self.expected_assembly

    @property
    def table(self) -> Optional[str]:
        return self.source.table if self.source is not None else None

    @property
    def row_index(self) -> Optional[int]:
        return self.source.row_index if self.source is not None else None


@dataclass(frozen=True)
class TypeAttribution:
    """Attribution of one TypeRef to one candidate assembly."""

    reference: TypeReference
    status: AttributionStatus
    candidate: Optional[AssemblyIdentity] = None
    definition: Optional[RowRef] = None
    final_assembly: Optional[AssemblyIdentity] = None
    final_type: Optional[TypeIdentity] = None
    forwarded: bool = False
    version_match: Optional[bool] = None
    evidence: Tuple[GraphEdge, ...] = ()
    missing: Tuple[MissingEvidence, ...] = ()

    @property
    def resolved(self) -> bool:
        return self.status == AttributionStatus.RESOLVED

    @property
    def reference_identity(self) -> TypeIdentity:
        return self.reference.identity

    @property
    def identity(self) -> TypeIdentity:
        return self.reference.identity

    @property
    def full_name(self) -> str:
        return self.reference.full_name

    @property
    def assembly_ref(self) -> Optional[AssemblyIdentity]:
        return self.reference.assembly

    @property
    def assembly(self) -> Optional[AssemblyIdentity]:
        return self.candidate

    @property
    def table(self) -> Optional[str]:
        return self.reference.source.table if self.reference.source is not None else None

    @property
    def row_index(self) -> Optional[int]:
        return self.reference.source.row_index if self.reference.source is not None else None

    @property
    def source_row(self) -> Optional[RowRef]:
        return self.reference.source

    @property
    def missing_evidence(self) -> Tuple[MissingEvidence, ...]:
        return self.missing


class AttributionGraph:
    """Metadata relation graph with row provenance for every edge."""

    def __init__(self) -> None:
        self.nodes: List[RowRef] = []
        self.edges: List[GraphEdge] = []
        self._node_set: Set[Tuple[str, str, int]] = set()
        self._edge_set: Set[Tuple[Any, ...]] = set()
        self._row_counts: Dict[Tuple[str, str], int] = {}

    def add_row_count(self, sample: str, table: str, count: int) -> None:
        self._row_counts[(sample, table)] = count

    def add_node(self, node: Optional[RowRef]) -> None:
        if node is None:
            return
        key = (node.sample, node.table, node.row_index)
        if key not in self._node_set:
            self._node_set.add(key)
            self.nodes.append(node)

    def add_edge(self, edge: GraphEdge) -> GraphEdge:
        key = (
            edge.kind,
            edge.sample,
            edge.table,
            edge.row_index,
            edge.source,
            edge.target,
            edge.file_offset,
            edge.detail,
        )
        self.add_node(edge.source)
        self.add_node(edge.target)
        if key not in self._edge_set:
            self._edge_set.add(key)
            self.edges.append(edge)
        return edge

    def edges_from(self, sample: str, table: str, row_index: int) -> Tuple[GraphEdge, ...]:
        return tuple(
            edge
            for edge in self.edges
            if edge.sample == sample and edge.table == table and edge.row_index == row_index
        )

    def validate(self) -> None:
        """Check that every edge's physical row exists in its source table."""

        errors = []
        for edge in self.edges:
            expected = self._row_counts.get((edge.sample, edge.table))
            if expected is None:
                errors.append("edge %s references unknown table %s in %s" % (edge.kind, edge.table, edge.sample))
            elif edge.row_index < 1 or edge.row_index > expected:
                errors.append(
                    "edge %s has row %d outside %s (%d rows)"
                    % (edge.kind, edge.row_index, edge.table, expected)
                )
            for end in (edge.source, edge.target):
                if end is None:
                    continue
                if (end.sample, end.table, end.row_index) not in self._node_set:
                    errors.append("edge %s points to a missing graph node %r" % (edge.kind, end))
                    continue
                end_count = self._row_counts.get((end.sample, end.table))
                if end_count is not None and not (1 <= end.row_index <= end_count):
                    errors.append(
                        "edge %s target row %d outside %s (%d rows)"
                        % (edge.kind, end.row_index, end.table, end_count)
                    )
        if errors:
            raise ValueError("; ".join(errors))


@dataclass(frozen=True)
class SampleError:
    sample: str
    error: str


@dataclass(frozen=True)
class AttributionReport:
    """All TypeRef attributions plus the provenance graph used to derive them."""

    references: Tuple[TypeReference, ...]
    results: Tuple[TypeAttribution, ...]
    graph: AttributionGraph
    sample_assemblies: Tuple[AssemblyIdentity, ...] = ()
    errors: Tuple[SampleError, ...] = ()

    @property
    def attributions(self) -> Tuple[TypeAttribution, ...]:
        return self.results

    @property
    def resolved(self) -> Tuple[TypeAttribution, ...]:
        return tuple(result for result in self.results if result.resolved)

    @property
    def missing(self) -> Tuple[TypeAttribution, ...]:
        return tuple(result for result in self.results if not result.resolved)

    def for_reference(self, reference: TypeReference) -> Tuple[TypeAttribution, ...]:
        return tuple(result for result in self.results if result.reference == reference)

    def by_full_name(self, full_name: str) -> Tuple[TypeAttribution, ...]:
        return tuple(result for result in self.results if result.reference.full_name == full_name)

    by_name = by_full_name


@dataclass
class MetadataSample:
    """A sample supplied either as a dnPE or as metadata-table-like objects."""

    key: str
    metadata: Any
    pe: Any = None
    error: Optional[str] = None


@dataclass
class _DefinedType:
    identity: TypeIdentity
    row: RowRef


@dataclass
class _ExportedType:
    identity: TypeIdentity
    row: RowRef
    flags: int
    type_def_id: int
    implementation_kind: str
    implementation_row_index: Optional[int]
    implementation_row: Optional[RowRef]
    assembly_ref: Optional[AssemblyIdentity]
    enclosing_exported: Optional[RowRef]


@dataclass
class _Sample:
    key: str
    metadata: Any
    assembly: Optional[AssemblyIdentity]
    assembly_row: Optional[RowRef]
    assembly_refs: Dict[int, AssemblyIdentity]
    assembly_ref_rows: Dict[int, RowRef]
    type_defs: Dict[str, List[_DefinedType]]
    exported_types: Dict[str, List[_ExportedType]]
    exported_by_row: Dict[int, _ExportedType]
    type_refs: List[Tuple[int, Any, RowRef]]


@dataclass
class _Outcome:
    status: AttributionStatus
    candidate: Optional[AssemblyIdentity]
    definition: Optional[RowRef]
    final_assembly: Optional[AssemblyIdentity]
    final_type: Optional[TypeIdentity]
    forwarded: bool
    evidence: Tuple[GraphEdge, ...]
    missing: Tuple[MissingEvidence, ...]


def _get_attr(obj: Any, name: str, default: Any = None) -> Any:
    try:
        return getattr(obj, name)
    except (AttributeError, IndexError, TypeError, ValueError):
        return default


def _struct_attr(row: Any, name: str, default: Any = None) -> Any:
    struct = _get_attr(row, "struct")
    if struct is None:
        return _get_attr(row, name, default)
    return _get_attr(struct, name, default)


def _row_offset(row: Any, table: Any, row_index: int) -> Optional[int]:
    struct = _get_attr(row, "struct")
    getter = _get_attr(struct, "get_file_offset")
    if callable(getter):
        try:
            value = getter()
        except Exception:
            value = None
        if value is not None:
            return int(value)
    table_offset = _get_attr(table, "file_offset")
    row_size = _get_attr(table, "row_size")
    if table_offset is not None and row_size:
        return int(table_offset) + (row_index - 1) * int(row_size)
    return None


def _table_rows(table: Any) -> List[Tuple[int, Any]]:
    if table is None:
        return []
    rows = _get_attr(table, "rows")
    if rows is None and isinstance(table, Mapping):
        rows = list(table.values())
    if rows is None:
        try:
            rows = list(table)
        except TypeError:
            return []
    return [(i + 1, row) for i, row in enumerate(rows) if row is not None]


def _get_table(metadata: Any, name: str) -> Any:
    direct = _get_attr(metadata, name)
    if direct is not None:
        return direct

    tables = _get_attr(metadata, "tables")
    if isinstance(tables, Mapping):
        direct = tables.get(name)
        if direct is not None:
            return direct

    if isinstance(metadata, Mapping):
        return metadata.get(name)

    tables_list = _get_attr(metadata, "tables_list")
    if tables_list is not None:
        for table in tables_list:
            if _get_attr(table, "name") == name:
                return table
    return None


def _text_attr(row: Any, public_name: str, struct_name: str) -> str:
    value = _get_attr(row, public_name)
    if value is None:
        value = _struct_attr(row, struct_name)
    return _as_text(value)


def _int_attr(row: Any, name: str, default: int = 0) -> int:
    """Read the raw metadata value, before dnfile's ClrFlags wrapper."""

    value = _struct_attr(row, name, None)
    if value is None:
        value = _get_attr(row, name, default)
    if hasattr(value, "value") and not isinstance(value, (int, bytes)):
        value = value.value
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _assembly_identity_from_row(row: Any) -> AssemblyIdentity:
    version = tuple(
        int(_get_attr(row, name, _struct_attr(row, name, 0)) or 0)
        for name in ("MajorVersion", "MinorVersion", "BuildNumber", "RevisionNumber")
    )
    public_key = _as_bytes(_get_attr(row, "PublicKey"))
    return AssemblyIdentity(
        name=_text_attr(row, "Name", "Name_StringIndex"),
        version=version,
        culture=_text_attr(row, "Culture", "Culture_StringIndex"),
        public_key=public_key or None,
        public_key_token=public_key_token(public_key, contains_public_key=True),
        flags=_int_attr(row, "Flags"),
    )


def _assembly_ref_identity_from_row(row: Any) -> AssemblyIdentity:
    version = tuple(
        int(_get_attr(row, name, _struct_attr(row, name, 0)) or 0)
        for name in ("MajorVersion", "MinorVersion", "BuildNumber", "RevisionNumber")
    )
    flags = _int_attr(row, "Flags")
    public_key = _as_bytes(_get_attr(row, "PublicKey"))
    return AssemblyIdentity(
        name=_text_attr(row, "Name", "Name_StringIndex"),
        version=version,
        culture=_text_attr(row, "Culture", "Culture_StringIndex"),
        public_key=public_key or None,
        public_key_token=public_key_token(public_key, contains_public_key=bool(flags & _ASSEMBLY_REF_PUBLIC_KEY)),
        flags=flags,
    )


def _split_coded_index(value: Any, tag_bits: int) -> Tuple[int, int]:
    try:
        encoded = int(value)
    except (TypeError, ValueError):
        return -1, 0
    return encoded & ((1 << tag_bits) - 1), encoded >> tag_bits


def _coerce_source(source: Any) -> Any:
    if isinstance(source, MetadataSample):
        return source
    if isinstance(source, (str, os.PathLike)):
        path = Path(source)
        if path.is_dir():
            return path
        return path
    return source


def _sample_key(source: Any, index: int) -> str:
    if isinstance(source, MetadataSample):
        return source.key
    if isinstance(source, (str, os.PathLike)):
        return os.fspath(source)
    for attr in ("key", "name", "filename"):
        value = _get_attr(source, attr)
        if value:
            return str(value)
    return "<memory:%d>" % index


def _normalize_sample_inputs(samples: Any) -> List[Any]:
    if isinstance(samples, (str, os.PathLike, MetadataSample)):
        return [samples]
    if _get_attr(samples, "net") is not None or _get_attr(samples, "mdtables") is not None:
        return [samples]
    if isinstance(samples, Mapping):
        if not samples:
            return []
        values = list(samples.values())
        if all(_get_attr(value, "rows") is not None for value in values):
            return [samples]
        return [
            MetadataSample(key=str(key), metadata=value)
            for key, value in samples.items()
        ]
    try:
        return list(samples)
    except TypeError:
        return [samples]


def _load_paths(paths: Iterable[Any], clr_lazy_load: bool) -> List[MetadataSample]:
    samples: List[MetadataSample] = []
    seen: Set[str] = set()

    def add_path(path: Path) -> None:
        key = os.fspath(path)
        if key in seen:
            return
        seen.add(key)
        try:
            import dnfile

            pe = dnfile.dnPE(str(path), clr_lazy_load=clr_lazy_load)
            samples.append(MetadataSample(key=key, metadata=pe.net, pe=pe))
        except Exception as exc:
            samples.append(MetadataSample(key=key, metadata=None, error="%s: %s" % (type(exc).__name__, exc)))

    for item in paths:
        source = _coerce_source(item)
        if isinstance(source, Path) and source.is_dir():
            for child in sorted(source.iterdir(), key=lambda p: p.name):
                if child.is_file() and child.suffix.casefold() in (".dll", ".exe", ".netmodule"):
                    add_path(child)
            continue
        if isinstance(source, Path):
            add_path(source)
            continue
        if isinstance(source, MetadataSample):
            samples.append(source)
            continue

        metadata = _get_attr(source, "_metadata")
        if metadata is None:
            net = _get_attr(source, "net")
            metadata = net if net is not None else source
        key = _sample_key(source, len(samples))
        samples.append(MetadataSample(key=key, metadata=metadata, pe=source))
    return samples


def load_sample_set(samples: Iterable[Any], *, clr_lazy_load: bool = False) -> Tuple[MetadataSample, ...]:
    """
    Parse only the supplied samples.

    A sample may be a file path, a directory whose immediate .dll/.exe/
    .netmodule children are the supplied set, a dnPE object, or a
    MetadataSample wrapper.
    """

    return tuple(_load_paths(_normalize_sample_inputs(samples), clr_lazy_load))


class StaticTypeAttributor:
    """Resolve TypeRef rows across a fixed, caller-supplied sample set."""

    def __init__(
        self,
        samples: Iterable[Any],
        *,
        clr_lazy_load: bool = False,
        max_forward_depth: int = 32,
    ) -> None:
        self.max_forward_depth = max_forward_depth
        self.input_samples = load_sample_set(samples, clr_lazy_load=clr_lazy_load)
        self.graph = AttributionGraph()
        self._samples: List[_Sample] = []
        self._by_assembly_name: Dict[str, List[_Sample]] = {}
        self._errors: List[SampleError] = []
        self._build()

    @classmethod
    def from_paths(cls, paths: Iterable[Any], **kwargs: Any) -> "StaticTypeAttributor":
        return cls(paths, **kwargs)

    def _metadata_tables(self, sample: MetadataSample) -> Any:
        metadata = sample.metadata
        if metadata is None:
            return None
        net = _get_attr(metadata, "net")
        if net is not None and _get_attr(net, "mdtables") is not None:
            return _get_attr(net, "mdtables")
        mdtables = _get_attr(metadata, "mdtables")
        if mdtables is not None:
            return mdtables
        return metadata

    def _build(self) -> None:
        for sample in self.input_samples:
            if sample.error:
                self._errors.append(SampleError(sample.key, sample.error))
                continue
            tables = self._metadata_tables(sample)
            if tables is None:
                self._errors.append(SampleError(sample.key, "no .NET metadata"))
                continue
            try:
                self._samples.append(self._build_sample(sample, tables))
            except Exception as exc:
                self._errors.append(SampleError(sample.key, "%s: %s" % (type(exc).__name__, exc)))

        for sample in self._samples:
            if sample.assembly is not None:
                self._by_assembly_name.setdefault(sample.assembly.name.casefold(), []).append(sample)

    def _build_sample(self, supplied: MetadataSample, tables: Any) -> _Sample:
        sample_key = supplied.key
        assembly_table = _get_table(tables, "Assembly")
        assembly_rows = _table_rows(assembly_table)
        assembly = None
        assembly_row = None
        if assembly_rows:
            index, row = assembly_rows[0]
            assembly = _assembly_identity_from_row(row)
            assembly_row = RowRef(sample_key, "Assembly", index, _row_offset(row, assembly_table, index))
            self.graph.add_node(assembly_row)
        self.graph.add_row_count(sample_key, "Assembly", len(assembly_rows))

        for supplemental in ("Module", "ModuleRef", "File"):
            self.graph.add_row_count(sample_key, supplemental, len(_table_rows(_get_table(tables, supplemental))))

        assembly_refs: Dict[int, AssemblyIdentity] = {}
        assembly_ref_rows: Dict[int, RowRef] = {}
        assembly_ref_table = _get_table(tables, "AssemblyRef")
        for index, row in _table_rows(assembly_ref_table):
            assembly_refs[index] = _assembly_ref_identity_from_row(row)
            ref = RowRef(sample_key, "AssemblyRef", index, _row_offset(row, assembly_ref_table, index))
            assembly_ref_rows[index] = ref
            self.graph.add_node(ref)
        self.graph.add_row_count(sample_key, "AssemblyRef", len(_table_rows(assembly_ref_table)))

        type_def_table = _get_table(tables, "TypeDef")
        type_def_rows = _table_rows(type_def_table)
        self.graph.add_row_count(sample_key, "TypeDef", len(type_def_rows))
        raw_type_defs: Dict[int, Tuple[Any, RowRef]] = {}
        raw_names: Dict[int, TypeIdentity] = {}
        for index, row in type_def_rows:
            ref = RowRef(sample_key, "TypeDef", index, _row_offset(row, type_def_table, index))
            raw_type_defs[index] = (row, ref)
            raw_names[index] = TypeIdentity(
                namespace=_text_attr(row, "TypeNamespace", "TypeNamespace_StringIndex"),
                name=_text_attr(row, "TypeName", "TypeName_StringIndex"),
            )
            self.graph.add_node(ref)

        nested_table = _get_table(tables, "NestedClass")
        nested_rows = _table_rows(nested_table)
        self.graph.add_row_count(sample_key, "NestedClass", len(nested_rows))
        parent_by_nested: Dict[int, int] = {}
        for index, row in nested_rows:
            nested_index = int(_struct_attr(row, "NestedClass_Index", 0) or 0)
            enclosing_index = int(_struct_attr(row, "EnclosingClass_Index", 0) or 0)
            if nested_index <= 0 or enclosing_index <= 0:
                continue
            parent_by_nested[nested_index] = enclosing_index
            source = raw_type_defs.get(nested_index, (None, None))[1]
            target = raw_type_defs.get(enclosing_index, (None, None))[1]
            self.graph.add_edge(
                GraphEdge(
                    kind="typedef.nested-in",
                    sample=sample_key,
                    table="NestedClass",
                    row_index=index,
                    source=source,
                    target=target,
                    file_offset=_row_offset(row, nested_table, index),
                )
            )

        def resolve_type_def_identity(index: int, stack: Set[int]) -> TypeIdentity:
            if index in raw_names and index not in stack:
                stack.add(index)
                parent = parent_by_nested.get(index)
                base = raw_names[index]
                if parent and parent in raw_names:
                    identity = resolve_type_def_identity(parent, stack).nested(base.name)
                else:
                    identity = base
                raw_names[index] = identity
                stack.discard(index)
            return raw_names[index]

        type_defs: Dict[str, List[_DefinedType]] = {}
        for index, (_, ref) in raw_type_defs.items():
            identity = resolve_type_def_identity(index, set())
            type_defs.setdefault(identity.full_name, []).append(_DefinedType(identity, ref))

        exported_table = _get_table(tables, "ExportedType")
        exported_rows = _table_rows(exported_table)
        self.graph.add_row_count(sample_key, "ExportedType", len(exported_rows))
        raw_exports: Dict[int, Tuple[Any, RowRef]] = {}
        for index, row in exported_rows:
            ref = RowRef(sample_key, "ExportedType", index, _row_offset(row, exported_table, index))
            raw_exports[index] = (row, ref)
            self.graph.add_node(ref)

        exported_by_row: Dict[int, _ExportedType] = {}
        for index, (row, ref) in raw_exports.items():
            encoded = _struct_attr(row, "Implementation_CodedIndex", 0)
            tag, target_index = _split_coded_index(encoded, _IMPLEMENTATION_TAG_BITS)
            kind = _IMPLEMENTATION_TABLES[tag] if 0 <= tag < len(_IMPLEMENTATION_TABLES) else "Invalid"
            implementation_row = None
            assembly_ref = None
            enclosing_exported = None
            if kind == "AssemblyRef":
                assembly_ref = assembly_refs.get(target_index)
                implementation_row = assembly_ref_rows.get(target_index)
            elif kind == "ExportedType":
                implementation_row = raw_exports.get(target_index, (None, None))[1]
                enclosing_exported = implementation_row
            elif kind == "File":
                file_table = _get_table(tables, "File")
                file_rows = _table_rows(file_table)
                if 0 < target_index <= len(file_rows):
                    implementation_row = RowRef(
                        sample_key,
                        "File",
                        target_index,
                        _row_offset(file_rows[target_index - 1][1], file_table, target_index),
                    )
            if implementation_row is not None:
                self.graph.add_edge(
                    GraphEdge(
                        kind="exportedtype.implementation",
                        sample=sample_key,
                        table="ExportedType",
                        row_index=index,
                        source=ref,
                        target=implementation_row,
                        file_offset=_row_offset(row, exported_table, index),
                        detail=kind,
                    )
                )
            exported_by_row[index] = _ExportedType(
                identity=TypeIdentity(
                    namespace=_text_attr(row, "TypeNamespace", "TypeNamespace_StringIndex"),
                    name=_text_attr(row, "TypeName", "TypeName_StringIndex"),
                ),
                row=ref,
                flags=_int_attr(row, "Flags"),
                type_def_id=_int_attr(row, "TypeDefId"),
                implementation_kind=kind,
                implementation_row_index=target_index,
                implementation_row=implementation_row,
                assembly_ref=assembly_ref,
                enclosing_exported=enclosing_exported,
            )

        def resolve_export_identity(index: int, stack: Set[int]) -> TypeIdentity:
            exported = exported_by_row[index]
            if index not in stack and exported.enclosing_exported is not None:
                stack.add(index)
                parent_index = exported.enclosing_exported.row_index
                if parent_index in exported_by_row:
                    exported.identity = resolve_export_identity(parent_index, stack).nested(exported.identity.name)
                stack.discard(index)
            return exported.identity

        exported_types: Dict[str, List[_ExportedType]] = {}
        for index, exported in exported_by_row.items():
            identity = resolve_export_identity(index, set())
            exported_types.setdefault(identity.full_name, []).append(exported)

        type_ref_table = _get_table(tables, "TypeRef")
        type_ref_rows = _table_rows(type_ref_table)
        self.graph.add_row_count(sample_key, "TypeRef", len(type_ref_rows))
        type_ref_entries = []
        type_ref_refs: Dict[int, RowRef] = {}
        for index, row in type_ref_rows:
            ref = RowRef(sample_key, "TypeRef", index, _row_offset(row, type_ref_table, index))
            type_ref_entries.append((index, row, ref))
            type_ref_refs[index] = ref

        type_refs: List[Tuple[int, Any, RowRef]] = []
        for index, row, ref in type_ref_entries:
            self.graph.add_node(ref)
            type_refs.append((index, row, ref))
            encoded = _struct_attr(row, "ResolutionScope_CodedIndex", 0)
            tag, target_index = _split_coded_index(encoded, _RESOLUTION_SCOPE_TAG_BITS)
            kind = _RESOLUTION_SCOPE_TABLES[tag] if 0 <= tag < len(_RESOLUTION_SCOPE_TABLES) else "Invalid"
            target = None
            if kind == "TypeRef":
                target = type_ref_refs.get(target_index)
            elif kind == "AssemblyRef":
                target = assembly_ref_rows.get(target_index)
            elif kind in ("Module", "ModuleRef") and target_index:
                target_table = _get_table(tables, kind)
                target_rows = _table_rows(target_table)
                if target_index <= len(target_rows):
                    target = RowRef(
                        sample_key,
                        kind,
                        target_index,
                        _row_offset(target_rows[target_index - 1][1], target_table, target_index),
                    )
            if target is not None:
                self.graph.add_edge(
                    GraphEdge(
                        kind="typeref.scope",
                        sample=sample_key,
                        table="TypeRef",
                        row_index=index,
                        source=ref,
                        target=target,
                        file_offset=_row_offset(row, type_ref_table, index),
                        detail=kind,
                    )
                )

        return _Sample(
            key=sample_key,
            metadata=tables,
            assembly=assembly,
            assembly_row=assembly_row,
            assembly_refs=assembly_refs,
            assembly_ref_rows=assembly_ref_rows,
            type_defs=type_defs,
            exported_types=exported_types,
            exported_by_row=exported_by_row,
            type_refs=type_refs,
        )

    def _sample_by_key(self, key: str) -> Optional[_Sample]:
        for sample in self._samples:
            if sample.key == key:
                return sample
        return None

    def _type_ref_identity(
        self,
        sample: _Sample,
        row_index: int,
        stack: Optional[Set[int]] = None,
    ) -> Tuple[TypeIdentity, Optional[AssemblyIdentity], Tuple[RowRef, ...], str, Optional[RowRef]]:
        stack = stack or set()
        if row_index in stack:
            raise ValueError("nested TypeRef cycle")
        stack.add(row_index)

        row_map = {index: (row, ref) for index, row, ref in sample.type_refs}
        row, ref = row_map[row_index]
        base = TypeIdentity(
            namespace=_text_attr(row, "TypeNamespace", "TypeNamespace_StringIndex"),
            name=_text_attr(row, "TypeName", "TypeName_StringIndex"),
        )
        encoded = _struct_attr(row, "ResolutionScope_CodedIndex", 0)
        tag, target_index = _split_coded_index(encoded, _RESOLUTION_SCOPE_TAG_BITS)
        kind = _RESOLUTION_SCOPE_TABLES[tag] if 0 <= tag < len(_RESOLUTION_SCOPE_TABLES) else "Invalid"
        if kind == "TypeRef" and target_index:
            parent_identity, parent_assembly, parent_scope, _, parent_ref = self._type_ref_identity(sample, target_index, stack)
            identity = parent_identity.nested(base.name)
            scope = parent_scope + (ref,)
            result = (identity, parent_assembly, scope, "TypeRef", parent_ref)
        elif kind == "AssemblyRef":
            result = (base, sample.assembly_refs.get(target_index), (ref,), "AssemblyRef", sample.assembly_ref_rows.get(target_index))
        elif kind in ("Module", "ModuleRef"):
            result = (base, sample.assembly, (ref,), kind, None)
        elif encoded == 0:
            result = (base, sample.assembly, (ref,), "Module", None)
        else:
            result = (base, None, (ref,), kind, None)

        stack.discard(row_index)
        return result

    def _type_references(self) -> List[TypeReference]:
        references = []
        for sample in self._samples:
            for row_index, _, source in sample.type_refs:
                try:
                    identity, assembly, scope, scope_kind, assembly_ref_source = self._type_ref_identity(sample, row_index)
                except Exception:
                    row = next((r for i, r, _ in sample.type_refs if i == row_index), None)
                    identity = TypeIdentity(
                        namespace=_text_attr(row, "TypeNamespace", "TypeNamespace_StringIndex"),
                        name=_text_attr(row, "TypeName", "TypeName_StringIndex"),
                    )
                    assembly = None
                    scope = (source,)
                    scope_kind = "Invalid"
                    assembly_ref_source = None
                references.append(
                    TypeReference(
                        identity=identity,
                        assembly=assembly,
                        source=source,
                        assembly_ref_source=assembly_ref_source,
                        scope=scope,
                        scope_kind=scope_kind,
                        source_assembly=sample.assembly.name if sample.assembly else None,
                    )
                )
        return references

    def _candidate_samples(self, reference: TypeReference, source_sample: Optional[_Sample]) -> List[_Sample]:
        if reference.scope_kind in ("Module", "ModuleRef"):
            return [source_sample] if source_sample is not None else []
        if reference.assembly is None:
            return []
        return list(self._by_assembly_name.get(reference.assembly.name.casefold(), ()))

    def _evidence_for_reference(self, reference: TypeReference, source_sample: Optional[_Sample]) -> Tuple[GraphEdge, ...]:
        evidence: List[GraphEdge] = []
        if source_sample is None:
            return ()
        for scope_row in reference.scope:
            evidence.extend(self.graph.edges_from(scope_row.sample, scope_row.table, scope_row.row_index))
        return tuple(evidence)

    def _export_chain_evidence(self, sample: _Sample, exported: _ExportedType) -> Tuple[GraphEdge, ...]:
        evidence: List[GraphEdge] = []
        seen: Set[int] = set()
        current: Optional[_ExportedType] = exported
        while current is not None and current.row.row_index not in seen:
            seen.add(current.row.row_index)
            evidence.extend(self.graph.edges_from(sample.key, "ExportedType", current.row.row_index))
            if current.enclosing_exported is None:
                break
            current = sample.exported_by_row.get(current.enclosing_exported.row_index)
        return tuple(evidence)

    def _root_exported(self, sample: _Sample, exported: _ExportedType) -> _ExportedType:
        current = exported
        seen: Set[int] = set()
        while current.enclosing_exported is not None and current.row.row_index not in seen:
            seen.add(current.row.row_index)
            parent = sample.exported_by_row.get(current.enclosing_exported.row_index)
            if parent is None:
                break
            current = parent
        return current

    def _resolve_forward(
        self,
        source_sample: _Sample,
        exported: _ExportedType,
        identity: TypeIdentity,
        reference: TypeReference,
        depth: int,
        visited: Set[Tuple[str, str]],
    ) -> List[_Outcome]:
        evidence = self._export_chain_evidence(source_sample, exported)
        root = self._root_exported(source_sample, exported)
        if depth >= self.max_forward_depth:
            missing = MissingEvidence(
                reason=AttributionStatus.CYCLE.value,
                reference=reference,
                expected_assembly=root.assembly_ref,
                source=root.row,
                searched_samples=(source_sample.key,),
                detail="forwarding depth limit reached",
            )
            return [_Outcome(AttributionStatus.CYCLE, source_sample.assembly, None, None, None, True, evidence, (missing,))]

        if root.implementation_kind == "AssemblyRef" and root.assembly_ref is not None:
            target_samples = self._by_assembly_name.get(root.assembly_ref.name.casefold(), [])
            if not target_samples:
                missing = MissingEvidence(
                    reason=AttributionStatus.MISSING_ASSEMBLY.value,
                    reference=reference,
                    expected_assembly=root.assembly_ref,
                    source=root.row,
                    searched_samples=tuple(sample.key for sample in self._samples),
                    detail="AssemblyRef target is absent from the supplied sample set",
                )
                return [
                    _Outcome(
                        AttributionStatus.MISSING_ASSEMBLY,
                        source_sample.assembly,
                        None,
                        None,
                        None,
                        True,
                        evidence,
                        (missing,),
                    )
                ]

            outcomes: List[_Outcome] = []
            for target_sample in target_samples:
                visit_key = (target_sample.key, identity.full_name)
                if visit_key in visited:
                    missing = MissingEvidence(
                        reason=AttributionStatus.CYCLE.value,
                        reference=reference,
                        expected_assembly=root.assembly_ref,
                        source=root.row,
                        searched_samples=(target_sample.key,),
                        detail="forwarding cycle",
                    )
                    outcomes.append(
                        _Outcome(
                            AttributionStatus.CYCLE,
                            source_sample.assembly,
                            None,
                            None,
                            None,
                            True,
                            evidence,
                            (missing,),
                        )
                    )
                    continue

                nested_visited = set(visited)
                target_outcomes = self._resolve_in_sample(
                    target_sample, identity, reference, depth + 1, nested_visited
                )
                for target_outcome in target_outcomes:
                    outcomes.append(
                        _Outcome(
                            status=target_outcome.status,
                            candidate=source_sample.assembly,
                            definition=target_outcome.definition,
                            final_assembly=target_outcome.final_assembly,
                            final_type=target_outcome.final_type,
                            forwarded=True,
                            evidence=evidence + target_outcome.evidence,
                            missing=target_outcome.missing,
                        )
                    )
            return outcomes

        if root.implementation_kind == "File":
            missing = MissingEvidence(
                reason=AttributionStatus.MISSING_MODULE.value,
                reference=reference,
                source=root.row,
                searched_samples=(source_sample.key,),
                detail="type is implemented in another module (File row)",
            )
            return [
                _Outcome(
                    AttributionStatus.MISSING_MODULE,
                    source_sample.assembly,
                    None,
                    None,
                    None,
                    True,
                    evidence,
                    (missing,),
                )
            ]

        missing = MissingEvidence(
            reason=AttributionStatus.MISSING_TYPE.value,
            reference=reference,
            source=root.row,
            searched_samples=(source_sample.key,),
            detail="ExportedType has no usable implementation",
        )
        return [
            _Outcome(
                AttributionStatus.MISSING_TYPE,
                source_sample.assembly,
                None,
                None,
                None,
                True,
                evidence,
                (missing,),
            )
        ]

    def _resolve_in_sample(
        self,
        sample: _Sample,
        identity: TypeIdentity,
        reference: TypeReference,
        depth: int = 0,
        visited: Optional[Set[Tuple[str, str]]] = None,
    ) -> List[_Outcome]:
        visited = visited or set()
        visit_key = (sample.key, identity.full_name)
        if visit_key in visited and depth > 0:
            missing = MissingEvidence(
                reason=AttributionStatus.CYCLE.value,
                reference=reference,
                source=reference.source,
                searched_samples=(sample.key,),
                detail="type resolution cycle",
            )
            return [
                _Outcome(
                    AttributionStatus.CYCLE,
                    sample.assembly,
                    None,
                    None,
                    None,
                    False,
                    (),
                    (missing,),
                )
            ]
        visited.add(visit_key)

        definitions = sample.type_defs.get(identity.full_name, [])
        if definitions:
            return [
                _Outcome(
                    AttributionStatus.RESOLVED,
                    sample.assembly,
                    definition.row,
                    sample.assembly,
                    definition.identity,
                    False,
                    (),
                    (),
                )
                for definition in definitions
            ]

        exports = sample.exported_types.get(identity.full_name, [])
        outcomes: List[_Outcome] = []
        for exported in exports:
            root = self._root_exported(sample, exported)
            if root.implementation_kind == "AssemblyRef":
                outcomes.extend(
                    self._resolve_forward(sample, exported, identity, reference, depth, visited)
                )
            elif root.implementation_kind == "ExportedType":
                parent_identity = root.identity
                outcomes.extend(
                    self._resolve_in_sample(sample, parent_identity, reference, depth + 1, set(visited))
                )
            elif root.implementation_kind == "File":
                outcomes.extend(
                    self._resolve_forward(sample, exported, identity, reference, depth, visited)
                )
            elif root.type_def_id:
                definition = next(
                    (candidate for candidate in sample.type_defs.values() if candidate and candidate[0].row.row_index == root.type_def_id),
                    None,
                )
                if definition:
                    outcomes.append(
                        _Outcome(
                            AttributionStatus.RESOLVED,
                            sample.assembly,
                            definition[0].row,
                            sample.assembly,
                            definition[0].identity,
                            False,
                            self._export_chain_evidence(sample, exported),
                            (),
                        )
                    )
        if outcomes:
            return outcomes

        missing = MissingEvidence(
            reason=AttributionStatus.MISSING_TYPE.value,
            reference=reference,
            expected_assembly=sample.assembly,
            source=reference.source,
            searched_samples=(sample.key,),
            detail="TypeDef and ExportedType tables contain no matching type",
        )
        return [
            _Outcome(
                AttributionStatus.MISSING_TYPE,
                sample.assembly,
                None,
                None,
                None,
                False,
                (),
                (missing,),
            )
        ]

    def _resolve_reference(self, reference: TypeReference) -> List[TypeAttribution]:
        source_sample = None
        if reference.source is not None:
            source_sample = self._sample_by_key(reference.source.sample)
        candidates = self._candidate_samples(reference, source_sample)
        reference_evidence = self._evidence_for_reference(reference, source_sample)

        if not candidates:
            missing = MissingEvidence(
                reason=AttributionStatus.MISSING_ASSEMBLY.value,
                reference=reference,
                expected_assembly=reference.assembly,
                source=reference.assembly_ref_source or reference.source,
                searched_samples=tuple(sample.key for sample in self._samples),
                detail="AssemblyRef target is absent from the supplied sample set",
            )
            return [
                TypeAttribution(
                    reference=reference,
                    status=AttributionStatus.MISSING_ASSEMBLY,
                    evidence=reference_evidence,
                    missing=(missing,),
                )
            ]

        results: List[TypeAttribution] = []
        for candidate in candidates:
            candidate_version_match = (
                reference.assembly.version == candidate.assembly.version
                if reference.assembly is not None and candidate.assembly is not None
                else None
            )
            outcomes = self._resolve_in_sample(candidate, reference.identity, reference)
            for outcome in outcomes:
                evidence = reference_evidence + outcome.evidence
                if outcome.status == AttributionStatus.RESOLVED and outcome.definition is not None:
                    self.graph.add_edge(
                        GraphEdge(
                            kind="attribution.resolved",
                            sample=reference.source.sample if reference.source is not None else candidate.key,
                            table="TypeRef" if reference.source is not None else "Assembly",
                            row_index=reference.source.row_index if reference.source is not None else 1,
                            source=reference.source,
                            target=outcome.definition,
                            file_offset=reference.source.file_offset if reference.source is not None else None,
                        )
                    )
                results.append(
                    TypeAttribution(
                        reference=reference,
                        status=outcome.status,
                        candidate=candidate.assembly,
                        definition=outcome.definition,
                        final_assembly=outcome.final_assembly,
                        final_type=outcome.final_type,
                        forwarded=outcome.forwarded,
                        version_match=candidate_version_match,
                        evidence=evidence,
                        missing=outcome.missing,
                    )
                )
        return results

    def attribute(self) -> AttributionReport:
        references = self._type_references()
        results: List[TypeAttribution] = []
        for reference in references:
            results.extend(self._resolve_reference(reference))
        return AttributionReport(
            references=tuple(references),
            results=tuple(results),
            graph=self.graph,
            sample_assemblies=tuple(sample.assembly for sample in self._samples if sample.assembly is not None),
            errors=tuple(self._errors),
        )

    def __iter__(self) -> Iterator[TypeAttribution]:
        return iter(self.attribute().results)


def build_attribution_graph(samples: Iterable[Any], *, clr_lazy_load: bool = False) -> AttributionGraph:
    """Build and validate a provenance graph without resolving references."""

    attributor = StaticTypeAttributor(samples, clr_lazy_load=clr_lazy_load)
    attributor.graph.validate()
    return attributor.graph


def attribute_type_references(
    samples: Iterable[Any],
    *,
    clr_lazy_load: bool = False,
    max_forward_depth: int = 32,
) -> AttributionReport:
    """Resolve every TypeRef in the supplied samples against those same samples."""

    attributor = StaticTypeAttributor(
        samples,
        clr_lazy_load=clr_lazy_load,
        max_forward_depth=max_forward_depth,
    )
    report = attributor.attribute()
    report.graph.validate()
    return report


attribute_type_refs = attribute_type_references
attribute_types = attribute_type_references
resolve_type_references = attribute_type_references
TypeAttributor = StaticTypeAttributor
attribute = attribute_type_references
build_graph = build_attribution_graph
StaticAttributor = StaticTypeAttributor
AttributionResult = TypeAttribution

__all__ = (
    'AssemblyIdentity',
    'AttributionGraph',
    'AttributionReport',
    'AttributionResult',
    'AttributionStatus',
    'GraphEdge',
    'MetadataSample',
    'MissingEvidence',
    'RowRef',
    'SampleError',
    'StaticAttributor',
    'StaticTypeAttributor',
    'TypeAttribution',
    'TypeAttributor',
    'TypeIdentity',
    'TypeReference',
    'attribute',
    'attribute_type_refs',
    'attribute_type_references',
    'attribute_types',
    'build_attribution_graph',
    'build_graph',
    'load_sample_set',
    'public_key_token',
    'resolve_type_references',
)
