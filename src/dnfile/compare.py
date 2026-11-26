"""Cross-reference metadata TypeDef rows between two builds.

Row numbers in metadata tables are positional and can change when types are
inserted.  This module builds a parent-qualified identity for TypeDef rows so
that archive observations can be moved to their new row numbers without
collapsing types that merely share a simple name.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, DefaultDict, Dict, List, Mapping, Optional, Sequence, Tuple, Union


NEW_DEFINITION = "new_definition"
UNCHANGED = "unchanged"
MOVED = "moved"
AMBIGUOUS = "ambiguous"
PARENT_CHANGED = "parent_changed"
SCOPE_CHANGED = "scope_changed"
REMOVED = "removed"

VERDICT_PRESERVED_IN_PLACE = "preserved_in_place"
VERDICT_RELOCATED = "relocated"
VERDICT_NEW = "new_definition"
VERDICT_AMBIGUOUS = "ambiguous"
VERDICT_NOT_PRESERVED = "not_preserved"


class VerdictMixin:
    preservation: str

    @property
    def preserved(self) -> bool:
        raise NotImplementedError

    @property
    def verdict(self) -> str:
        return self.preservation

    def is_preserved(self) -> bool:
        return self.preserved is True


_FIELD_ALIASES = {
    "name": (
        "TypeName",
        "type_name",
        "Name",
        "name",
        "SimpleName",
        "simple_name",
        "类型名",
        "类型名称",
        "简名",
        "名称",
    ),
    "namespace": (
        "TypeNamespace",
        "type_namespace",
        "Namespace",
        "namespace",
        "命名空间",
    ),
    "module": (
        "ModuleName",
        "module_name",
        "module",
        "Module",
        "模块名",
        "模块名称",
        "模块",
    ),
    "rid": (
        "RowIndex",
        "row_index",
        "RID",
        "rid",
        "RowNumber",
        "row_number",
        "行号",
        "表行号",
        "元数据行号",
        "MetadataRowIndex",
        "metadata_row_index",
    ),
    "token": ("MetadataToken", "metadata_token", "Token", "token"),
    "parent_ref": (
        "EnclosingClass",
        "enclosing_class",
        "EnclosingType",
        "enclosing_type",
        "ParentType",
        "parent_type",
        "DeclaringType",
        "declaring_type",
        "DeclaringTypeName",
        "declaring_type_name",
        "EnclosingTypeName",
        "enclosing_type_name",
        "Parent",
        "parent",
        "ParentName",
        "parent_name",
        "parent_simple_name",
        "父类型",
        "父类型名称",
        "外层类型",
        "外层类型名称",
        "所属类型",
        "声明类型",
        "父",
    ),
    "nested_ref": (
        "NestedClass",
        "nested_class",
        "NestedType",
        "nested_type",
        "Nested",
        "nested",
        "嵌套类型",
        "内嵌类型",
        "Class",
        "class",
    ),
    "enclosing_ref": (
        "EnclosingClass",
        "enclosing_class",
        "Enclosing",
        "enclosing",
        "Parent",
        "parent",
        "外层类型",
        "父类型",
        "外围类型",
    ),
}


def _normalized_key(key: Any) -> str:
    return str(key).lower().replace("_", "").replace("-", "")


def _get_field(obj: Any, names: Sequence[str], default: Any = None) -> Any:
    if obj is None:
        return default

    if isinstance(obj, Mapping):
        for name in names:
            if name in obj:
                return obj[name]
        normalized = {_normalized_key(key): value for key, value in obj.items()}
        for name in names:
            key = _normalized_key(name)
            if key in normalized:
                return normalized[key]
        return default

    for name in names:
        try:
            if hasattr(obj, name):
                return getattr(obj, name)
        except Exception:
            continue

    wanted = {_normalized_key(name) for name in names}
    for attr in dir(obj):
        if attr.startswith("__"):
            continue
        if _normalized_key(attr) in wanted:
            try:
                return getattr(obj, attr)
            except Exception:
                continue
    return default


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace").rstrip("\x00")
    item_value = getattr(value, "value", None)
    if item_value is not None and item_value is not value:
        return _as_text(item_value)
    return str(value)


def _rows_from_value(value: Any) -> List[Any]:
    if value is None:
        return []
    if hasattr(value, "rows"):
        rows = value.rows
        return list(rows or [])
    if hasattr(value, "columns") and hasattr(value, "to_dict"):
        return list(value.to_dict(orient="records"))
    if isinstance(value, (list, tuple)):
        return list(value)
    try:
        return list(value)
    except TypeError:
        return [value]


def _table_from_source(source: Any, table_name: str) -> List[Any]:
    if source is None:
        return []

    if isinstance(source, Mapping):
        direct = _get_field(source, (table_name,))
        if direct is not None:
            return _rows_from_value(direct)
        tables = _get_field(source, ("mdtables", "tables", "MetadataTables"))
        if tables is not None and tables is not source:
            rows = _table_from_source(tables, table_name)
            if rows:
                return rows
        return []

    if isinstance(source, (list, tuple)):
        return list(source)

    table_name_matches = _as_text(getattr(source, "name", "")) == table_name
    if table_name_matches and hasattr(source, "rows"):
        return _rows_from_value(source)

    net = getattr(source, "net", None)
    if net is not None:
        rows = _table_from_source(net, table_name)
        if rows:
            return rows

    mdtables = _get_field(source, ("mdtables", "MetaDataTables", "tables"))
    if mdtables is not None and mdtables is not source:
        rows = _table_from_source(mdtables, table_name)
        if rows:
            return rows

    direct = _get_field(source, (table_name,))
    if direct is not None:
        return _rows_from_value(direct)

    source_table_name = _as_text(getattr(source, "name", ""))
    if hasattr(source, "rows") and (
        not source_table_name or source_table_name == table_name
    ):
        return _rows_from_value(source)

    return []


def _reference_rid(value: Any) -> Optional[int]:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value > 0 else None

    row_index = _get_field(value, ("row_index", "RowIndex", "rid", "RID", "RowNumber"))
    if row_index is not None and not isinstance(row_index, bool):
        try:
            result = int(row_index)
        except (TypeError, ValueError):
            result = 0
        if result > 0:
            return result

    if isinstance(value, Mapping):
        return None
    try:
        result = int(value)
    except (TypeError, ValueError):
        return None
    return result if result > 0 else None


def _explicit_rid(row: Any) -> Optional[int]:
    token = _get_field(row, _FIELD_ALIASES["token"])
    token_int = _reference_rid(token)
    if token_int is not None and token_int > 0xFFFFFF:
        rid = token_int & 0x00FFFFFF
        if rid > 0:
            return rid

    raw = _get_field(row, _FIELD_ALIASES["rid"])
    rid = _reference_rid(raw)
    if rid is not None:
        return rid
    return None


def _split_namespace_name(text: str, default_namespace: str = "") -> Tuple[str, str]:
    if "." in text:
        namespace, name = text.rsplit(".", 1)
        return namespace, name
    return default_namespace, text


def _named_identity_from_reference(
    ref: Any,
    *,
    module: str,
    default_namespace: str = "",
    trail: Tuple[Any, ...] = (),
) -> Optional[TypeIdentity]:
    if ref is None or isinstance(ref, (int, bool)):
        return None

    if isinstance(ref, str):
        path = ref.strip()
        if not path:
            return None
        separator = "/" if "/" in path else ("+" if "+" in path else None)
        if separator is not None:
            segments = path.split(separator)
            namespace, first_name = _split_namespace_name(segments[0].strip(), default_namespace)
            identity: Optional[TypeIdentity] = TypeIdentity(
                name=first_name,
                namespace=namespace,
                module=module,
                parent=None,
            )
            for segment in segments[1:]:
                identity = TypeIdentity(
                    name=segment.strip(),
                    namespace="",
                    module=module,
                    parent=identity,
                )
            return identity

        namespace, name = _split_namespace_name(path, default_namespace)
        return TypeIdentity(name=name, namespace=namespace, module=module, parent=None)

    if id(ref) in trail:
        return None

    name = _as_text(_get_field(ref, _FIELD_ALIASES["name"]))
    if not name:
        return None
    namespace = _as_text(_get_field(ref, _FIELD_ALIASES["namespace"])) or default_namespace
    parent_ref = _get_field(ref, _FIELD_ALIASES["parent_ref"])
    parent_identity = None
    if parent_ref is not None:
        parent_identity = _named_identity_from_reference(
            parent_ref,
            module=module,
            default_namespace=namespace,
            trail=trail + (id(ref),),
        )
    return TypeIdentity(name=name, namespace=namespace, module=module, parent=parent_identity)


@dataclass(frozen=True)
class TypeIdentity:
    """Parent-qualified identity of a TypeDef row."""

    name: str
    namespace: str = ""
    module: str = ""
    parent: Optional["TypeIdentity"] = None

    @property
    def is_nested(self) -> bool:
        return self.parent is not None

    @property
    def parent_key(self) -> Tuple[Any, ...]:
        return self.parent.key if self.parent is not None else ()

    @property
    def key(self) -> Tuple[str, str, Tuple[Any, ...], str]:
        return (self.module or "", self.namespace or "", self.parent_key, self.name or "")

    @property
    def full_name(self) -> str:
        if self.parent is not None:
            return self.parent.full_name + "/" + self.name
        if self.namespace:
            return self.namespace + "." + self.name
        return self.name

    @property
    def qualified_name(self) -> str:
        return self.full_name

    def __str__(self) -> str:
        return self.full_name


@dataclass
class TypeObservation:
    """One TypeDef row in one metadata table export."""

    identity: TypeIdentity
    rid: int
    position: int
    table_name: str = "TypeDef"
    row: Any = None
    warnings: Tuple[str, ...] = ()

    @property
    def name(self) -> str:
        return self.identity.name

    @property
    def simple_name(self) -> str:
        return self.identity.name

    @property
    def namespace(self) -> str:
        return self.identity.namespace

    @property
    def module(self) -> str:
        return self.identity.module

    @property
    def parent(self) -> Optional[TypeIdentity]:
        return self.identity.parent

    @property
    def row_index(self) -> int:
        """ECMA metadata row indices/RIDs are one-based."""
        return self.rid

    @property
    def row_number(self) -> int:
        return self.rid


@dataclass
class RowMatch(VerdictMixin):
    identity: TypeIdentity
    old: TypeObservation
    new: TypeObservation
    status: str
    preservation: str

    @property
    def name(self) -> str:
        return self.identity.name

    @property
    def simple_name(self) -> str:
        return self.identity.name

    @property
    def old_observation(self) -> TypeObservation:
        return self.old

    @property
    def new_observation(self) -> TypeObservation:
        return self.new

    @property
    def old_row(self) -> Any:
        return self.old.row

    @property
    def new_row(self) -> Any:
        return self.new.row

    @property
    def old_rid(self) -> int:
        return self.old.rid

    @property
    def new_rid(self) -> int:
        return self.new.rid

    @property
    def old_index(self) -> int:
        return self.old.rid

    @property
    def old_row_number(self) -> int:
        return self.old.rid

    @property
    def new_index(self) -> int:
        return self.new.rid

    @property
    def new_row_number(self) -> int:
        return self.new.rid

    @property
    def old_position(self) -> int:
        return self.old.position

    @property
    def new_position(self) -> int:
        return self.new.position

    @property
    def moved(self) -> bool:
        return self.old.rid != self.new.rid

    @property
    def row_changed(self) -> bool:
        return self.moved

    @property
    def preserved(self) -> bool:
        return True

    @property
    def identity_preserved(self) -> bool:
        return True

    @property
    def can_carry_observations(self) -> bool:
        return True

    @property
    def requires_review(self) -> bool:
        return False

    @property
    def conclusion(self) -> str:
        if self.moved:
            return (
                f"preserved: {self.identity.full_name} moved from TypeDef RID "
                f"{self.old.rid} to {self.new.rid}; update the observed row number"
            )
        return f"preserved in place: {self.identity.full_name} remains at RID {self.old.rid}"


@dataclass
class NewDefinition(VerdictMixin):
    identity: TypeIdentity
    new: TypeObservation
    status: str = NEW_DEFINITION
    preservation: str = VERDICT_NEW

    @property
    def name(self) -> str:
        return self.identity.name

    @property
    def simple_name(self) -> str:
        return self.identity.name

    @property
    def new_observation(self) -> TypeObservation:
        return self.new

    @property
    def new_row(self) -> Any:
        return self.new.row

    @property
    def rid(self) -> int:
        return self.new.rid

    @property
    def new_rid(self) -> int:
        return self.new.rid

    @property
    def new_index(self) -> int:
        return self.new.rid

    @property
    def new_row_number(self) -> int:
        return self.new.rid

    @property
    def preserved(self) -> bool:
        return False

    @property
    def can_carry_observations(self) -> bool:
        return False

    @property
    def identity_preserved(self) -> bool:
        return False

    @property
    def requires_review(self) -> bool:
        return False

    @property
    def conclusion(self) -> str:
        return f"new definition: {self.identity.full_name} at TypeDef RID {self.new.rid}"


@dataclass
class RemovedDefinition(VerdictMixin):
    identity: TypeIdentity
    old: TypeObservation
    status: str = REMOVED
    preservation: str = VERDICT_NOT_PRESERVED

    @property
    def name(self) -> str:
        return self.identity.name

    @property
    def simple_name(self) -> str:
        return self.identity.name

    @property
    def old_observation(self) -> TypeObservation:
        return self.old

    @property
    def old_row(self) -> Any:
        return self.old.row

    @property
    def old_rid(self) -> int:
        return self.old.rid

    @property
    def old_index(self) -> int:
        return self.old.rid

    @property
    def old_row_number(self) -> int:
        return self.old.rid

    @property
    def preserved(self) -> bool:
        return False

    @property
    def can_carry_observations(self) -> bool:
        return False

    @property
    def identity_preserved(self) -> bool:
        return False

    @property
    def requires_review(self) -> bool:
        return True

    @property
    def conclusion(self) -> str:
        return f"not preserved: {self.identity.full_name} disappeared from the new table"


@dataclass
class AmbiguousMatch(VerdictMixin):
    name: str
    old: List[TypeObservation] = field(default_factory=list)
    new: List[TypeObservation] = field(default_factory=list)
    identity: Optional[TypeIdentity] = None
    identities: List[TypeIdentity] = field(default_factory=list)
    reason: str = "duplicate_name"
    status: str = AMBIGUOUS
    preservation: str = VERDICT_AMBIGUOUS

    @property
    def old_observations(self) -> List[TypeObservation]:
        return self.old

    @property
    def new_observations(self) -> List[TypeObservation]:
        return self.new

    @property
    def candidates(self) -> List[TypeObservation]:
        return list(self.old) + list(self.new)

    @property
    def old_rids(self) -> List[int]:
        return [item.rid for item in self.old]

    @property
    def new_rids(self) -> List[int]:
        return [item.rid for item in self.new]

    @property
    def preserved(self) -> bool:
        return False

    @property
    def can_carry_observations(self) -> bool:
        return False

    @property
    def identity_preserved(self) -> Optional[bool]:
        return None

    @property
    def requires_review(self) -> bool:
        return True

    @property
    def conclusion(self) -> str:
        return (
            f"ambiguous: {self.name} cannot be matched safely "
            f"(old RIDs {self.old_rids}, new RIDs {self.new_rids})"
        )


@dataclass
class ParentChange(VerdictMixin):
    name: str
    old: TypeObservation
    new: TypeObservation
    status: str = PARENT_CHANGED
    preservation: str = VERDICT_NOT_PRESERVED
    probable: bool = True

    @property
    def old_observation(self) -> TypeObservation:
        return self.old

    @property
    def new_observation(self) -> TypeObservation:
        return self.new

    @property
    def old_identity(self) -> TypeIdentity:
        return self.old.identity

    @property
    def new_identity(self) -> TypeIdentity:
        return self.new.identity

    @property
    def old_rid(self) -> int:
        return self.old.rid

    @property
    def new_rid(self) -> int:
        return self.new.rid

    @property
    def old_index(self) -> int:
        return self.old.rid

    @property
    def old_row_number(self) -> int:
        return self.old.rid

    @property
    def new_index(self) -> int:
        return self.new.rid

    @property
    def new_row_number(self) -> int:
        return self.new.rid

    @property
    def preserved(self) -> bool:
        return False

    @property
    def can_carry_observations(self) -> bool:
        return False

    @property
    def identity_preserved(self) -> bool:
        return False

    @property
    def requires_review(self) -> bool:
        return True

    @property
    def conclusion(self) -> str:
        return (
            "not preserved by identity: parent scope for "
            f"{self.name} changed from {self.old.identity.full_name} to "
            f"{self.new.identity.full_name}"
        )


@dataclass
class ComparisonReport:
    old_module: str = ""
    new_module: str = ""
    matches: List[RowMatch] = field(default_factory=list)
    added_identities: List[NewDefinition] = field(default_factory=list)
    removed_identities: List[RemovedDefinition] = field(default_factory=list)
    ambiguous_identities: List[AmbiguousMatch] = field(default_factory=list)
    parent_changes: List[ParentChange] = field(default_factory=list)
    name_ambiguities: List[AmbiguousMatch] = field(default_factory=list)

    @property
    def unchanged(self) -> List[RowMatch]:
        return [item for item in self.matches if not item.moved]


    @property
    def moved(self) -> List[RowMatch]:
        return [item for item in self.matches if item.moved]

    @property
    def relocated(self) -> List[RowMatch]:
        return self.moved

    @property
    def moved_observations(self) -> List[RowMatch]:
        return self.moved

    @property
    def relocated_observations(self) -> List[RowMatch]:
        return self.moved

    @property
    def moved_definitions(self) -> List[RowMatch]:
        return self.moved

    @property
    def new_definitions(self) -> List[NewDefinition]:
        return self.added_identities

    @property
    def new(self) -> List[NewDefinition]:
        return self.added_identities

    @property
    def removed(self) -> List[RemovedDefinition]:
        return self.removed_identities

    @property
    def missing(self) -> List[RemovedDefinition]:
        return self.removed_identities

    @property
    def ambiguous(self) -> List[AmbiguousMatch]:
        return self.ambiguous_identities + self.name_ambiguities

    @property
    def ambiguous_matches(self) -> List[AmbiguousMatch]:
        return self.ambiguous

    @property
    def ambiguous_names(self) -> List[AmbiguousMatch]:
        return self.name_ambiguities

    @property
    def parent_changed(self) -> List[ParentChange]:
        return self.parent_changes

    @property
    def relocations(self) -> Dict[int, int]:
        return {item.old_rid: item.new_rid for item in self.matches if item.moved}

    @property
    def row_map(self) -> Dict[int, int]:
        return {item.old_rid: item.new_rid for item in self.matches}

    @property
    def mapping(self) -> Dict[int, int]:
        return self.row_map

    @property
    def old_to_new(self) -> Dict[int, int]:
        return self.row_map

    @property
    def rid_map(self) -> Dict[int, int]:
        return self.row_map

    @property
    def decisions(self) -> List[Union[RowMatch, NewDefinition, RemovedDefinition, AmbiguousMatch, ParentChange]]:
        return [
            *self.matches,
            *self.added_identities,
            *self.removed_identities,
            *self.ambiguous,
            *self.parent_changes,
        ]

    @property
    def manifest(self) -> List[Dict[str, Any]]:
        return [self._decision_dict(item) for item in self._triaged_decisions()]

    @property
    def checklist(self) -> List[Dict[str, Any]]:
        return self.manifest

    @property
    def preservation_report(self) -> List[Dict[str, Any]]:
        return self.manifest

    @property
    def unresolved(self) -> List[AmbiguousMatch]:
        return self.ambiguous

    @property
    def ambiguous_definitions(self) -> List[AmbiguousMatch]:
        return self.ambiguous_identities

    @property
    def preservation_conclusions(self) -> List[str]:
        return [item["conclusion"] for item in self.manifest]

    def __getitem__(self, key: str) -> Any:
        aliases = {
            "new_definitions": "new_definitions",
            "new": "new_definitions",
            "moved": "moved",
            "moved_observations": "moved_observations",
            "relocated": "relocated",
            "ambiguous": "ambiguous",
            "ambiguous_names": "ambiguous_names",
            "parent_changes": "parent_changes",
            "removed": "removed",
            "missing": "missing",
            "manifest": "manifest",
            "checklist": "checklist",
            "summary": "summary",
            "relocations": "relocations",
            "row_map": "row_map",
        }
        attr = aliases.get(key, key)
        if not hasattr(self, attr):
            raise KeyError(key)
        return getattr(self, attr)

    def _triaged_decisions(self) -> List[Any]:
        parent_new_ids = {id(change.new) for change in self.parent_changes}
        parent_old_ids = {id(change.old) for change in self.parent_changes}
        name_ambiguous_new_ids = {
            id(observation)
            for ambiguity in self.name_ambiguities
            for observation in ambiguity.new
        }
        name_ambiguous_old_ids = {
            id(observation)
            for ambiguity in self.name_ambiguities
            for observation in ambiguity.old
        }

        decisions: List[Any] = [*self.matches, *self.ambiguous_identities]
        decisions.extend(
            item
            for item in self.added_identities
            if id(item.new) not in parent_new_ids
            and id(item.new) not in name_ambiguous_new_ids
        )
        decisions.extend(self.parent_changes)
        decisions.extend(self.name_ambiguities)
        decisions.extend(
            item
            for item in self.removed_identities
            if id(item.old) not in name_ambiguous_old_ids and id(item.old) not in parent_old_ids
        )
        return decisions

    @staticmethod
    def _decision_dict(item: Any) -> Dict[str, Any]:
        if isinstance(item, RowMatch):
            kind = "moved" if item.moved else "unchanged"
            return {
                "kind": kind,
                "status": item.status,
                "preservation": item.preservation,
                "preserved": item.preserved,
                "identity": item.identity.full_name,
                "old_rid": item.old_rid,
                "new_rid": item.new_rid,
                "old_index": item.old_rid,
                "new_index": item.new_rid,
                "conclusion": item.conclusion,
            }
        if isinstance(item, NewDefinition):
            return {
                "kind": "new_definition",
                "status": item.status,
                "preservation": item.preservation,
                "preserved": False,
                "identity": item.identity.full_name,
                "new_rid": item.new_rid,
                "new_index": item.new_rid,
                "conclusion": item.conclusion,
            }
        if isinstance(item, RemovedDefinition):
            return {
                "kind": "removed",
                "status": item.status,
                "preservation": item.preservation,
                "preserved": False,
                "identity": item.identity.full_name,
                "old_rid": item.old_rid,
                "old_index": item.old_rid,
                "conclusion": item.conclusion,
            }
        if isinstance(item, ParentChange):
            return {
                "kind": "parent_changed",
                "status": item.status,
                "preservation": item.preservation,
                "preserved": False,
                "name": item.name,
                "old_identity": item.old_identity.full_name,
                "new_identity": item.new_identity.full_name,
                "old_rid": item.old_rid,
                "new_rid": item.new_rid,
                "old_index": item.old_rid,
                "new_index": item.new_rid,
                "conclusion": item.conclusion,
            }
        return {
            "kind": "ambiguous",
            "status": item.status,
            "preservation": item.preservation,
            "preserved": False,
            "name": item.name,
            "identity": item.identity.full_name if item.identity is not None else None,
            "identities": [identity.full_name for identity in item.identities],
            "old_rids": item.old_rids,
            "new_rids": item.new_rids,
            "conclusion": item.conclusion,
        }

    def to_dicts(self) -> Dict[str, Any]:
        return {
            "old_module": self.old_module,
            "new_module": self.new_module,
            "summary": self.summary,
            "manifest": self.manifest,
            "matches": [self._decision_dict(item) for item in self.matches],
            "moved": [self._decision_dict(item) for item in self.moved],
            "unchanged": [self._decision_dict(item) for item in self.unchanged],
            "new_definitions": [self._decision_dict(item) for item in self.new_definitions],
            "removed": [self._decision_dict(item) for item in self.removed],
            "ambiguous": [self._decision_dict(item) for item in self.ambiguous],
            "parent_changes": [self._decision_dict(item) for item in self.parent_changes],
            "relocations": self.relocations,
            "row_map": self.row_map,
        }

    @property
    def summary(self) -> Dict[str, int]:
        return {
            "matches": len(self.matches),
            "unchanged": len(self.unchanged),
            "moved": len(self.moved),
            "new_definitions": len(self.added_identities),
            "removed": len(self.removed_identities),
            "ambiguous": len(self.ambiguous),
            "parent_changes": len(self.parent_changes),
            "auto_preservable_observations": len(self.matches),
            "requires_review": len(self.ambiguous) + len(self.parent_changes) + len(self.removed_identities),
        }

    def render_text(self) -> str:
        lines = ["TypeDef archive cross-reference"]
        if self.old_module or self.new_module:
            lines.append(f"module: {self.old_module or '?'} -> {self.new_module or '?'}")
        for item in self.manifest:
            lines.append("- [{}] {}".format(item["preservation"], item["conclusion"]))
        return "\n".join(lines)

    def __str__(self) -> str:
        return self.render_text()


@dataclass
class _RawTypeRow:
    position: int
    rid: int
    row: Any
    name: str
    namespace: str
    module: str
    parent_ref: Any = None


class TypeIndex:
    """Parent- and module-qualified index of TypeDef rows."""

    def __init__(self, observations: Sequence[TypeObservation], module_name: str = ""):
        self.module_name = module_name
        self.observations: List[TypeObservation] = list(observations)
        self.by_identity: DefaultDict[TypeIdentity, List[TypeObservation]] = defaultdict(list)
        self.by_rid: Dict[int, TypeObservation] = {}
        for observation in self.observations:
            self.by_identity[observation.identity].append(observation)
            self.by_rid[observation.rid] = observation

    @classmethod
    def build(
        cls,
        source: Any = None,
        *,
        type_rows: Optional[Sequence[Any]] = None,
        rows: Optional[Sequence[Any]] = None,
        nested_rows: Any = None,
        nested: Any = None,
        parent_map: Optional[Mapping[int, int]] = None,
        module_name: Optional[str] = None,
        table_name: str = "TypeDef",
    ) -> "TypeIndex":
        resolved_rows = type_rows if type_rows is not None else rows
        if resolved_rows is not None:
            raw_rows = list(resolved_rows)
        else:
            raw_rows = _table_from_source(source, table_name)

        if module_name is None:
            module_name = cls._module_name_from_source(source)
        module_name = _as_text(module_name)

        raw_by_rid: Dict[int, _RawTypeRow] = {}
        raw_rows_list: List[_RawTypeRow] = []
        for position, row in enumerate(raw_rows):
            rid = _explicit_rid(row)
            if rid is None:
                rid = position + 1
            raw = _RawTypeRow(
                position=position,
                rid=rid,
                row=row,
                name=_as_text(_get_field(row, _FIELD_ALIASES["name"])),
                namespace=_as_text(_get_field(row, _FIELD_ALIASES["namespace"])),
                module=_as_text(_get_field(row, _FIELD_ALIASES["module"])) or module_name,
                parent_ref=_get_field(row, _FIELD_ALIASES["parent_ref"]),
            )
            raw_rows_list.append(raw)
            raw_by_rid[rid] = raw

        child_to_parent: Dict[int, int] = {}
        nested_source = nested_rows if nested_rows is not None else nested
        if nested_source is None and source is not None and resolved_rows is None:
            nested_source = source
        for nested_row in _table_from_source(nested_source, "NestedClass") if nested_source is not None else []:
            child_rid = _reference_rid(_get_field(nested_row, _FIELD_ALIASES["nested_ref"]))
            parent_rid = _reference_rid(_get_field(nested_row, _FIELD_ALIASES["enclosing_ref"]))
            if child_rid is not None and parent_rid is not None:
                child_to_parent[child_rid] = parent_rid
        if parent_map:
            child_to_parent.update({int(child): int(parent) for child, parent in parent_map.items()})

        raw_by_object_id = {id(raw.row): rid for rid, raw in raw_by_rid.items()}
        identity_cache: Dict[int, TypeIdentity] = {}
        warning_cache: Dict[int, Tuple[str, ...]] = {}

        def resolve_reference_rid(ref: Any) -> Optional[int]:
            rid = _reference_rid(ref)
            if rid is not None and rid in raw_by_rid:
                return rid
            if id(ref) in raw_by_object_id:
                return raw_by_object_id[id(ref)]
            if isinstance(ref, str):
                matches = [candidate.rid for candidate in raw_rows_list if candidate.name == ref]
                if len(matches) == 1:
                    return matches[0]
            return None

        def identity_for(rid: int, trail: Tuple[int, ...] = ()) -> TypeIdentity:
            if rid in identity_cache:
                return identity_cache[rid]
            raw = raw_by_rid[rid]
            warnings: List[str] = []
            parent_identity: Optional[TypeIdentity] = None
            named_parent_identity: Optional[TypeIdentity] = None

            parent_rid = child_to_parent.get(rid)
            if parent_rid is None and raw.parent_ref is not None:
                parent_rid = resolve_reference_rid(raw.parent_ref)
                if parent_rid is None:
                    named_parent_identity = _named_identity_from_reference(
                        raw.parent_ref,
                        module=raw.module,
                        default_namespace=raw.namespace,
                    )
                    if named_parent_identity is None:
                        warnings.append("unresolved_parent_reference")

            if parent_rid is not None:
                if parent_rid == rid or parent_rid in trail:
                    warnings.append("nested_parent_cycle")
                else:
                    parent_identity = identity_for(parent_rid, trail + (rid,))
            elif named_parent_identity is not None:
                parent_identity = named_parent_identity

            identity = TypeIdentity(
                name=raw.name,
                namespace=raw.namespace,
                module=raw.module,
                parent=parent_identity,
            )
            identity_cache[rid] = identity
            warning_cache[rid] = tuple(warnings)
            return identity

        observations: List[TypeObservation] = []
        for raw in raw_rows_list:
            identity = identity_for(raw.rid)
            observations.append(
                TypeObservation(
                    identity=identity,
                    rid=raw.rid,
                    position=raw.position,
                    table_name=table_name,
                    row=raw.row,
                    warnings=warning_cache.get(raw.rid, ()),
                )
            )

        return cls(observations, module_name=module_name)

    @staticmethod
    def _module_name_from_source(source: Any) -> str:
        if isinstance(source, (list, tuple)):
            return ""
        module_rows = _table_from_source(source, "Module")
        if not module_rows:
            return ""
        name = _get_field(module_rows[0], ("Name", "name", "ModuleName", "module_name"))
        return _as_text(name)

    def compare(self, new: Union["TypeIndex", Any], *args: Any, **kwargs: Any) -> ComparisonReport:
        if not isinstance(new, TypeIndex):
            new_index = TypeIndex.build(new, *args, **kwargs)
        else:
            new_index = new
        return compare_indexes(self, new_index)

    def __len__(self) -> int:
        return len(self.observations)


def compare_indexes(old: TypeIndex, new: TypeIndex) -> ComparisonReport:
    report = ComparisonReport(old_module=old.module_name, new_module=new.module_name)
    processed_old = set()
    processed_new = set()

    old_groups = old.by_identity
    new_groups = new.by_identity

    for identity in sorted(set(old_groups) & set(new_groups), key=lambda item: item.full_name):
        old_items = sorted(old_groups[identity], key=lambda item: item.rid)
        new_items = sorted(new_groups[identity], key=lambda item: item.rid)
        if len(old_items) == 1 and len(new_items) == 1:
            old_item = old_items[0]
            new_item = new_items[0]
            status = UNCHANGED if old_item.rid == new_item.rid else MOVED
            preservation = (
                VERDICT_PRESERVED_IN_PLACE if status == UNCHANGED else VERDICT_RELOCATED
            )
            report.matches.append(
                RowMatch(
                    identity=identity,
                    old=old_item,
                    new=new_item,
                    status=status,
                    preservation=preservation,
                )
            )
            processed_old.add(id(old_item))
            processed_new.add(id(new_item))
        else:
            ambiguity = AmbiguousMatch(
                name=identity.full_name,
                old=old_items,
                new=new_items,
                identity=identity,
                identities=[identity],
                reason="duplicate_parent_qualified_name",
            )
            report.ambiguous_identities.append(ambiguity)
            processed_old.update(id(item) for item in old_items)
            processed_new.update(id(item) for item in new_items)

    residual_old: List[TypeObservation] = []
    residual_new: List[TypeObservation] = []

    for identity, items in old_groups.items():
        if identity in new_groups:
            continue
        if len(items) > 1:
            report.ambiguous_identities.append(
                AmbiguousMatch(
                    name=identity.full_name,
                    old=sorted(items, key=lambda item: item.rid),
                    new=[],
                    identity=identity,
                    identities=[identity],
                    reason="duplicate_old_identity",
                )
            )
            processed_old.update(id(item) for item in items)
        else:
            residual_old.append(items[0])

    for identity, items in new_groups.items():
        if identity in old_groups:
            continue
        if len(items) > 1:
            report.ambiguous_identities.append(
                AmbiguousMatch(
                    name=identity.full_name,
                    old=[],
                    new=sorted(items, key=lambda item: item.rid),
                    identity=identity,
                    identities=[identity],
                    reason="duplicate_new_identity",
                )
            )
            processed_new.update(id(item) for item in items)
        else:
            residual_new.append(items[0])

    residual_old = [item for item in residual_old if id(item) not in processed_old]
    residual_new = [item for item in residual_new if id(item) not in processed_new]
    old_by_simple_name: DefaultDict[str, List[TypeObservation]] = DefaultDict(list)
    new_by_simple_name: DefaultDict[str, List[TypeObservation]] = DefaultDict(list)
    for item in residual_old:
        old_by_simple_name[item.name].append(item)
    for item in residual_new:
        new_by_simple_name[item.name].append(item)

    for name in sorted(set(old_by_simple_name) | set(new_by_simple_name)):
        old_items = sorted(old_by_simple_name.get(name, []), key=lambda item: item.rid)
        new_items = sorted(new_by_simple_name.get(name, []), key=lambda item: item.rid)

        if len(old_items) == 1 and len(new_items) == 1:
            old_item = old_items[0]
            new_item = new_items[0]
            status = PARENT_CHANGED if old_item.identity.parent != new_item.identity.parent else SCOPE_CHANGED
            report.parent_changes.append(
                ParentChange(name=name, old=old_item, new=new_item, status=status)
            )
            report.added_identities.append(
                NewDefinition(identity=new_item.identity, new=new_item)
            )
            report.removed_identities.append(
                RemovedDefinition(identity=old_item.identity, old=old_item)
            )
        elif old_items and new_items:
            identities = sorted(
                {item.identity for item in old_items + new_items},
                key=lambda item: item.full_name,
            )
            report.name_ambiguities.append(
                AmbiguousMatch(
                    name=name,
                    old=old_items,
                    new=new_items,
                    identities=identities,
                    reason="same_simple_name_with_unresolved_parent_move",
                )
            )
        elif new_items:
            for item in new_items:
                report.added_identities.append(NewDefinition(identity=item.identity, new=item))
        else:
            for item in old_items:
                report.removed_identities.append(
                    RemovedDefinition(identity=item.identity, old=item)
                )

    report.matches.sort(key=lambda item: item.old_rid)
    report.added_identities.sort(key=lambda item: item.new_rid)
    report.removed_identities.sort(key=lambda item: item.old_rid)
    report.parent_changes.sort(key=lambda item: item.old_rid)
    report.ambiguous_identities.sort(key=lambda item: item.name)
    report.name_ambiguities.sort(key=lambda item: item.name)
    return report


def compare_type_tables(
    old: Any,
    new: Any,
    nested_old: Any = None,
    nested_new: Any = None,
    *,
    old_nested: Any = None,
    new_nested: Any = None,
    parent_map_old: Optional[Mapping[int, int]] = None,
    parent_map_new: Optional[Mapping[int, int]] = None,
    old_module_name: Optional[str] = None,
    new_module_name: Optional[str] = None,
    module_name: Optional[str] = None,
) -> ComparisonReport:
    """Build two :class:`TypeIndex` objects and compare them."""

    if isinstance(old, TypeIndex):
        old_index = old
    else:
        old_index = TypeIndex.build(
            old,
            nested_rows=nested_old if nested_old is not None else old_nested,
            parent_map=parent_map_old,
            module_name=old_module_name if old_module_name is not None else module_name,
        )
    if isinstance(new, TypeIndex):
        new_index = new
    else:
        new_index = TypeIndex.build(
            new,
            nested_rows=nested_new if nested_new is not None else new_nested,
            parent_map=parent_map_new,
            module_name=new_module_name if new_module_name is not None else module_name,
        )
    return compare_indexes(old_index, new_index)


build_type_index = TypeIndex.build
build_cross_reference = compare_type_tables
compare_metadata = compare_type_tables
compare_assemblies = compare_type_tables
compare_metadata_tables = compare_type_tables
compare_typedef_tables = compare_type_tables
compare = compare_type_tables
build_comparison_index = TypeIndex.build
build_metadata_index = TypeIndex.build
build_typedef_index = TypeIndex.build
MetadataIndex = TypeIndex
ComparisonIndex = TypeIndex
CrossReferenceIndex = TypeIndex
MetadataComparison = ComparisonReport
CrossReferenceReport = ComparisonReport


def build_preservation_manifest(*args: Any, **kwargs: Any) -> List[Dict[str, Any]]:
    return compare_type_tables(*args, **kwargs).manifest


build_checklist = build_preservation_manifest


__all__ = [
    "AmbiguousMatch",
    "ComparisonReport",
    "ComparisonIndex",
    "CrossReferenceIndex",
    "CrossReferenceReport",
    "NewDefinition",
    "MetadataComparison",
    "MetadataIndex",
    "ParentChange",
    "RemovedDefinition",
    "RowMatch",
    "TypeIdentity",
    "TypeIndex",
    "TypeObservation",
    "build_cross_reference",
    "build_checklist",
    "build_comparison_index",
    "build_metadata_index",
    "build_preservation_manifest",
    "build_type_index",
    "build_typedef_index",
    "compare",
    "compare_assemblies",
    "compare_indexes",
    "compare_metadata",
    "compare_metadata_tables",
    "compare_type_tables",
    "compare_typedef_tables",
]
