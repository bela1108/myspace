# -*- coding: utf-8 -*-
"""
Restricted forensic views of .NET metadata.

An auditor may only release a small set of metadata rows for external
review.  Exporting whole metadata tables would leak the heap text of
unrelated rows, so this module builds a *restricted view* instead:

* starting from the rows the caller is licensed to disclose, necessary
  table and heap references are traced;
* each field is disclosed according to policy: published directly,
  reduced to a summary (digest and length), or left blank;
* when a licensed row and a quarantined row share source material
  (e.g. the same #Strings heap entry), the view still records where the
  original material lives in the file, but the exported output never
  contains the quarantined row or context borrowed from it;
* an external reviewer can import the restricted view and read the
  authorized field values together with the reason for any missing
  evidence.
"""

import enum
import json
import hashlib
from typing import Any, Dict, List, Tuple, Union, Iterable, Optional

from . import base, enums


FORMAT_NAME = "dnfile.restricted-view"
FORMAT_VERSION = 1

# reasons for missing (or partial) evidence
REASON_NOT_APPROVED = "field not approved for disclosure"
REASON_SUMMARY_ONLY = "field approved as summary only"
REASON_REF_OUT_OF_SCOPE = "referenced row is outside the approved scope"
REASON_NO_DATA = "no data available in source file"
REASON_ROW_MISSING = "row could not be parsed from source file"


class Disclosure(enum.Enum):
    """
    Per-field disclosure level decided by the review policy.
    """

    # the field value may be published directly
    PUBLIC = "public"
    # only a summary (digest and length) of the field may be published
    SUMMARY = "summary"
    # the field must be left blank in the external output
    REDACTED = "redacted"


class FieldRule:
    """
    A policy rule for a single field: how much may be disclosed, and
    the reason recorded when the full value is withheld.
    """

    def __init__(self, disclosure: Disclosure, reason: str = ""):
        self.disclosure = disclosure
        self.reason = reason

    def __repr__(self):
        return f"FieldRule({self.disclosure!r}, reason={self.reason!r})"


class ViewPolicy:
    """
    The approval scope for one restricted view.

    allowed_rows      mapping of metadata table name to the 1-based row
                      indices (rids) the caller is licensed to disclose.
    field_rules       mapping of (table_name, field_name) or
                      (None, field_name) to a Disclosure or FieldRule.
                      Rules keyed with a table name take precedence over
                      table-independent rules for the same field.
    default           disclosure level for fields without an explicit rule.
    default_reason    reason recorded for fields withheld by default.
    """

    def __init__(
        self,
        allowed_rows: Dict[str, Iterable[int]],
        field_rules: Optional[Dict[Tuple[Optional[str], str], Union[Disclosure, FieldRule]]] = None,
        default: Disclosure = Disclosure.REDACTED,
        default_reason: str = REASON_NOT_APPROVED,
    ):
        self.allowed_rows: Dict[str, List[int]] = {
            table: sorted(set(int(rid) for rid in rids)) for table, rids in allowed_rows.items()
        }
        self.default = default
        self.default_reason = default_reason
        self.field_rules: Dict[Tuple[Optional[str], str], FieldRule] = {}
        for key, rule in (field_rules or {}).items():
            table_name, field_name = key
            if not isinstance(rule, FieldRule):
                rule = FieldRule(rule)
            self.field_rules[(table_name, field_name)] = rule

    def is_row_allowed(self, table_name: str, rid: int) -> bool:
        return rid in self.allowed_rows.get(table_name, ())

    def rule_for(self, table_name: str, field_name: str) -> FieldRule:
        rule = self.field_rules.get((table_name, field_name))
        if rule is None:
            rule = self.field_rules.get((None, field_name))
        if rule is None:
            rule = FieldRule(self.default, self.default_reason)
        if not rule.reason:
            if rule.disclosure is Disclosure.SUMMARY:
                rule = FieldRule(rule.disclosure, REASON_SUMMARY_ONLY)
            elif rule.disclosure is Disclosure.REDACTED:
                rule = FieldRule(rule.disclosure, self.default_reason)
        return rule


def _struct_field_bytes(row: "base.MDTableRow", struct_name: str) -> bytes:
    """
    Return the raw bytes of a single struct field within the row data,
    or b"" if they cannot be determined.
    """
    struct = row.struct
    offsets = getattr(struct, "__field_offsets__", None)
    if not offsets or struct_name not in offsets or not row._data:
        return b""
    ordered = sorted(offsets.items(), key=lambda kv: kv[1])
    start = offsets[struct_name]
    end = len(row._data)
    for _, offset in ordered:
        if offset > start:
            end = offset
            break
    return row._data[start:end]


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json_value(value: Any) -> Any:
    """
    Convert a parsed row attribute into a JSON-safe value.
    """
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, enums.ClrFlags):
        return {"flags": [name for name, enabled in value if enabled]}
    if isinstance(value, enum.Enum):
        return {"raw": int(value), "display": str(value)}
    if isinstance(value, base.HeapItem):
        return _json_value(value.value)
    return str(value)


class FieldView:
    """
    One field of a restricted row, as seen by the external reviewer.
    """

    def __init__(
        self,
        name: str,
        disclosure: Disclosure,
        value: Any = None,
        reason: str = "",
        source: Optional[Dict[str, Any]] = None,
        summary: Optional[Dict[str, Any]] = None,
        references: Optional[List[Dict[str, Any]]] = None,
    ):
        self.name = name
        self.disclosure = disclosure
        self.value = value
        # reason the full evidence is missing (empty when fully disclosed)
        self.reason = reason
        # location of the original material in the source file
        self.source = source
        self.summary = summary
        self.references = references

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "name": self.name,
            "disclosure": self.disclosure.value,
            "value": self.value,
            "reason": self.reason,
        }
        if self.source is not None:
            d["source"] = self.source
        if self.summary is not None:
            d["summary"] = self.summary
        if self.references is not None:
            d["references"] = self.references
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "FieldView":
        return cls(
            name=d["name"],
            disclosure=Disclosure(d["disclosure"]),
            value=d.get("value"),
            reason=d.get("reason", ""),
            source=d.get("source"),
            summary=d.get("summary"),
            references=d.get("references"),
        )


class RowView:
    """
    One licensed row within a restricted view.
    """

    def __init__(
        self,
        table: str,
        rid: int,
        file_offset: Optional[int] = None,
        fields: Optional[List[FieldView]] = None,
        error: str = "",
    ):
        self.table = table
        self.rid = rid
        # file offset of the row in the original file
        self.file_offset = file_offset
        self.fields: List[FieldView] = fields or []
        self.error = error

    def get_field(self, name: str) -> Optional[FieldView]:
        for field in self.fields:
            if field.name == name:
                return field
        return None

    def authorized_fields(self) -> Dict[str, Any]:
        """
        Values the external reviewer is authorized to see.
        """
        return {f.name: f.value for f in self.fields if f.disclosure is Disclosure.PUBLIC}

    def missing_evidence(self) -> Dict[str, str]:
        """
        Fields that are not fully disclosed, mapped to the reason why.
        """
        return {f.name: f.reason for f in self.fields if f.disclosure is not Disclosure.PUBLIC}

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "table": self.table,
            "rid": self.rid,
            "file_offset": self.file_offset,
            "fields": [f.to_dict() for f in self.fields],
        }
        if self.error:
            d["error"] = self.error
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "RowView":
        return cls(
            table=d["table"],
            rid=d["rid"],
            file_offset=d.get("file_offset"),
            fields=[FieldView.from_dict(f) for f in d.get("fields", [])],
            error=d.get("error", ""),
        )


class RestrictedView:
    """
    A restricted forensic view of a parsed .NET file.

    Built on the auditor side with :meth:`from_dnfile` and a
    :class:`ViewPolicy`, serialized with :meth:`to_json`, and imported
    by the external reviewer with :meth:`from_json`.
    """

    def __init__(
        self,
        rows: Optional[List[RowView]] = None,
        scope: Optional[Dict[str, List[int]]] = None,
        label: str = "",
    ):
        self.rows: List[RowView] = rows or []
        self.scope: Dict[str, List[int]] = scope or {}
        self.label = label

    #
    # reviewer-facing API
    #

    def get_row(self, table: str, rid: int) -> Optional[RowView]:
        for row in self.rows:
            if row.table == table and row.rid == rid:
                return row
        return None

    def missing_evidence(self) -> Dict[str, Dict[str, str]]:
        """
        Reasons for missing evidence, keyed by "Table:rid" then field name.
        """
        result: Dict[str, Dict[str, str]] = {}
        for row in self.rows:
            missing = row.missing_evidence()
            if row.error:
                missing["<row>"] = row.error
            if missing:
                result[f"{row.table}:{row.rid}"] = missing
        return result

    #
    # serialization
    #

    def to_dict(self) -> Dict[str, Any]:
        return {
            "format": FORMAT_NAME,
            "version": FORMAT_VERSION,
            "label": self.label,
            "scope": {"allowed_rows": self.scope},
            "rows": [r.to_dict() for r in self.rows],
        }

    def to_json(self, **kwargs) -> str:
        return json.dumps(self.to_dict(), **kwargs)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "RestrictedView":
        if d.get("format") != FORMAT_NAME:
            raise ValueError(f"not a restricted view: {d.get('format')!r}")
        if d.get("version") != FORMAT_VERSION:
            raise ValueError(f"unsupported restricted view version: {d.get('version')!r}")
        scope = d.get("scope", {}).get("allowed_rows", {})
        return cls(
            rows=[RowView.from_dict(r) for r in d.get("rows", [])],
            scope={table: list(rids) for table, rids in scope.items()},
            label=d.get("label", ""),
        )

    @classmethod
    def from_json(cls, data: Union[str, bytes]) -> "RestrictedView":
        return cls.from_dict(json.loads(data))

    #
    # auditor-side construction
    #

    @classmethod
    def from_dnfile(cls, dn, policy: ViewPolicy, label: str = "") -> "RestrictedView":
        """
        Build a restricted view of the given dnfile.dnPE object,
        tracing table and heap references from the licensed rows only.
        """
        mdtables = dn.net.mdtables
        tables_by_name = {t.name: t for t in mdtables.tables_list}
        rows: List[RowView] = []
        for table_name, rids in sorted(policy.allowed_rows.items()):
            table = tables_by_name.get(table_name)
            for rid in rids:
                row = None
                if table is not None:
                    try:
                        row = table.get_with_row_index(rid)
                    except (IndexError, TypeError):
                        row = None
                if row is None:
                    rows.append(RowView(table_name, rid, error=REASON_ROW_MISSING))
                    continue
                rows.append(_export_row(table_name, rid, row, policy))
        return cls(rows=rows, scope=policy.allowed_rows, label=label)


def _heap_source(heap_name: str, index: Optional[int], item: Optional["base.HeapItem"], heap) -> Dict[str, Any]:
    """
    Locate the original material of a heap reference in the source file.
    """
    source: Dict[str, Any] = {"kind": "heap", "heap": heap_name, "index": index}
    if item is not None:
        source["rva"] = item.rva
        source["size"] = item.raw_size
        file_offset = None
        if heap is not None and item.rva is not None:
            file_offset = heap.get_file_offset(item.rva)
        source["file_offset"] = file_offset
    return source


def _reference_views(value: Any, policy: ViewPolicy) -> List[Dict[str, Any]]:
    """
    Trace table references without disclosing quarantined rows.
    """
    if isinstance(value, base.MDTableIndex):
        indexes = [value]
    elif isinstance(value, (list, tuple)):
        indexes = [v for v in value if isinstance(v, base.MDTableIndex)]
    else:
        indexes = []

    refs: List[Dict[str, Any]] = []
    for index in indexes:
        table_name = index.table.name if index.table is not None else None
        in_scope = table_name is not None and policy.is_row_allowed(table_name, index.row_index)
        ref: Dict[str, Any] = {
            "table": table_name,
            "rid": index.row_index,
            "in_scope": in_scope,
        }
        if not in_scope:
            # the referenced row is quarantined: record the pointer held
            # by the licensed row, but never its content or context.
            ref["reason"] = REASON_REF_OUT_OF_SCOPE
        refs.append(ref)
    return refs


def _export_field(
    row: "base.MDTableRow",
    table_name: str,
    attr_name: str,
    struct_name: str,
    kind: str,
    policy: ViewPolicy,
) -> FieldView:
    rule = policy.rule_for(table_name, attr_name)
    disclosure = rule.disclosure
    reason = rule.reason
    parsed = getattr(row, attr_name, None)

    source: Optional[Dict[str, Any]] = None
    summary: Optional[Dict[str, Any]] = None
    references: Optional[List[Dict[str, Any]]] = None

    if kind in ("strings", "guids", "blobs"):
        heap_name = {"strings": "#Strings", "guids": "#GUID", "blobs": "#Blob"}[kind]
        heap = {"strings": row._strings, "guids": row._guids, "blobs": row._blobs}[kind]
        index = getattr(row.struct, struct_name, None)
        item = parsed if isinstance(parsed, base.HeapItem) else None
        source = _heap_source(heap_name, index, item, heap)
        raw = item.raw_data if item is not None else b""
        value = parsed
    elif kind in ("indexes", "codedindexes", "lists"):
        references = _reference_views(parsed, policy)
        # the raw index held by the licensed row is its own data;
        # the referenced row's content is never resolved into the view.
        value = getattr(row.struct, struct_name, None)
        raw = _struct_field_bytes(row, struct_name)
    else:
        value = parsed
        raw = _struct_field_bytes(row, struct_name)

    if parsed is None and disclosure is Disclosure.PUBLIC:
        # evidence expected but absent from the source file
        return FieldView(attr_name, Disclosure.REDACTED, reason=REASON_NO_DATA,
                         source=source)

    if disclosure is Disclosure.PUBLIC:
        return FieldView(attr_name, disclosure, value=_json_value(value),
                         source=source, references=references)

    if disclosure is Disclosure.SUMMARY:
        summary = {"sha256": _digest(raw), "length": len(raw)}
        return FieldView(attr_name, disclosure, reason=reason or REASON_SUMMARY_ONLY,
                         source=source, summary=summary)

    return FieldView(attr_name, Disclosure.REDACTED, reason=reason,
                     source=source)


def _export_row(table_name: str, rid: int, row: "base.MDTableRow", policy: ViewPolicy) -> RowView:
    fields: List[FieldView] = []
    for strategy in base.MDTableRow.CLASS_ATTRS + base.MDTableRow.CLASS_ATTRS_TABLES:
        kind = strategy[len("_struct_"):]
        for struct_name, spec in getattr(row.__class__, strategy, {}).items():
            attr_name = spec[0] if isinstance(spec, tuple) else spec
            fields.append(_export_field(row, table_name, attr_name, struct_name, kind, policy))

    file_offset = None
    if hasattr(row.struct, "get_file_offset"):
        file_offset = row.struct.get_file_offset()

    return RowView(table_name, rid, file_offset=file_offset, fields=fields)
