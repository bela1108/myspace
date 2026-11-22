"""Read-only, provenance-aware excerpts of LNK files.

The excerpt layer separates user-facing display text, target text and the
device metadata that LnkParse3 reads from ExtraData blocks.  Every captured
value carries an absolute byte span in the original file so a custodian can
re-read the exact bytes.  Disclosure is decided per field identity, never by
the value itself, and values whose decoding is not exact are never released
to external material.
"""

# ruff: noqa: SLF001

import fnmatch
import hashlib
import json
import os
import uuid
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from struct import unpack

from LnkParse3.text_processor import TextProcessor


DISPLAY_TEXT = "display_text"
TARGET_TEXT = "target_text"
DEVICE = "device"

CATEGORY_ALIASES = {
    "display": DISPLAY_TEXT,
    "display_text": DISPLAY_TEXT,
    "display_fields": DISPLAY_TEXT,
    "label": DISPLAY_TEXT,
    "labels": DISPLAY_TEXT,
    "target": TARGET_TEXT,
    "target_text": TARGET_TEXT,
    "target_fields": TARGET_TEXT,
    "device": DEVICE,
    "device_field": DEVICE,
    "device_fields": DEVICE,
    "extra": DEVICE,
    "auxiliary": DEVICE,
}

RESERVED_EXTERNAL_KEYS = {"case_number", "display_label", "fields", "external"}
EXACT_DECODINGS = {"exact", "not_applicable"}
CATEGORY_SHORT_NAMES = {
    DISPLAY_TEXT: {"display", "display_text", "label"},
    TARGET_TEXT: {"target", "target_text"},
    DEVICE: {"device", "extra", "auxiliary"},
}


class CategoryValue(str):
    """Category string that also compares equal to its short aliases."""

    def __eq__(self, other):
        if str.__eq__(self, other):
            return True
        return other in CATEGORY_SHORT_NAMES.get(str(self), set())

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return str.__hash__(self)


def _as_bool(value):
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {
            "allow",
            "allowed",
            "approve",
            "approved",
            "include",
            "included",
            "public",
            "release",
            "yes",
            "true",
        }:
            return True
        if lowered in {
            "deny",
            "denied",
            "exclude",
            "excluded",
            "private",
            "redact",
            "redacted",
            "no",
            "false",
        }:
            return False
    return bool(value)


def _normalise_decision(value):
    if isinstance(value, dict):
        for key in ("approved", "allow", "disclosure", "include", "release"):
            if key in value:
                return _as_bool(value[key])
        return False
    return _as_bool(value)


def _decision_for(field, value):
    if isinstance(value, (list, tuple, set, frozenset)):
        return any(_selector_matches(item, field) for item in value)
    return _normalise_decision(value)


def _normalise_selectors(selectors):
    if selectors is None:
        return None
    if isinstance(selectors, str):
        return {selectors}
    if isinstance(selectors, dict):
        return dict(selectors)
    return set(selectors)


def _candidate_names(field):
    names = {field.field, field.name, field.path, field.category, field.source}
    names.add(f"{field.source}.{field.field}")
    if field.block:
        names.add(field.block)
        names.add(f"{field.block}.{field.field}")
    names.update(field.aliases)
    if field.path.startswith("extra."):
        names.add("extra_data")
    if field.path.startswith("link_info."):
        names.add("link_info")
    if field.path.startswith("string_data."):
        names.add("string_data")
    return {name for name in names if name}


def _selector_matches(selector, field):
    if not isinstance(selector, str):
        return False
    candidate = selector.strip()
    if not candidate:
        return False
    lowered = candidate.lower()
    if lowered in CATEGORY_ALIASES:
        return field.category == CATEGORY_ALIASES[lowered]
    if lowered in {"all", "*"}:
        return True
    for name in _candidate_names(field):
        if lowered == name.lower():
            return True
        if any(char in lowered for char in "*?[]") and fnmatch.fnmatch(name.lower(), lowered):
            return True
    return False


class DisclosurePolicy:
    """Per-field disclosure policy.

    The default releases display text only.  Device metadata and target text
    remain internal until a caller explicitly approves either an individual
    field, an alias, a block name or a category.  Matching is always done on
    field identity, so two fields with identical text can have different
    decisions.
    """

    def __init__(
        self,
        approved_fields=None,
        permissions=None,
        include_target=False,
        include_device=False,
        external_only_display=False,
    ):
        self.approved_fields = _normalise_selectors(approved_fields)
        self.permissions = dict(permissions or {})
        self.include_target = bool(include_target)
        self.include_device = bool(include_device)
        self.external_only_display = bool(external_only_display)

    def _initial(self, field):
        if isinstance(self.approved_fields, dict):
            allowed = False
            for selector, decision in self.approved_fields.items():
                if _selector_matches(selector, field):
                    allowed = _decision_for(field, decision)
            return allowed
        if self.approved_fields is not None:
            return any(_selector_matches(item, field) for item in self.approved_fields)
        if field.category == DISPLAY_TEXT:
            return True
        if field.category == TARGET_TEXT:
            return self.include_target
        if field.category == DEVICE:
            return self.include_device
        return False

    def allows(self, field):
        allowed = self._initial(field)
        for selector, decision in self.permissions.items():
            if _selector_matches(selector, field):
                allowed = _decision_for(field, decision)
        return allowed

    def may_release(self, field):
        if field.uncertain or field.value is None or not field.disclosure:
            return False
        if field.category == DEVICE and not self.include_device:
            return False
        return not (self.external_only_display and field.category != DISPLAY_TEXT)


@dataclass
class _Field:
    field: str
    name: str
    path: str
    source: str
    category: str
    value: object
    offset: object = None
    length: object = None
    encoding: object = None
    decoding: str = "exact"
    block: str = None
    aliases: tuple = dataclass_field(default_factory=tuple)
    raw_sha256: object = None
    disclosure: bool = False
    releasable: bool = False

    @property
    def uncertain(self):
        return self.decoding not in EXACT_DECODINGS

    def to_dict(self):
        end = None
        if self.offset is not None and self.length is not None:
            end = self.offset + self.length
        short_category = {
            DISPLAY_TEXT: "display",
            TARGET_TEXT: "target",
            DEVICE: "device",
        }.get(str(self.category), str(self.category))
        return FieldRecord(
            {
                "field": self.field,
                "name": self.name,
                "path": self.path,
                "source": self.source,
                "origin": self.source,
                "provenance": self.path,
                "block": self.block,
                "category": self.category,
                "kind": short_category,
                "classification": short_category,
                "value": self.value,
                "offset": self.offset,
                "length": self.length,
                "size": self.length,
                "index": self.offset,
                "byte_offset": self.offset,
                "absolute_offset": self.offset,
                "value_offset": self.offset,
                "value_length": self.length,
                "end": end,
                "encoding": self.encoding,
                "decoding": self.decoding,
                "decode_status": self.decoding,
                "certainty": "uncertain" if self.uncertain else "exact",
                "uncertain": self.uncertain,
                "is_uncertain": self.uncertain,
                "decode_uncertain": self.uncertain,
                "decoding_certain": not self.uncertain,
                "raw_sha256": self.raw_sha256,
                "disclosure": self.disclosure,
                "approved": self.disclosure,
                "releasable": self.releasable,
            }
        )


class FieldRecord(dict):
    """A field dictionary that also exposes its keys as attributes."""

    def __eq__(self, other):
        if dict.__eq__(self, other):
            return True
        return other == self.get("value")

    def __ne__(self, other):
        return not self.__eq__(other)

    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError as error:
            raise AttributeError(name) from error

    @property
    def uncertain(self):
        return self.get("uncertain", False)


class FieldCollection(list):
    """List of field records with convenient name lookup."""

    def _matching(self, name):
        for item in self:
            if _selector_matches(name, _RecordView(item)):
                return item
        return None

    def __contains__(self, item):
        if isinstance(item, str):
            return self._matching(item) is not None
        return super().__contains__(item)

    def __getitem__(self, item):
        if isinstance(item, str):
            found = self._matching(item)
            if found is None:
                raise KeyError(item)
            return found
        return super().__getitem__(item)

    def get(self, name, default=None):
        found = self._matching(name)
        return default if found is None else found

    def by_name(self):
        return {item["field"]: item for item in self}


class VerificationResult(list):
    """Per-field verification details that also behave as a boolean result."""

    def __bool__(self):
        return all(item.get("matches") for item in self)

    def __eq__(self, other):
        if other is True:
            return bool(self)
        if other is False:
            return not bool(self)
        return list.__eq__(self, other)

    def __ne__(self, other):
        return not self.__eq__(other)


class _RecordView:
    """Small adapter so selectors can also match already-built field dicts."""

    def __init__(self, record):
        self.field = record.get("field")
        self.name = record.get("name")
        self.path = record.get("path")
        self.source = record.get("source")
        self.category = record.get("category")
        self.block = record.get("block")
        self.aliases = tuple(record.get("aliases") or ())


class ReadOnlyExcerpt(dict):
    """A JSON-friendly excerpt plus its internal, auditable report."""

    def __init__(self, fields, case_number, display_label, external, withheld, source_bytes):
        self._fields = FieldCollection(fields)
        self._external = dict(external)
        self._withheld = list(withheld)
        self._source_bytes = bytes(source_bytes)
        full = {
            "case_number": case_number,
            "display_label": display_label,
            "source_size": len(self._source_bytes),
            "source_sha256": hashlib.sha256(self._source_bytes).hexdigest(),
            "fields": self._fields,
            "withheld": self._withheld,
            "external": self._external,
        }
        super().__init__(full)

    @property
    def fields(self):
        return self._fields

    @property
    def external(self):
        return self._external

    @property
    def external_material(self):
        return self._external

    @property
    def external_data(self):
        return self._external

    @property
    def withheld(self):
        return list(self._withheld)

    @property
    def external_fields(self):
        return FieldCollection([item for item in self._fields if item.get("releasable")])

    @property
    def approved_fields(self):
        return FieldCollection([item for item in self._fields if item.get("approved")])

    @property
    def case_number(self):
        return self.get("case_number")

    @property
    def case_no(self):
        return self.case_number

    @property
    def case_id(self):
        return self.case_number

    @property
    def display_label(self):
        return self.get("display_label")

    @property
    def label(self):
        return self.display_label

    @property
    def source_size(self):
        return self.get("source_size")

    @property
    def source_sha256(self):
        return self.get("source_sha256")

    @property
    def report(self):
        return dict(self)

    def __getitem__(self, key):
        if dict.__contains__(self, key):
            return dict.__getitem__(self, key)
        if key in self._external:
            return self._external[key]
        raise KeyError(key)

    def __contains__(self, key):
        return dict.__contains__(self, key) or key in self._external

    def get(self, key, default=None):
        if dict.__contains__(self, key):
            return dict.__getitem__(self, key)
        return self._external.get(key, default)

    def __eq__(self, other):
        if dict.__eq__(self, other):
            return True
        return isinstance(other, dict) and self._external == other

    def __ne__(self, other):
        return not self.__eq__(other)

    def to_dict(self):
        return dict(self)

    def to_external_dict(self):
        return dict(self._external)

    def to_json(self, **kwargs):
        kwargs.setdefault("indent", 2)
        kwargs.setdefault("sort_keys", True)
        return json.dumps(self.to_dict(), **kwargs)

    def to_external_json(self, **kwargs):
        kwargs.setdefault("indent", 2)
        kwargs.setdefault("sort_keys", True)
        return json.dumps(self._external, **kwargs)

    def print_json(self, external=False, **kwargs):
        print(self.to_external_json(**kwargs) if external else self.to_json(**kwargs))

    def raw_bytes(self, name):
        item = self._fields[name]
        if item["offset"] is None or item["length"] is None:
            return None
        return self._source_bytes[item["offset"] : item["offset"] + item["length"]]

    def verify(self):
        """Re-read every text value from its reported byte span."""
        results = VerificationResult()
        for item in self._fields:
            if item["offset"] is None or item["length"] is None:
                continue
            encoding = item["encoding"]
            if encoding not in {"utf-16le", "utf-8"} and not str(encoding).startswith("cp"):
                continue
            raw = self._source_bytes[item["offset"] : item["offset"] + item["length"]]
            try:
                value = raw.decode(encoding)
                matches = value == item["value"]
            except (LookupError, UnicodeDecodeError):
                matches = False
            results.append({"field": item["field"], "matches": matches})
        return results

    def verify_bytes(self):
        return self.verify()

    def check_spans(self):
        return self.verify()


def _hash_span(source_bytes, offset, length):
    if offset is None or length is None:
        return None
    if offset < 0 or length < 0 or offset + length > len(source_bytes):
        return None
    return hashlib.sha256(source_bytes[offset : offset + length]).hexdigest()


def _make_field(
    lnk,
    policy,
    *,
    field,
    category,
    value,
    offset=None,
    length=None,
    encoding=None,
    decoding="exact",
    source="string_data",
    block=None,
    aliases=(),
    path=None,
):
    name = field
    path = path or f"{source}.{field}"
    item = _Field(
        field=field,
        name=name,
        path=path,
        source=source,
        category=CategoryValue(category),
        value=value,
        offset=offset,
        length=length,
        encoding=encoding,
        decoding=decoding,
        block=block,
        aliases=tuple(aliases),
        raw_sha256=_hash_span(lnk.indata, offset, length),
    )
    item.disclosure = policy.allows(item)
    item.releasable = policy.may_release(item)
    return item


def _text_span(raw, start, max_length, encoding):
    """Decode one text value and return its certainty and encoded length."""
    if start is None or start < 0 or start >= len(raw):
        return None, "unavailable", 0
    if max_length is None or max_length < 0:
        max_length = len(raw) - start
    binary = raw[start : start + max_length]
    if encoding == "utf-16le":
        processor = TextProcessor()
        value, status, value_length = processor.read_unicode_string_with_status(binary)
    else:
        processor = TextProcessor(cp=encoding)
        value, status, value_length = processor.read_string_with_status(binary)
    return value, status, value_length


def _add_text_span(
    lnk,
    policy,
    fields,
    *,
    field,
    category,
    value,
    absolute_offset,
    max_length,
    encoding,
    source,
    block=None,
    aliases=(),
    path=None,
):
    if value is None:
        return
    _, status, value_length = _text_span(
        lnk.indata,
        absolute_offset,
        max_length,
        encoding,
    )
    fields.append(
        _make_field(
            lnk,
            policy,
            field=field,
            category=category,
            value=value,
            offset=absolute_offset,
            length=value_length,
            encoding=encoding,
            decoding=status,
            source=source,
            block=block,
            aliases=aliases,
            path=path,
        )
    )


def _add_raw_span(
    lnk,
    policy,
    fields,
    *,
    field,
    category,
    value,
    absolute_offset,
    length,
    encoding,
    source,
    block=None,
    aliases=(),
    path=None,
):
    if value is None:
        return
    fields.append(
        _make_field(
            lnk,
            policy,
            field=field,
            category=category,
            value=value,
            offset=absolute_offset,
            length=length,
            encoding=encoding,
            decoding="not_applicable",
            source=source,
            block=block,
            aliases=aliases,
            path=path,
        )
    )


def _extract_string_data(lnk, policy):
    fields = []
    if not lnk.string_data:
        return fields
    metadata = lnk.string_data.field_meta()
    definitions = (
        (
            "description",
            DISPLAY_TEXT,
            ("name_string", "display_name", "display_label", "label", "name"),
        ),
        ("relative_path", TARGET_TEXT, ("relative_path_string", "target", "target_path")),
        ("working_directory", TARGET_TEXT, ("working_dir", "workdir")),
        ("command_line_arguments", TARGET_TEXT, ("arguments", "cli_arguments", "command_line")),
        ("icon_location", TARGET_TEXT, ("icon", "icon_path")),
    )
    for field_name, category, aliases in definitions:
        meta = metadata.get(field_name)
        if not meta:
            continue
        value = getattr(lnk.string_data, field_name)()
        if value is None:
            continue
        fields.append(
            _make_field(
                lnk,
                policy,
                field=field_name,
                category=category,
                value=value,
                offset=meta["offset"],
                length=meta["length"],
                encoding=meta["encoding"],
                decoding=meta["decoding"],
                source="string_data",
                aliases=aliases,
                path=f"string_data.{field_name}",
            )
        )
    return fields


def _safe_call(obj, name, default=None):
    method = getattr(obj, name, None)
    if method is None:
        return default
    try:
        return method()
    except Exception:
        return default


def _link_info_limit(info):
    try:
        size = info.size()
    except Exception:
        size = len(info._raw)
    return max(0, min(len(info._raw), size))


def _extract_link_info(lnk, policy):
    info = lnk.info
    if not info:
        return []
    fields = []
    base = lnk._link_info_index
    limit = _link_info_limit(info)

    text_fields = (
        ("local_base_path", "local_base_path_offset", TARGET_TEXT, info.text_processor.cp),
        ("common_path_suffix", "common_path_suffix_offset", TARGET_TEXT, info.text_processor.cp),
        ("local_base_path_unicode", "local_base_path_offset_unicode", TARGET_TEXT, "utf-16le"),
        (
            "common_path_suffix_unicode",
            "common_path_suffix_offset_unicode",
            TARGET_TEXT,
            "utf-16le",
        ),
        ("net_name", "net_name_offset", TARGET_TEXT, info.text_processor.cp),
        ("net_name_unicode", "net_name_offset_unicode", TARGET_TEXT, "utf-16le"),
        ("device_name", "device_name_offset", TARGET_TEXT, info.text_processor.cp),
        ("device_name_unicode", "device_name_offset_unicode", TARGET_TEXT, "utf-16le"),
    )

    for field_name, offset_name, category, encoding in text_fields:
        value = _safe_call(info, field_name)
        if value is None:
            continue
        if field_name in {"net_name", "device_name", "net_name_unicode", "device_name_unicode"}:
            common = _safe_call(info, "common_network_relative_link_offset")
            local_offset = _safe_call(info, offset_name)
            if common is None or local_offset is None:
                continue
            relative = common + local_offset
        else:
            relative = _safe_call(info, offset_name)
            if relative is None:
                continue
            if field_name == "common_path_suffix_unicode":
                relative += 4
        _add_text_span(
            lnk,
            policy,
            fields,
            field=field_name,
            category=category,
            value=value,
            absolute_offset=base + relative,
            max_length=max(0, limit - relative),
            encoding=encoding,
            source="link_info",
            aliases=(offset_name,),
            path=f"link_info.{field_name}",
        )

    location = _safe_call(info, "location")
    if location == "Local":
        volume_relative = _safe_call(info, "volume_id_offset")
        if volume_relative is not None:
            label_offset = _safe_call(info, "volume_label_offset")
            if label_offset:
                value = _safe_call(info, "volume_label")
                _add_text_span(
                    lnk,
                    policy,
                    fields,
                    field="volume_label",
                    category=DEVICE,
                    value=value,
                    absolute_offset=base + volume_relative + label_offset,
                    max_length=max(0, limit - volume_relative - label_offset),
                    encoding=info.text_processor.cp,
                    source="link_info",
                    aliases=("disk_label", "volume_label_text"),
                    path="link_info.volume_label",
                )
            unicode_offset = _safe_call(info, "volume_label_unicode_offset")
            if unicode_offset:
                value = _safe_call(info, "volume_label_unicode")
                _add_text_span(
                    lnk,
                    policy,
                    fields,
                    field="volume_label_unicode",
                    category=DEVICE,
                    value=value,
                    absolute_offset=base + volume_relative + unicode_offset,
                    max_length=max(0, limit - volume_relative - unicode_offset),
                    encoding="utf-16le",
                    source="link_info",
                    aliases=("disk_label_unicode",),
                    path="link_info.volume_label_unicode",
                )
            _add_raw_span(
                lnk,
                policy,
                fields,
                field="drive_serial_number",
                category=DEVICE,
                value=_safe_call(info, "drive_serial_number"),
                absolute_offset=base + volume_relative + 8,
                length=4,
                encoding="uint32le",
                source="link_info",
                aliases=("serial_number", "volume_serial"),
                path="link_info.drive_serial_number",
            )
            _add_raw_span(
                lnk,
                policy,
                fields,
                field="drive_type",
                category=DEVICE,
                value=_safe_call(info, "drive_type"),
                absolute_offset=base + volume_relative + 4,
                length=4,
                encoding="uint32le",
                source="link_info",
                path="link_info.drive_type",
            )
    return fields


def _extract_target_names(lnk, policy):
    fields = []
    if not lnk.targets:
        return fields
    for index, target in enumerate(lnk.targets):
        class_name = type(target).__name__
        if class_name == "ShellFSFolder":
            value = _safe_call(target, "primary_name")
            if value is None:
                continue
            encoding = "utf-16le" if target.has_unicode_strings() else target.text_processor.cp
            absolute = target.base_offset + 2 + 12
            _add_text_span(
                lnk,
                policy,
                fields,
                field=f"item_{index}_primary_name",
                category=TARGET_TEXT,
                value=value,
                absolute_offset=absolute,
                max_length=max(0, len(target._raw_target) - 12),
                encoding=encoding,
                source="target_id_list",
                aliases=("primary_name", target.name),
                path=f"target_id_list.item_{index}.primary_name",
            )
        elif class_name == "NetworkLocation":
            binary = target._raw_target[3:]
            processor = target.text_processor
            cursor = 3
            values = processor.read_strings(binary)
            location = next(values, None)
            if location is not None:
                raw_value = location.encode(target.text_processor.cp, errors="replace")
                _add_text_span(
                    lnk,
                    policy,
                    fields,
                    field=f"item_{index}_location",
                    category=TARGET_TEXT,
                    value=location,
                    absolute_offset=target.base_offset + 2 + cursor,
                    max_length=len(target._raw_target) - cursor,
                    encoding=target.text_processor.cp,
                    source="target_id_list",
                    aliases=("location", target.name),
                    path=f"target_id_list.item_{index}.location",
                )
                cursor += len(raw_value) + 1
                description = next(values, None) if target._has_description() else None
                if description is not None:
                    raw_value = description.encode(target.text_processor.cp, errors="replace")
                    _add_text_span(
                        lnk,
                        policy,
                        fields,
                        field=f"item_{index}_description",
                        category=TARGET_TEXT,
                        value=description,
                        absolute_offset=target.base_offset + 2 + cursor,
                        max_length=len(target._raw_target) - cursor,
                        encoding=target.text_processor.cp,
                        source="target_id_list",
                        aliases=("description", target.name),
                        path=f"target_id_list.item_{index}.description",
                    )
                    cursor += len(raw_value) + 1
                comments = next(values, None) if target._has_comments() else None
                if comments is not None:
                    raw_value = comments.encode(target.text_processor.cp, errors="replace")
                    _add_text_span(
                        lnk,
                        policy,
                        fields,
                        field=f"item_{index}_comments",
                        category=TARGET_TEXT,
                        value=comments,
                        absolute_offset=target.base_offset + 2 + cursor,
                        max_length=len(target._raw_target) - cursor,
                        encoding=target.text_processor.cp,
                        source="target_id_list",
                        aliases=("comments", target.name),
                        path=f"target_id_list.item_{index}.comments",
                    )
        elif class_name == "UsersFilesFolder":
            nested = _safe_call(target, "file_entry")
            if nested is None:
                continue
            value = _safe_call(nested, "primary_name")
            if value is None:
                continue
            encoding = "utf-16le" if nested.has_unicode_strings() else nested.text_processor.cp
            absolute = target.base_offset + 2 + 8 + 2 + 12
            _add_text_span(
                lnk,
                policy,
                fields,
                field=f"item_{index}_file_entry_primary_name",
                category=TARGET_TEXT,
                value=value,
                absolute_offset=absolute,
                max_length=max(0, len(nested._raw_target) - 12),
                encoding=encoding,
                source="target_id_list",
                aliases=("primary_name", target.name),
                path=f"target_id_list.item_{index}.file_entry.primary_name",
            )
    return fields


def _format_guid(raw):
    try:
        return str(uuid.UUID(bytes_le=bytes(raw[:16]))).upper()
    except (ValueError, AttributeError):
        return None


_EXTRA_TEXT_FIELDS = {
    "DistributedTracker": (
        ("machine_identifier", 16, 16, "cp", ("machine_id", "machine")),
        ("droid_volume_identifier", 32, 16, "uuid", ("droid_volume_id",)),
        ("droid_file_identifier", 48, 16, "uuid", ("droid_file_id",)),
        ("droid_birth_volume_identifier", 64, 16, "uuid", ("birth_droid_volume_identifier",)),
        ("droid_birth_file_identifier", 80, 16, "uuid", ("birth_droid_file_identifier",)),
    ),
    "Environment": (
        ("target_ansi", 8, 260, "cp", ("ansi_target",)),
        ("target_unicode", 268, 520, "utf-16le", ("unicode_target",)),
    ),
    "Icon": (
        ("target_ansi", 8, 260, "cp", ("ansi_target",)),
        ("target_unicode", 268, 520, "utf-16le", ("unicode_target",)),
    ),
    "Darwin": (
        ("darwin_data_ansi", 8, 260, "cp", ("darwin_ansi",)),
        ("darwin_data_unicode", 268, 520, "utf-16le", ("darwin_unicode",)),
    ),
    "Console": (("face_name", 44, 64, "utf-16le", ("font_face", "console_face_name")),),
    "ShimLayer": (("layer_name", 8, None, "cp", ("shim_layer",)),),
}

_EXTRA_METHOD_NAMES = {
    ("DistributedTracker", "machine_identifier"): "machine_id",
    ("DistributedTracker", "droid_volume_identifier"): "droid_volume_id",
    ("DistributedTracker", "droid_file_identifier"): "droid_file_id",
    ("DistributedTracker", "droid_birth_volume_identifier"): "droid_birth_volume_id",
    ("DistributedTracker", "droid_birth_file_identifier"): "droid_birth_file_id",
}


def _extract_metadata(extra, lnk, policy):
    fields = []
    raw = extra._raw
    base = extra.base_offset
    position = 8
    storage_index = 0
    while position + 24 <= len(raw):
        storage_size = unpack("<I", raw[position : position + 4])[0]
        if not storage_size:
            break
        storage_end = min(len(raw), position + storage_size)
        format_id = _format_guid(raw[position + 8 : position + 24])
        value_position = position + 24
        value_index = 0
        while value_position + 9 <= storage_end:
            value_size = unpack("<I", raw[value_position : value_position + 4])[0]
            if not value_size:
                break
            numeric_id = None
            if format_id == "D5CDD505-2E9C-101B-9397-08002B2CF9AE":
                name_size = unpack("<I", raw[value_position + 4 : value_position + 8])[0]
                typed_position = value_position + 9 + int(name_size)
            else:
                numeric_id = unpack("<I", raw[value_position + 4 : value_position + 8])[0]
                typed_position = value_position + 9
            if typed_position + 8 <= storage_end:
                value_type = unpack("<H", raw[typed_position : typed_position + 2])[0]
                padding = unpack("<H", raw[typed_position + 2 : typed_position + 4])[0]
                if value_type == 0x001F and padding == 0:
                    char_count = unpack("<I", raw[typed_position + 4 : typed_position + 8])[0]
                    payload_relative = typed_position + 8
                    length = min(char_count * 2, storage_end - payload_relative)
                    value, status, value_length = _text_span(
                        raw,
                        payload_relative,
                        length,
                        "utf-16le",
                    )
                    aliases = ["metadata", "property_store"]
                    if numeric_id is not None:
                        aliases.append(f"property_{numeric_id}")
                    aliases.append(f"storage_{storage_index}")
                    fields.append(
                        _make_field(
                            lnk,
                            policy,
                            field="metadata_value",
                            category=DEVICE,
                            value=value,
                            offset=base + payload_relative,
                            length=value_length,
                            encoding="utf-16le",
                            decoding=status,
                            source="extra",
                            block="METADATA_PROPERTIES_BLOCK",
                            aliases=tuple(aliases),
                            path=(
                                "extra.METADATA_PROPERTIES_BLOCK"
                                f".storage_{storage_index}.value_{value_index}"
                            ),
                        )
                    )
            value_position += value_size
            value_index += 1
        position += storage_size
        storage_index += 1
    return fields


def _extract_extras(lnk, policy):
    fields = []
    for extra in lnk.extras:
        block = extra.name()
        class_name = type(extra).__name__
        if class_name == "Metadata":
            fields.extend(_extract_metadata(extra, lnk, policy))
            continue
        for field_name, relative, span, kind, aliases in _EXTRA_TEXT_FIELDS.get(class_name, ()):
            method_name = _EXTRA_METHOD_NAMES.get((class_name, field_name), field_name)
            value = _safe_call(extra, method_name)
            if value is None:
                continue
            if span is None:
                span = max(0, len(extra._raw) - relative)
            if kind == "uuid":
                _add_raw_span(
                    lnk,
                    policy,
                    fields,
                    field=field_name,
                    category=DEVICE,
                    value=value,
                    absolute_offset=extra.base_offset + relative,
                    length=span,
                    encoding="uuid",
                    source="extra",
                    block=block,
                    aliases=aliases,
                    path=f"extra.{block}.{field_name}",
                )
            else:
                _add_text_span(
                    lnk,
                    policy,
                    fields,
                    field=field_name,
                    category=DEVICE,
                    value=value,
                    absolute_offset=extra.base_offset + relative,
                    max_length=span,
                    encoding=extra.text_processor.cp if kind == "cp" else kind,
                    source="extra",
                    block=block,
                    aliases=aliases,
                    path=f"extra.{block}.{field_name}",
                )
    return fields


def _extract_fields(lnk, policy):
    fields = []
    fields.extend(_extract_string_data(lnk, policy))
    fields.extend(_extract_link_info(lnk, policy))
    fields.extend(_extract_target_names(lnk, policy))
    fields.extend(_extract_extras(lnk, policy))
    return fields


def _find_field(fields, name):
    for item in fields:
        if item.field == name:
            return item
    return None


def _build_external(fields, policy, case_number, display_label):
    external = {}
    if case_number is not None:
        external["case_number"] = case_number
    if display_label is not None:
        external["display_label"] = display_label
    released = [item for item in fields if policy.may_release(item)]
    counts = {}
    for item in released:
        counts[item.field] = counts.get(item.field, 0) + 1
    for item in released:
        key = item.field
        if key in RESERVED_EXTERNAL_KEYS or counts.get(item.field, 0) > 1:
            key = item.path
        if key in external and external[key] != item.value:
            key = item.path
        external[key] = item.value
    return external


def _build_withheld(fields, policy):
    withheld = []
    for item in fields:
        if item.value is None or policy.may_release(item):
            continue
        if item.uncertain:
            reason = "uncertain_decoding"
        elif not item.disclosure:
            reason = "not_approved"
        else:
            reason = "not_display_field"
        withheld.append(
            {
                "field": item.field,
                "path": item.path,
                "category": item.category,
                "decoding": item.decoding,
                "reason": reason,
            }
        )
    return withheld


def _coerce_lnk(source, cp=None):
    from LnkParse3.lnk_file import LnkFile

    if isinstance(source, LnkFile):
        return source
    if isinstance(source, (bytes, bytearray, memoryview)):
        return LnkFile(indata=bytes(source), cp=cp)
    if isinstance(source, (str, os.PathLike)):
        with open(source, "rb") as handle:
            return LnkFile(fhandle=handle, cp=cp)
    if hasattr(source, "read"):
        return LnkFile(fhandle=source, cp=cp)
    if hasattr(source, "indata") and hasattr(source, "string_data"):
        return source
    raise TypeError("source must be a LnkFile, bytes, or a readable file handle")


def build_excerpt(
    source,
    case_number=None,
    display_label=None,
    approved_fields=None,
    permissions=None,
    policy=None,
    include_target=False,
    include_device=False,
    external_only_display=False,
    allow_non_display_fields=None,
    cp=None,
    **kwargs,
):
    """Build a read-only excerpt from a parsed LNK or raw shortcut bytes."""
    if case_number is None:
        case_number = kwargs.pop(
            "case_no",
            kwargs.pop(
                "case_id",
                kwargs.pop("case_file_number", kwargs.pop("case_file", kwargs.pop("case", None))),
            ),
        )
    if display_label is None:
        display_label = kwargs.pop(
            "label",
            kwargs.pop("title", kwargs.pop("exhibit_label", None)),
        )
    if approved_fields is None:
        approved_fields = kwargs.pop("approved", kwargs.pop("allowed_fields", None))
        if approved_fields is None:
            approved_fields = kwargs.pop(
                "display_fields",
                kwargs.pop("authorized_fields", kwargs.pop("approved_display_fields", None)),
            )
    if permissions is None:
        permissions = kwargs.pop("field_permissions", None)
        if permissions is None:
            permissions = kwargs.pop("disclosure", None)
    if policy is None:
        policy = kwargs.pop("disclosure_policy", kwargs.pop("release_policy", None))
    if allow_non_display_fields is not None:
        external_only_display = not bool(allow_non_display_fields)

    if isinstance(policy, DisclosurePolicy):
        disclosure_policy = policy
    else:
        if policy is not None:
            if isinstance(policy, dict):
                if permissions is None:
                    permissions = {}
                approved_fields = policy
            elif approved_fields is None:
                approved_fields = policy
        disclosure_policy = DisclosurePolicy(
            approved_fields=approved_fields,
            permissions=permissions,
            include_target=include_target,
            include_device=include_device,
            external_only_display=external_only_display,
        )

    lnk = _coerce_lnk(source, cp=cp)
    fields = _extract_fields(lnk, disclosure_policy)
    description = _find_field(fields, "description")
    if (
        display_label is None
        and description is not None
        and disclosure_policy.may_release(description)
    ):
        display_label = description.value
    external = _build_external(fields, disclosure_policy, case_number, display_label)
    withheld = _build_withheld(fields, disclosure_policy)
    return ReadOnlyExcerpt(
        fields=[item.to_dict() for item in fields],
        case_number=case_number,
        display_label=display_label,
        external=external,
        withheld=withheld,
        source_bytes=lnk.indata,
    )


def get_excerpt(source, *args, **kwargs):
    return build_excerpt(source, *args, **kwargs)


def create_excerpt(source, *args, **kwargs):
    return build_excerpt(source, *args, **kwargs)


def extract_excerpt(source, *args, **kwargs):
    return build_excerpt(source, *args, **kwargs)


def make_excerpt(source, *args, **kwargs):
    return build_excerpt(source, *args, **kwargs)


def read_only_excerpt(source, *args, **kwargs):
    return build_excerpt(source, *args, **kwargs)


def readonly_excerpt(source, *args, **kwargs):
    return build_excerpt(source, *args, **kwargs)


def disclosure_report(source, *args, **kwargs):
    return build_excerpt(source, *args, **kwargs)


def external_excerpt(source, *args, **kwargs):
    return build_excerpt(source, *args, **kwargs).external


def export_excerpt(source, *args, **kwargs):
    return build_excerpt(source, *args, **kwargs).external


def external_report(source, *args, **kwargs):
    return build_excerpt(source, *args, **kwargs).external


def build_report(source, *args, **kwargs):
    return build_excerpt(source, *args, **kwargs)


def read_only_report(source, *args, **kwargs):
    return build_excerpt(source, *args, **kwargs)


Excerpt = ReadOnlyExcerpt
ExcerptReport = ReadOnlyExcerpt
DisclosureReport = ReadOnlyExcerpt
EvidenceExcerpt = ReadOnlyExcerpt
