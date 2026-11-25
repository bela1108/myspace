"""
Boot Configuration Data (BCD) role and boot-selection analysis.

An offline BCD hive proves how a machine is *configured* to boot.  It does
not, by itself, prove which menu item a user actually chose on the last boot.
This module keeps that distinction explicit:

* every fact read from the hive carries the registry key it came from;
* a caller-supplied one-time selection observation can establish an observed
  choice for that boot;
* without such an observation the result is a configured default, never a
  claim about the actual last selection;
* references to objects that are not present in the hive are reported instead
  of being silently treated as valid.

The analyzer accepts either a RegistryHive or a plain mapping describing a
synthetic BCD model.  The mapping form is useful for testing selection logic
without committing a binary hive fixture:

    {
        "objects": {
            "{bootmgr}": {
                "type": 0x10100002,
                "elements": {
                    0x23000003: "{default-os}",
                    0x24000001: ["{default-os}", "{temporary-os}"],
                },
            },
            "{default-os}": {
                "type": 0x10200003,
                "name": "Windows Default",
                "elements": {0x12000002: "\\Windows\\system32\\winload.efi"},
            },
        }
    }
"""

from __future__ import annotations

import datetime as dt
import logging
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

# BCD object store key path.
# See https://www.geoffchappell.com/notes/windows/boot/bcd/objects.htm
BCD_OBJECTS_PATH = r"\Objects"

# Well-known BCD object identifier for the Windows Boot Manager.
WINDOWS_BOOT_MANAGER_GUID = "{9dea862c-5cdd-4e70-acc1-f32b344d4795}"

# BCD object element types.
# See https://www.geoffchappell.com/notes/windows/boot/bcd/elements.htm
ELEMENT_TYPE_APPLICATION_DEVICE = 0x11000001
ELEMENT_TYPE_APPLICATION_PATH = 0x12000002
ELEMENT_TYPE_DESCRIPTION = 0x12000004
ELEMENT_TYPE_DEFAULT = 0x23000003
ELEMENT_TYPE_RESUME_OBJECT = 0x23000006
ELEMENT_TYPE_DISPLAY_ORDER = 0x24000001
ELEMENT_TYPE_BOOT_SEQUENCE = 0x24000002
ELEMENT_TYPE_TOOLS_DISPLAY_ORDER = 0x24000010

# Aliases kept for callers and plugins that used the older constants.
ELEM_TYPE_APPLICATION_DEVICE = ELEMENT_TYPE_APPLICATION_DEVICE
ELEM_TYPE_APPLICATION_PATH = ELEMENT_TYPE_APPLICATION_PATH
ELEM_TYPE_DESCRIPTION = ELEMENT_TYPE_DESCRIPTION
ELEM_TYPE_DEFAULT = ELEMENT_TYPE_DEFAULT
ELEM_TYPE_RESUME_OBJECT = ELEMENT_TYPE_RESUME_OBJECT
ELEM_TYPE_DISPLAY_ORDER = ELEMENT_TYPE_DISPLAY_ORDER
ELEM_TYPE_BOOT_SEQUENCE = ELEMENT_TYPE_BOOT_SEQUENCE
BCD_OBJECTS_KEY_PATH = BCD_OBJECTS_PATH

# BCD object types -> (generic role, specific role).
OBJECT_TYPE_ROLES: dict[int, tuple[str, str]] = {
    0x10100001: ("boot_manager", "firmware_boot_manager"),
    0x10100002: ("boot_manager", "windows_boot_manager"),
    0x101FFFFF: ("firmware_application", "firmware_application"),
    0x10200003: ("boot_loader", "windows_boot_loader"),
    0x10200004: ("resume_application", "windows_resume_application"),
    0x10200005: ("memory_diagnostic", "windows_memory_diagnostic"),
    0x10300000: ("legacy_loader", "legacy_loader"),
    0x30000000: ("device", "device"),
}

_GUID_RE = re.compile(
    r"^\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?$"
)

_ELEMENT_NAME_MAP = {
    "applicationdevice": ELEMENT_TYPE_APPLICATION_DEVICE,
    "applicationpath": ELEMENT_TYPE_APPLICATION_PATH,
    "description": ELEMENT_TYPE_DESCRIPTION,
    "default": ELEMENT_TYPE_DEFAULT,
    "resumeobject": ELEMENT_TYPE_RESUME_OBJECT,
    "displayorder": ELEMENT_TYPE_DISPLAY_ORDER,
    "bootsequence": ELEMENT_TYPE_BOOT_SEQUENCE,
    "toolsdisplayorder": ELEMENT_TYPE_TOOLS_DISPLAY_ORDER,
}


def _coerce_int(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    try:
        text = str(value).strip()
        if text.lower().startswith("0x"):
            return int(text, 16)
        return int(text)
    except (TypeError, ValueError):
        return None


def _decode_bytes(data: bytes) -> str:
    if data.startswith(bytes([255, 254])):
        return data[2:].decode("utf-16-le", errors="replace")
    if data.startswith(bytes([254, 255])):
        return data[2:].decode("utf-16-be", errors="replace")
    if not data:
        return ""

    if bytes([0]) in data:
        pairs = len(data) // 2
        high_zero = sum(1 for index in range(1, len(data), 2) if data[index] == 0)
        if pairs and high_zero >= max(1, int(pairs * 0.6)):
            return data.decode("utf-16-le", errors="replace")
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            return data.decode("latin-1")

    candidates: list[tuple[int, int, str]] = []
    for encoding in ("utf-16-le", "utf-8"):
        try:
            text = data.decode(encoding)
        except UnicodeDecodeError:
            continue
        printable = sum(1 for character in text if character.isprintable() or character in "\r\n\t")
        controls = sum(1 for character in text if ord(character) < 32 and character not in "\r\n\t")
        candidates.append((printable - controls * 4, len(text), text))
    if candidates:
        return max(candidates, key=lambda item: (item[0], item[1]))[2]
    return data.decode("latin-1")


def _as_text(value: Any) -> str | None:
    """Convert a BCD string-ish value into text without losing meaning."""
    if value is None:
        return None
    if isinstance(value, (bytes, bytearray)):
        text = _decode_bytes(bytes(value))
    elif isinstance(value, (list, tuple)):
        parts = [_as_text(item) for item in value]
        return ", ".join(part for part in parts if part)
    else:
        text = str(value)
    text = text.replace("\x00", "").strip()
    return text or None


def _as_text_list(value: Any) -> list[str]:
    """Normalize REG_SZ, REG_MULTI_SZ and bytes into a list of strings."""
    if value is None:
        return []
    if isinstance(value, (bytes, bytearray)):
        text = _decode_bytes(bytes(value))
        return [part.strip() for part in text.split(chr(0)) if part.strip()]
    if isinstance(value, (list, tuple)):
        result: list[str] = []
        for item in value:
            result.extend(_as_text_list(item))
        return result
    text = str(value).replace("\x00", "\n")
    return [part.strip() for part in re.split(r"[\r\n;]+", text) if part.strip()]


def canonical_guid(value: Any) -> str | None:
    """Return a brace-delimited lower-case GUID where possible."""
    text = _as_text(value)
    if not text:
        return None
    text = text.strip()
    if _GUID_RE.match(text):
        return "{" + text.strip("{}").lower() + "}"
    return text.lower()


def _is_guid(value: Any) -> bool:
    text = _as_text(value)
    return bool(text and _GUID_RE.match(text.strip()))


def _format_object_type(object_type: int | None) -> str | None:
    return f"0x{object_type:08X}" if object_type is not None else None


def _role_for_type(object_type: int | None) -> tuple[str, str]:
    if object_type is None:
        return "unknown", "unknown"
    if object_type in OBJECT_TYPE_ROLES:
        return OBJECT_TYPE_ROLES[object_type]
    if 0x10300000 <= object_type <= 0x103FFFFF:
        return "legacy_loader", "legacy_loader"
    return "unknown", f"unknown_0x{object_type:08X}"


def _parse_element_type(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    text = str(value).strip()
    if not text:
        return None
    mapped = _ELEMENT_NAME_MAP.get(re.sub(r"[^a-z0-9]", "", text.lower()))
    if mapped is not None:
        return mapped
    try:
        if text.lower().startswith("0x"):
            return int(text, 16)
        if re.fullmatch(r"[0-9a-fA-F]{4,8}", text):
            return int(text, 16)
        return int(text)
    except ValueError:
        return None


def _safe_get_value(key: Any, value_name: str) -> Any:
    if key is None:
        return None
    try:
        return key.get_value(
            value_name,
            as_json=False,
            raise_on_missing=False,
            trim_values=False,
        )
    except TypeError:
        try:
            return key.get_value(value_name)
        except Exception:
            return None
    except Exception:
        logger.debug("Failed reading BCD value %s", value_name, exc_info=True)
        return None


def _safe_get_subkey(key: Any, subkey_name: str) -> Any:
    if key is None:
        return None
    try:
        return key.get_subkey(subkey_name, raise_on_missing=False)
    except TypeError:
        try:
            return key.get_subkey(subkey_name)
        except Exception:
            return None
    except Exception:
        logger.debug("Failed reading BCD subkey %s", subkey_name, exc_info=True)
        return None


def _safe_iter_subkeys(key: Any) -> list[Any]:
    if key is None:
        return []
    try:
        return list(key.iter_subkeys() or [])
    except Exception:
        logger.debug("Failed iterating BCD subkeys", exc_info=True)
        return []


def _name_suffix(name: str | None) -> str:
    return " (" + name + ")" if name else ""


@dataclass
class BcdObject:
    """Normalized BCD object used by the selection analyzer."""

    guid: str
    object_type: int | None
    elements: dict[int, Any] = field(default_factory=dict)
    name: str | None = None
    application_path: str | None = None
    source_key: str = ""
    type_source_key: str | None = None

    @property
    def role(self) -> str:
        return _role_for_type(self.object_type)[0]

    @property
    def role_detail(self) -> str:
        return _role_for_type(self.object_type)[1]

    def public(self) -> dict[str, Any]:
        return {
            "guid": self.guid,
            "object_type": self.object_type,
            "type": _format_object_type(self.object_type),
            "role": self.role,
            "role_detail": self.role_detail,
            "name": self.name,
            "application_path": self.application_path,
            "source_key": self.source_key,
            "type_source_key": self.type_source_key,
        }


@dataclass
class BcdModel:
    """A collection of normalized BCD objects."""

    objects: dict[str, BcdObject] = field(default_factory=dict)
    source: str = "registry"

    @classmethod
    def from_source(cls, source: Any) -> BcdModel:
        if isinstance(source, cls):
            return source
        if isinstance(source, Mapping):
            return cls.from_mapping(source)
        return cls.from_hive(source)

    @classmethod
    def from_hive(cls, hive: Any) -> BcdModel:
        objects_key = None
        for path in (BCD_OBJECTS_PATH, "Objects"):
            try:
                objects_key = hive.get_key(path)
                break
            except Exception:
                continue

        if objects_key is None:
            root = getattr(hive, "root", None)
            if root is not None and str(getattr(root, "name", "")).lower() == "objects":
                objects_key = root

        objects: dict[str, BcdObject] = {}
        for object_key in _safe_iter_subkeys(objects_key):
            record = _record_from_registry_object(object_key)
            if record is not None:
                objects[record.guid] = record
        return cls(objects=objects, source="registry")

    @classmethod
    def from_mapping(cls, model: Mapping[Any, Any]) -> BcdModel:
        object_map = _find_objects_mapping(model)
        objects: dict[str, BcdObject] = {}
        for raw_guid, raw_object in object_map.items():
            record = _record_from_mapping_object(raw_guid, raw_object)
            if record is not None:
                objects[record.guid] = record
        return cls(objects=objects, source="mapping")


def _find_objects_mapping(model: Mapping[Any, Any]) -> Mapping[Any, Any]:
    for key, value in model.items():
        if str(key).lower() in ("objects", "object_store", "\\objects") and isinstance(value, Mapping):
            return value

    for value in model.values():
        if isinstance(value, Mapping):
            for key, nested in value.items():
                if str(key).lower() in ("objects", "object_store", "\\objects") and isinstance(nested, Mapping):
                    return nested

    if model and all(_is_guid(key) for key in model):
        return model
    return {}


def _get_mapping_value(mapping: Mapping[Any, Any], *names: str) -> Any:
    wanted = {name.lower() for name in names}
    for key, value in mapping.items():
        if str(key).lower() in wanted:
            return value
    return None


def _unwrap_element_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        for key in ("Element", "element", "value", "Value", "data"):
            if key in value:
                return value[key]
        if "guid" in value:
            return value["guid"]
    return value


def _elements_from_mapping(raw_elements: Any) -> dict[int, Any]:
    elements: dict[int, Any] = {}
    if isinstance(raw_elements, Mapping):
        for raw_type, raw_value in raw_elements.items():
            element_type = _parse_element_type(raw_type)
            if element_type is None:
                continue
            elements[element_type] = _unwrap_element_value(raw_value)
        return elements

    if isinstance(raw_elements, (list, tuple)):
        for item in raw_elements:
            if not isinstance(item, Mapping):
                continue
            raw_type = _get_mapping_value(item, "type", "element_type", "element", "name")
            raw_value = _get_mapping_value(item, "value", "data", "element")
            element_type = _parse_element_type(raw_type)
            if element_type is not None:
                elements[element_type] = _unwrap_element_value(raw_value)
    return elements


def _record_from_mapping_object(raw_guid: Any, raw_object: Any) -> BcdObject | None:
    if not isinstance(raw_object, Mapping):
        return None

    guid = canonical_guid(_get_mapping_value(raw_object, "guid", "object_guid") or raw_guid)
    if not guid:
        return None

    raw_elements = _get_mapping_value(raw_object, "elements", "elements_map", "values")
    if raw_elements is None:
        raw_elements = {key: value for key, value in raw_object.items() if _parse_element_type(key) is not None}
    elements = _elements_from_mapping(raw_elements)

    description = _get_mapping_value(raw_object, "description", "Description")
    description_type = None
    description_name = None
    if isinstance(description, Mapping):
        description_type = _get_mapping_value(description, "type", "object_type")
        description_name = _get_mapping_value(description, "name", "value", "description")
    elif description is not None:
        description_name = description

    object_type = _coerce_int(_get_mapping_value(raw_object, "type", "object_type", "description_type") or description_type)
    name = _as_text(_get_mapping_value(raw_object, "name") or description_name or elements.get(ELEMENT_TYPE_DESCRIPTION))
    application_path = _as_text(
        _get_mapping_value(raw_object, "application_path", "image_path", "path") or elements.get(ELEMENT_TYPE_APPLICATION_PATH)
    )

    source_key = BCD_OBJECTS_PATH + "\\" + guid
    return BcdObject(
        guid=guid,
        object_type=object_type,
        elements=elements,
        name=name,
        application_path=application_path,
        source_key=source_key,
        type_source_key=source_key + "\\Description\\Type" if object_type is not None else None,
    )


def _record_from_registry_object(object_key: Any) -> BcdObject | None:
    raw_name = getattr(object_key, "name", None)
    guid = canonical_guid(raw_name)
    if guid is None:
        return None

    source_key = BCD_OBJECTS_PATH + "\\" + str(raw_name)
    description_key = _safe_get_subkey(object_key, "Description")
    object_type = _coerce_int(_safe_get_value(description_key, "Type"))

    elements: dict[int, Any] = {}
    elements_key = _safe_get_subkey(object_key, "Elements")
    for element_key in _safe_iter_subkeys(elements_key):
        element_type = _parse_element_type(getattr(element_key, "name", None))
        if element_type is None:
            continue
        value = _safe_get_value(element_key, "Element")
        if value is None:
            value = _safe_get_value(element_key, "(default)")
        if value is not None:
            elements[element_type] = value

    name = _as_text(elements.get(ELEMENT_TYPE_DESCRIPTION))
    if name is None and description_key is not None:
        name = _as_text(_safe_get_value(description_key, "Description"))
    application_path = _as_text(elements.get(ELEMENT_TYPE_APPLICATION_PATH))

    return BcdObject(
        guid=guid,
        object_type=object_type,
        elements=elements,
        name=name,
        application_path=application_path,
        source_key=source_key,
        type_source_key=source_key + "\\Description\\Type" if object_type is not None else None,
    )


def _element_source(record: BcdObject, element_type: int, index: int | None = None) -> str:
    source = f"{record.source_key}\\Elements\\{element_type:08X}\\Element"
    if index is not None:
        source += f"[{index}]"
    return source


def _element_guid(value: Any) -> str | None:
    if isinstance(value, (list, tuple)):
        return canonical_guid(value[0]) if value else None
    return canonical_guid(value)


def _element_guid_list(value: Any) -> list[str]:
    result: list[str] = []
    for item in _as_text_list(value):
        guid = canonical_guid(item)
        if guid:
            result.append(guid)
    return result


def _display_order_guids(record: BcdObject) -> list[str]:
    return _element_guid_list(record.elements.get(ELEMENT_TYPE_DISPLAY_ORDER))


def _entry_from_record(
    record: BcdObject,
    source_key: str,
    relationship: str | None = None,
) -> dict[str, Any]:
    entry = {
        "guid": record.guid,
        "resolved": True,
        "object_type": record.object_type,
        "type": _format_object_type(record.object_type),
        "role": record.role,
        "role_detail": record.role_detail,
        "name": record.name,
        "application_path": record.application_path,
        "source_key": source_key,
    }
    if relationship is not None:
        entry["relationship"] = relationship
    return entry


def _unresolved_entry(
    guid: str | None,
    source_key: str | None,
    relationship: str | None = None,
) -> dict[str, Any]:
    entry = {
        "guid": guid,
        "resolved": False,
        "object_type": None,
        "type": None,
        "role": None,
        "role_detail": None,
        "name": None,
        "application_path": None,
        "source_key": source_key,
    }
    if relationship is not None:
        entry["relationship"] = relationship
    return entry


def _missing_object(
    guid: str | None,
    source_key: str | None,
    referenced_as: str,
    reason: str,
) -> dict[str, Any]:
    return {
        "guid": guid,
        "source_key": source_key,
        "referenced_as": referenced_as,
        "reason": reason,
    }


def _normalize_observation(raw_observation: Any, default_source: str | None = None) -> dict[str, Any] | None:
    if raw_observation is None:
        return None

    if isinstance(raw_observation, (list, tuple)):
        raw_observation = raw_observation[0] if raw_observation else None
        if raw_observation is None:
            return None
    if isinstance(raw_observation, str):
        observation: dict[str, Any] = {"guid": raw_observation}
    elif isinstance(raw_observation, Mapping):
        observation = dict(raw_observation)
    else:
        observation = {}
        for attr in ("guid", "selected_guid", "object_guid", "id", "value"):
            if hasattr(raw_observation, attr):
                observation["guid"] = getattr(raw_observation, attr)
                break
        for attr in ("source", "source_key", "evidence", "note"):
            if hasattr(raw_observation, attr):
                observation[attr] = getattr(raw_observation, attr)
                break

    raw_guid = None
    for key in (
        "guid",
        "selected_guid",
        "object_guid",
        "entry",
        "selected_entry",
        "boot_entry",
        "object",
        "id",
    ):
        if observation.get(key) is not None:
            raw_guid = observation[key]
            break
    if isinstance(raw_guid, Mapping):
        for key in ("guid", "selected_guid", "object_guid", "id"):
            if raw_guid.get(key) is not None:
                raw_guid = raw_guid[key]
                break
        else:
            raw_guid = None
    elif raw_guid is not None and not isinstance(raw_guid, str):
        for attr in ("guid", "selected_guid", "object_guid", "id"):
            if hasattr(raw_guid, attr):
                raw_guid = getattr(raw_guid, attr)
                break
    guid = canonical_guid(raw_guid)
    if guid is None:
        return None

    source_key = None
    for key in ("source_key", "source", "evidence", "note"):
        if observation.get(key):
            source_key = str(observation[key])
            break
    if source_key is None:
        source_key = default_source or "caller:one_time_selection"

    observed_at = None
    for key in ("observed_at", "timestamp", "time", "when"):
        if observation.get(key):
            observed_at = observation[key]
            break
    if isinstance(observed_at, dt.datetime):
        observed_at = observed_at.isoformat()

    return {
        "guid": guid,
        "provided": True,
        "kind": "one_time_selection",
        "source_key": source_key,
        "observed_at": observed_at,
    }


def _manager_sort_key(record: BcdObject) -> tuple[int, int, int, int, str]:
    return (
        0 if record.elements.get(ELEMENT_TYPE_DEFAULT) else 1,
        0 if record.guid == WINDOWS_BOOT_MANAGER_GUID else 1,
        0 if record.object_type == 0x10100002 else 1 if record.object_type == 0x10100001 else 2,
        0 if record.elements.get(ELEMENT_TYPE_DISPLAY_ORDER) else 1,
        record.guid,
    )


def _choose_boot_manager(
    objects: dict[str, BcdObject],
    boot_manager_guid: Any,
) -> tuple[BcdObject | None, list[BcdObject], list[dict[str, Any]]]:
    missing: list[dict[str, Any]] = []
    if boot_manager_guid is not None:
        guid = canonical_guid(boot_manager_guid)
        record = objects.get(guid) if guid else None
        if record is None:
            missing.append(
                _missing_object(
                    guid,
                    BCD_OBJECTS_PATH + "\\" + guid if guid else BCD_OBJECTS_PATH,
                    "boot_manager",
                    "explicit_boot_manager_not_found",
                )
            )
            return None, [], missing
        return record, [record], missing

    managers = [record for record in objects.values() if record.role == "boot_manager"]
    if not managers:
        managers = [
            record
            for record in objects.values()
            if record.elements.get(ELEMENT_TYPE_DEFAULT) or record.elements.get(ELEMENT_TYPE_DISPLAY_ORDER)
        ]
    managers.sort(key=_manager_sort_key)
    return (managers[0] if managers else None), managers, missing


def _resolve_reference(
    guid: str | None,
    source_key: str,
    referenced_as: str,
    objects: dict[str, BcdObject],
    missing: list[dict[str, Any]],
    relationship: str | None = None,
) -> dict[str, Any]:
    if guid is None:
        missing.append(_missing_object(None, source_key, referenced_as, "missing_reference_value"))
        return _unresolved_entry(None, source_key, relationship)
    record = objects.get(guid)
    if record is None:
        missing.append(_missing_object(guid, source_key, referenced_as, "object_not_found"))
        return _unresolved_entry(guid, source_key, relationship)
    return _entry_from_record(record, source_key, relationship)


def _follow_chain(
    start: BcdObject,
    start_source: str,
    relationship: str,
    objects: dict[str, BcdObject],
    missing: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Follow nested boot managers to the entry that would be launched."""
    chain: list[dict[str, Any]] = []
    current: BcdObject | None = start
    current_source = start_source
    current_relationship = relationship
    visited: set = set()

    while current is not None:
        if current.guid in visited:
            entry = _unresolved_entry(current.guid, current_source, "cycle_detected")
            chain.append(entry)
            missing.append(_missing_object(current.guid, current_source, "selection_cycle", "cycle_detected"))
            break
        visited.add(current.guid)
        chain.append(_entry_from_record(current, current_source, current_relationship))
        if current.role != "boot_manager":
            break

        default_value = current.elements.get(ELEMENT_TYPE_DEFAULT)
        if default_value is None:
            break

        next_source = _element_source(current, ELEMENT_TYPE_DEFAULT)
        next_guid = _element_guid(default_value)
        next_record = objects.get(next_guid) if next_guid else None
        if next_record is None:
            missing.append(_missing_object(next_guid, next_source, "nested_default_entry", "object_not_found"))
            chain.append(_unresolved_entry(next_guid, next_source, "default"))
            break
        current = next_record
        current_source = next_source
        current_relationship = "default"

    return chain


def _dedupe_missing(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen = set()
    result = []
    for item in items:
        key = (
            item.get("guid"),
            item.get("source_key"),
            item.get("referenced_as"),
            item.get("reason"),
        )
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return result


def _claim(
    name: str,
    statement: str,
    source_key: str | None,
    provable: bool,
    certainty: str,
    evidence: str | None = None,
) -> dict[str, Any]:
    result = {
        "claim": name,
        "statement": statement,
        "source_key": source_key,
        "provable": provable,
        "certainty": certainty,
    }
    if evidence is not None:
        result["evidence"] = evidence
    return result


def analyze_boot_selection(
    registry_hive: Any = None,
    observed_selection: Any = None,
    *,
    observation: Any = None,
    selected_guid: Any = None,
    boot_manager_guid: Any = None,
    source: str | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    """
    Resolve the BCD boot role chain and report only what the evidence proves.

    :param registry_hive: A RegistryHive or a synthetic BCD mapping.
    :param observed_selection: Optional caller-supplied one-time selection
        observation.  May be a GUID string, a mapping with a guid key (and
        optionally source_key or timestamp), or an object with a guid
        attribute.  Supplying this is the only way the result can claim an
        observed selection rather than a configured default.
    :param observation: Alias for observed_selection.
    :param selected_guid: Convenience alias for a bare observed GUID.
    :param boot_manager_guid: Optional explicit boot-manager object GUID.
    :param source: Optional evidence source label for a bare observation.
    """
    if registry_hive is None:
        registry_hive = kwargs.get("hive") or kwargs.get("bcd_hive")
    if boot_manager_guid is None:
        boot_manager_guid = kwargs.get("boot_manager") or kwargs.get("manager_guid")
    if observed_selection is None:
        observed_selection = observation
    if observed_selection is None:
        observed_selection = selected_guid
    if observed_selection is None:
        for alias in (
            "observed_entry",
            "observed_guid",
            "last_selection",
            "last_boot_entry",
            "last_boot",
            "selected_boot_entry",
            "selection",
        ):
            if kwargs.get(alias) is not None:
                observed_selection = kwargs[alias]
                break

    model = BcdModel.from_source(registry_hive)
    objects = model.objects
    missing: list[dict[str, Any]] = []

    boot_manager, boot_managers, manager_missing = _choose_boot_manager(objects, boot_manager_guid)
    missing.extend(manager_missing)
    if boot_manager is None and not manager_missing:
        missing.append(_missing_object(None, BCD_OBJECTS_PATH, "boot_manager", "boot_manager_not_found"))

    objects_public = [objects[guid].public() for guid in sorted(objects)]
    roles_public: dict[str, list[dict[str, Any]]] = {}
    for object_public in objects_public:
        roles_public.setdefault(object_public["role"], []).append(object_public)
    boot_managers_public = [record.public() for record in boot_managers]
    boot_manager_public = boot_manager.public() if boot_manager is not None else None

    default_entry: dict[str, Any] | None = None
    default_source: str | None = None
    if boot_manager is not None:
        default_value = boot_manager.elements.get(ELEMENT_TYPE_DEFAULT)
        if default_value is not None:
            default_source = _element_source(boot_manager, ELEMENT_TYPE_DEFAULT)
            default_entry = _resolve_reference(
                _element_guid(default_value),
                default_source,
                "default_entry",
                objects,
                missing,
            )

    display_order: list[dict[str, Any]] = []
    display_source: str | None = None
    if boot_manager is not None:
        display_value = boot_manager.elements.get(ELEMENT_TYPE_DISPLAY_ORDER)
        if display_value is not None:
            display_source = _element_source(boot_manager, ELEMENT_TYPE_DISPLAY_ORDER)
            for index, guid in enumerate(_element_guid_list(display_value)):
                entry = _resolve_reference(
                    guid,
                    _element_source(boot_manager, ELEMENT_TYPE_DISPLAY_ORDER, index),
                    "display_order",
                    objects,
                    missing,
                )
                entry["index"] = index
                display_order.append(entry)

    boot_sequence: list[dict[str, Any]] = []
    boot_sequence_source: str | None = None
    if boot_manager is not None:
        sequence_value = boot_manager.elements.get(ELEMENT_TYPE_BOOT_SEQUENCE)
        if sequence_value is not None:
            boot_sequence_source = _element_source(boot_manager, ELEMENT_TYPE_BOOT_SEQUENCE)
            for index, guid in enumerate(_element_guid_list(sequence_value)):
                entry = _resolve_reference(
                    guid,
                    _element_source(boot_manager, ELEMENT_TYPE_BOOT_SEQUENCE, index),
                    "boot_sequence",
                    objects,
                    missing,
                )
                entry["index"] = index
                boot_sequence.append(entry)

    normalized_observation = _normalize_observation(observed_selection, source)
    observed_entry: dict[str, Any] | None = None
    if normalized_observation is not None:
        observed_entry = _resolve_reference(
            normalized_observation["guid"],
            normalized_observation["source_key"],
            "observed_selection",
            objects,
            missing,
            relationship="one_time_observation",
        )

    observation_in_display_order: bool | None = None
    observation_display_managers: list[BcdObject] = []
    if normalized_observation is not None:
        for manager in boot_managers:
            if normalized_observation["guid"] in _display_order_guids(manager):
                observation_display_managers.append(manager)
        if boot_managers:
            observation_in_display_order = bool(observation_display_managers)
    selection_context_manager = observation_display_managers[0] if observation_display_managers else boot_manager
    selection_context_source = (
        _element_source(selection_context_manager, ELEMENT_TYPE_DISPLAY_ORDER)
        if observation_display_managers and selection_context_manager is not None
        else None
    )
    selection_context_display_order: list[dict[str, Any]] = []
    if selection_context_manager is not None:
        for index, context_guid in enumerate(_display_order_guids(selection_context_manager)):
            context_entry = _resolve_reference(
                context_guid,
                _element_source(selection_context_manager, ELEMENT_TYPE_DISPLAY_ORDER, index),
                "display_order",
                objects,
                missing,
            )
            context_entry["index"] = index
            selection_context_display_order.append(context_entry)

    selected_entry: dict[str, Any] | None
    selection_chain: list[dict[str, Any]]
    selected_basis: str
    selected_certainty: str
    selected_source: str | None

    if normalized_observation is not None:
        selected_basis = "caller_observation"
        selected_source = normalized_observation["source_key"]
        if observed_entry is not None and observed_entry["resolved"]:
            selected_certainty = "observed"
            selection_chain = _follow_chain(
                objects[observed_entry["guid"]],
                selected_source,
                "one_time_observation",
                objects,
                missing,
            )
        else:
            selected_certainty = "unresolved"
            selection_chain = [observed_entry] if observed_entry is not None else []
        selected_entry = selection_chain[-1] if selection_chain else observed_entry
    else:
        selected_basis = "bcd_default"
        selected_source = default_source
        if default_entry is not None and default_entry["resolved"]:
            selected_certainty = "configured_default"
            selection_chain = _follow_chain(
                objects[default_entry["guid"]],
                default_source or default_entry["source_key"],
                "default",
                objects,
                missing,
            )
        else:
            selected_certainty = "unresolved"
            selection_chain = [default_entry] if default_entry is not None else []
        selected_entry = selection_chain[-1] if selection_chain else default_entry

    if selected_entry is None:
        selected_entry = _unresolved_entry(None, selected_source, "default")
    selected_entry = dict(selected_entry)
    selected_entry["basis"] = selected_basis
    selected_entry["certainty"] = selected_certainty
    if selected_entry.get("source_key") is None:
        selected_entry["source_key"] = selected_source

    selected_in_display_order: bool | None = None
    selected_display_index: int | None = None
    if selected_entry.get("resolved") and selected_entry.get("guid"):
        for manager in boot_managers:
            manager_order = _display_order_guids(manager)
            if selected_entry["guid"] in manager_order:
                selected_in_display_order = True
                selected_display_index = manager_order.index(selected_entry["guid"])
                break
        else:
            if boot_managers:
                selected_in_display_order = False
    selected_entry["in_display_order"] = selected_in_display_order
    selected_entry["display_order_index"] = selected_display_index

    selection_path: list[dict[str, Any]] = []
    path_manager = selection_context_manager if selection_context_manager is not None else boot_manager
    if path_manager is not None:
        step = _entry_from_record(path_manager, path_manager.source_key, "boot_manager")
        step["step"] = 0
        step["basis"] = "bcd"
        step["certainty"] = "configured"
        selection_path.append(step)
    for entry in selection_chain:
        step = dict(entry)
        step["step"] = len(selection_path)
        step["basis"] = selected_basis
        step["certainty"] = selected_certainty
        selection_path.append(step)
    if not selection_path and selected_entry is not None:
        step = dict(selected_entry)
        step["step"] = 0
        selection_path.append(step)

    claims: list[dict[str, Any]] = []
    if boot_manager is not None:
        claims.append(
            _claim(
                "boot_manager",
                "The BCD boot manager object is " + boot_manager.guid + _name_suffix(boot_manager.name) + ".",
                boot_manager.source_key,
                True,
                "configured",
            )
        )
    else:
        claims.append(
            _claim(
                "boot_manager",
                "No BCD boot manager object could be identified.",
                None,
                False,
                "unresolved",
            )
        )

    if default_entry is not None:
        if default_entry["resolved"]:
            claims.append(
                _claim(
                    "configured_default_entry",
                    "The configured default boot entry is "
                    + str(default_entry["guid"])
                    + _name_suffix(default_entry.get("name"))
                    + ".",
                    default_entry["source_key"],
                    True,
                    "configured",
                )
            )
        else:
            claims.append(
                _claim(
                    "configured_default_reference",
                    "The configured default references "
                    + str(default_entry["guid"])
                    + ", but that object is not present in the hive.",
                    default_entry["source_key"],
                    True,
                    "configured",
                )
            )
            claims.append(
                _claim(
                    "configured_default_entry",
                    "The configured default entry cannot be resolved from the offline BCD.",
                    default_entry["source_key"],
                    False,
                    "unresolved",
                )
            )
    else:
        claims.append(
            _claim(
                "configured_default_entry",
                "The boot manager has no Default element.",
                boot_manager.source_key if boot_manager is not None else None,
                True,
                "absent",
            )
        )

    if display_source is not None:
        display_guids = [entry["guid"] for entry in display_order]
        claims.append(
            _claim(
                "display_order",
                "The boot manager display order is " + str(display_guids) + ".",
                display_source,
                True,
                "configured",
            )
        )
    else:
        claims.append(
            _claim(
                "display_order",
                "The boot manager has no DisplayOrder element.",
                boot_manager.source_key if boot_manager is not None else None,
                True,
                "absent",
            )
        )

    observation_resolved = bool(observed_entry is not None and observed_entry["resolved"])
    if normalized_observation is not None:
        if observation_in_display_order is True:
            claim_manager = observation_display_managers[0]
            claims.append(
                _claim(
                    "observed_selection_in_display_order",
                    "The observed selection "
                    + str(normalized_observation["guid"])
                    + " is listed in the DisplayOrder of "
                    + claim_manager.guid
                    + ".",
                    _element_source(claim_manager, ELEMENT_TYPE_DISPLAY_ORDER),
                    True,
                    "configured",
                )
            )
        elif observation_in_display_order is False:
            claims.append(
                _claim(
                    "observed_selection_in_display_order",
                    "The observed selection "
                    + str(normalized_observation["guid"])
                    + " is not listed in any boot manager DisplayOrder; it may be a one-time or temporary option.",
                    None,
                    True,
                    "absent",
                )
            )
        if observation_resolved:
            claims.append(
                _claim(
                    "observed_selection",
                    "The caller-provided one-time observation selects "
                    + str(observed_entry["guid"])
                    + _name_suffix(observed_entry.get("name"))
                    + ".",
                    normalized_observation["source_key"],
                    True,
                    "observed",
                    evidence="caller_provided_one_time_observation",
                )
            )
        else:
            claims.append(
                _claim(
                    "observed_selection",
                    "The caller-provided observation references "
                    + str(normalized_observation["guid"])
                    + ", which is missing from the BCD object store; the observed selection is unresolved.",
                    normalized_observation["source_key"],
                    False,
                    "unresolved",
                    evidence="caller_provided_one_time_observation",
                )
            )
    else:
        claims.append(
            _claim(
                "actual_last_selection",
                "The actual last boot selection is not provable from the offline BCD alone; "
                "only the configured default is known.",
                None,
                False,
                "not_observable",
            )
        )

    actual_selection_known = bool(normalized_observation is not None and observation_resolved)
    if normalized_observation is not None:
        if observation_resolved:
            conclusion_statement = (
                "The caller-provided one-time observation selects "
                + str(observed_entry["guid"])
                + _name_suffix(observed_entry.get("name"))
                + ". This is an observed selection, not merely the BCD default."
            )
            if observation_in_display_order is True:
                conclusion_statement += " The entry is listed in the boot manager DisplayOrder."
            elif observation_in_display_order is False:
                conclusion_statement += (
                    " The entry is not listed in any boot manager DisplayOrder,"
                    " which is consistent with a one-time or temporary option."
                )
            conclusion_certainty = "observed"
        else:
            conclusion_statement = (
                "The caller-provided observation references "
                + str(normalized_observation["guid"])
                + ", which is missing; the actual selection is unresolved. "
            )
            if default_entry is not None and default_entry["resolved"]:
                conclusion_statement += "The configured default is " + str(default_entry["guid"]) + "."
            else:
                conclusion_statement += "No resolvable configured default is available."
            conclusion_certainty = "unresolved"
    elif default_entry is not None and default_entry["resolved"]:
        conclusion_statement = (
            "BCD proves the configured default entry is "
            + str(default_entry["guid"])
            + _name_suffix(default_entry.get("name"))
            + "; it does not prove which entry was actually selected on the last boot."
        )
        conclusion_certainty = "configured_default"
    else:
        conclusion_statement = "BCD does not define a resolvable default entry; the actual last boot selection is not provable."
        conclusion_certainty = "unresolved"

    provable_claims = [claim["claim"] for claim in claims if claim["provable"]]
    unprovable_claims = [claim["claim"] for claim in claims if not claim["provable"]]
    conclusion = {
        "statement": conclusion_statement,
        "basis": selected_basis,
        "certainty": conclusion_certainty,
        "actual_selection_known": actual_selection_known,
        "actual_selection_guid": selected_entry.get("guid") if actual_selection_known and selected_entry else None,
        "selected_guid": selected_entry.get("guid") if selected_entry else None,
        "default_guid": default_entry.get("guid") if default_entry is not None else None,
        "provable_claims": provable_claims,
        "unprovable_claims": unprovable_claims,
        "caveats": (
            ["actual_last_selection_requires_an_observation"]
            if normalized_observation is None
            else ["observation_is_caller_supplied_single_boot_evidence"]
        ),
    }

    missing = _dedupe_missing(missing)
    observation_public = dict(normalized_observation) if normalized_observation is not None else None
    if observation_public is not None:
        observation_public["in_display_order"] = observation_in_display_order
        observation_public["display_order_manager_guids"] = [manager.guid for manager in observation_display_managers]

    return {
        "boot_manager": boot_manager_public,
        "boot_managers": boot_managers_public,
        "default_entry": default_entry,
        "default": default_entry,
        "default_entry_guid": default_entry["guid"] if default_entry is not None else None,
        "display_order": display_order,
        "display_order_entries": display_order,
        "display_order_guids": [entry["guid"] for entry in display_order],
        "display_order_manager_guid": boot_manager.guid if boot_manager is not None else None,
        "boot_sequence": boot_sequence,
        "observation": observation_public,
        "observed": observation_public,
        "observed_selection": observation_public,
        "selected_entry": selected_entry,
        "selection": selected_entry,
        "selected_entry_guid": selected_entry.get("guid") if selected_entry else None,
        "selection_path": selection_path,
        "objects": objects_public,
        "roles": roles_public,
        "missing_objects": missing,
        "missing_object_guids": [item["guid"] for item in missing if item.get("guid")],
        "claims": claims,
        "conclusion": conclusion,
        "conclusion_statement": conclusion_statement,
        "observed_selection_in_display_order": observation_in_display_order,
        "selection_context": {
            "boot_manager_guid": selection_context_manager.guid if selection_context_manager is not None else None,
            "display_order_source_key": selection_context_source,
            "display_order_manager_guids": [manager.guid for manager in observation_display_managers],
            "display_order": selection_context_display_order,
        },
        "actual_selection_known": actual_selection_known,
        "actual_selection_guid": selected_entry.get("guid") if actual_selection_known and selected_entry else None,
        "actual_selection": selected_entry if actual_selection_known else None,
        "certainty": conclusion_certainty,
        "source_key": selected_entry.get("source_key") if selected_entry else None,
        "source_keys": {
            "boot_manager": boot_manager_public["source_key"] if boot_manager_public else None,
            "default_entry": default_entry["source_key"] if default_entry else None,
            "display_order": display_source,
            "boot_sequence": boot_sequence_source,
            "observation": observation_public["source_key"] if observation_public else None,
            "selected_entry": selected_entry.get("source_key") if selected_entry else None,
            "selection_context": selection_context_source,
        },
    }


# Public aliases: the operation is naturally described as resolving, analyzing,
# or getting the selection path.
resolve_boot_selection = analyze_boot_selection
get_boot_selection = analyze_boot_selection
get_boot_selection_path = analyze_boot_selection
get_bcd_boot_selection = analyze_boot_selection
resolve_bcd_boot_selection = analyze_boot_selection


def read_bcd_roles(registry_hive: Any) -> list[dict[str, Any]]:
    """Return every BCD object with its decoded role and source key."""
    model = BcdModel.from_source(registry_hive)
    return [model.objects[guid].public() for guid in sorted(model.objects)]


get_bcd_roles = read_bcd_roles
load_bcd_roles = read_bcd_roles
