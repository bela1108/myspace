"""Layered comparison for registry security descriptors and NK references."""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import struct
from collections.abc import Iterable, Mapping
from typing import Any

from regipy.security_utils import convert_sid
from regipy.structs import REGF_HEADER_SIZE, SID, SECURITY_KEY_v1_1

REAL_CHANGE = "real_change"
EQUIVALENT_REREFERENCE = "equivalent_rereference"
NOT_COLLECTED = "not_collected"
UNCHANGED = "unchanged"
SECURITY_UNAVAILABLE = "security_unavailable"
KEY_ONLY_FIRST = "key_only_in_first"
KEY_ONLY_SECOND = "key_only_in_second"

_MISSING_OFFSETS = {0, 0xFFFFFFFF}


class ComparisonStatus(str):
    """String status that also compares equal to common spelling aliases."""

    _aliases: tuple[str, ...]

    def __new__(cls, value: str, aliases: Iterable[str] = ()) -> ComparisonStatus:
        obj = super().__new__(cls, value)
        obj._aliases = tuple(aliases)
        return obj

    @staticmethod
    def _normalize(value: object) -> str:
        return "".join(char for char in str(value).lower() if char.isalnum())

    def __eq__(self, other: object) -> bool:
        if isinstance(other, str):
            normalized = self._normalize(other)
            if self._normalize(self) == normalized:
                return True
            return any(self._normalize(alias) == normalized for alias in self._aliases)
        return NotImplemented

    def __hash__(self) -> int:
        return hash(str(self))


_STATUS_ALIASES = {
    REAL_CHANGE: ("security_changed", "descriptor_changed", "permission_changed"),
    EQUIVALENT_REREFERENCE: (
        "equivalent_re_reference",
        "reference_only",
        "reference_moved",
        "reference_swap",
    ),
    NOT_COLLECTED: ("uncollected", "missing_security_descriptor", "collection_gap"),
    SECURITY_UNAVAILABLE: ("parse_error", "security_reference_unavailable"),
    UNCHANGED: ("no_change", "same_security_descriptor"),
}

_ACE_TYPES = {
    0: "ACCESS_ALLOWED",
    1: "ACCESS_DENIED",
    2: "SYSTEM_AUDIT",
    3: "SYSTEM_ALARM",
    4: "ACCESS_ALLOWED_COMPOUND",
    5: "ACCESS_ALLOWED_OBJECT",
    6: "ACCESS_DENIED_OBJECT",
    7: "SYSTEM_AUDIT_OBJECT",
    8: "SYSTEM_ALARM_OBJECT",
    9: "ACCESS_ALLOWED_CALLBACK",
    10: "ACCESS_DENIED_CALLBACK",
    11: "ACCESS_ALLOWED_CALLBACK_OBJECT",
    12: "ACCESS_DENIED_CALLBACK_OBJECT",
    13: "13",
    14: "SYSTEM_ALARM_CALLBACK",
    15: "SYSTEM_AUDIT_CALLBACK_OBJECT",
    16: "SYSTEM_ALARM_CALLBACK_OBJECT",
}

_ACE_FLAGS = (
    ("OBJECT_INHERIT_ACE", 0x01),
    ("CONTAINER_INHERIT_ACE", 0x02),
    ("NO_PROPAGATE_INHERIT_ACE", 0x04),
    ("INHERIT_ONLY_ACE", 0x08),
)

_ACCESS_MASK_FLAGS = (
    ("DELETE", 0x00010000),
    ("READ_CONTROL", 0x00020000),
    ("WRITE_DAC", 0x00040000),
    ("WRITE_OWNER", 0x00080000),
    ("SYNCHRONIZE", 0x00100000),
    ("ACCESS_SYSTEM_SECURITY", 0x01000000),
    ("MAXIMUM_ALLOWED", 0x02000000),
    ("GENERIC_ALL", 0x10000000),
    ("GENERIC_EXECUTE", 0x20000000),
    ("GENERIC_WRITE", 0x40000000),
    ("GENERIC_READ", 0x80000000),
)

_CONTROL_FLAGS = (
    ("SE_OWNER_DEFAULTED", 0x0001),
    ("SE_GROUP_DEFAULTED", 0x0002),
    ("SE_DACL_PRESENT", 0x0004),
    ("SE_DACL_DEFAULTED", 0x0008),
    ("SE_SACL_PRESENT", 0x0010),
    ("SE_SACL_DEFAULTED", 0x0020),
    ("SE_DACL_AUTO_INHERIT_REQ", 0x0100),
    ("SE_SACL_AUTO_INHERIT_REQ", 0x0200),
    ("SE_DACL_AUTO_INHERITED", 0x0400),
    ("SE_SACL_AUTO_INHERITED", 0x0800),
    ("SE_DACL_PROTECTED", 0x1000),
    ("SE_SACL_PROTECTED", 0x2000),
    ("SE_RM_CONTROL_VALID", 0x4000),
    ("SE_SELF_RELATIVE", 0x8000),
)


def _flags_dict(value: int, flags: Iterable[tuple[str, int]]) -> dict[str, bool]:
    return {name: bool(value & bit) for name, bit in flags}


def _flag_names(value: int, flags: Iterable[tuple[str, int]]) -> list[str]:
    return [name for name, bit in flags if value & bit]


def _parse_sid_at(buffer: bytes, offset: int) -> str:
    sid = SID.parse(buffer[offset:])
    return convert_sid(sid)


def _parse_acl(buffer: bytes, offset: int) -> list[dict[str, Any]] | None:
    if not offset:
        return None
    if offset + 8 > len(buffer):
        raise ValueError(f"ACL offset {offset} is outside security descriptor")

    acl_size = struct.unpack_from("<H", buffer, offset + 2)[0]
    ace_count = struct.unpack_from("<H", buffer, offset + 4)[0]
    end = min(len(buffer), offset + acl_size) if acl_size else len(buffer)
    position = offset + 8
    aces: list[dict[str, Any]] = []

    for _ in range(ace_count):
        if position + 8 > end:
            raise ValueError("ACE header is outside ACL")
        ace_type_value = buffer[position]
        flags_value = buffer[position + 1]
        ace_size = struct.unpack_from("<H", buffer, position + 2)[0]
        access_mask_value = struct.unpack_from("<I", buffer, position + 4)[0]
        if ace_size < 8 or position + ace_size > end:
            raise ValueError(f"Invalid ACE size {ace_size} at offset {position}")

        sid = _parse_sid_at(buffer, position + 8)
        aces.append(
            {
                "ace_type": _ACE_TYPES.get(ace_type_value, str(ace_type_value)),
                "ace_type_value": ace_type_value,
                "flags": _flags_dict(flags_value, _ACE_FLAGS),
                "flags_names": _flag_names(flags_value, _ACE_FLAGS),
                "flags_value": flags_value,
                "access_mask": _flags_dict(access_mask_value, _ACCESS_MASK_FLAGS),
                "access_mask_names": _flag_names(access_mask_value, _ACCESS_MASK_FLAGS),
                "access_mask_value": access_mask_value,
                "sid": sid,
            }
        )
        position += ace_size

    return aces


def parse_security_descriptor(buffer: bytes) -> dict[str, Any]:
    """Parse a self-relative security descriptor into stable, comparable data."""
    if len(buffer) < 20:
        raise ValueError("Security descriptor is shorter than its fixed header")

    control_value = struct.unpack_from("<H", buffer, 2)[0]
    owner_offset = struct.unpack_from("<I", buffer, 4)[0]
    group_offset = struct.unpack_from("<I", buffer, 8)[0]
    sacl_offset = struct.unpack_from("<I", buffer, 12)[0]
    dacl_offset = struct.unpack_from("<I", buffer, 16)[0]

    return {
        "revision": buffer[0],
        "control_value": control_value,
        "control_flags": _flags_dict(control_value, _CONTROL_FLAGS),
        "control_flag_names": _flag_names(control_value, _CONTROL_FLAGS),
        "owner": _parse_sid_at(buffer, owner_offset) if owner_offset else None,
        "group": _parse_sid_at(buffer, group_offset) if group_offset else None,
        "sacl": _parse_acl(buffer, sacl_offset),
        "dacl": _parse_acl(buffer, dacl_offset),
    }


def stable_hash(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _raw_hash(buffer: bytes | None) -> str | None:
    return hashlib.sha256(buffer).hexdigest() if buffer is not None else None


def _json_safe(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    if isinstance(value, bytes):
        return value.hex()
    if hasattr(value, "items"):
        return {str(key): _json_safe(item) for key, item in value.items()}
    return value


def _missing_evidence(material: dict[str, Any], key_path: str | None, reason: str, present_in_hive: bool) -> dict[str, Any]:
    if reason == NOT_COLLECTED:
        collection_status = NOT_COLLECTED
    elif reason == KEY_ONLY_FIRST:
        collection_status = "key_absent_from_second_material"
    elif reason == KEY_ONLY_SECOND:
        collection_status = "key_absent_from_first_material"
    else:
        collection_status = reason
    return {
        "collected": False,
        "present_in_hive": present_in_hive,
        "collection_status": collection_status,
        "reason": reason,
        "material_role": material["role"],
        "material": material["name"],
        "hive_path": material.get("path"),
        "key_path": key_path,
        "locator": _locator(material.get("path"), key_path),
    }


def _locator(hive_path: str | None, key_path: str | None, offset: int | None = None) -> dict[str, Any]:
    locator: dict[str, Any] = {"hive_path": hive_path, "key_path": key_path}
    if offset is not None:
        locator["security_key_offset"] = offset
        locator["security_key_offset_hex"] = f"0x{offset:08x}"
    return locator


def _evidence_for_nk(nk: Any, key_path: str, material: dict[str, Any]) -> dict[str, Any]:
    header = getattr(nk, "header", None)
    raw_offset = getattr(header, "security_key_offset", None)
    security_offset = None if raw_offset is None else int(raw_offset)
    nk_offset = getattr(nk, "nk_offset", None)
    if nk_offset is not None:
        nk_offset = int(nk_offset)

    evidence: dict[str, Any] = {
        "collected": True,
        "present_in_hive": True,
        "collection_status": "collected",
        "material_role": material["role"],
        "material": material["name"],
        "hive_path": material.get("path"),
        "key_path": key_path,
        "nk_offset": nk_offset,
        "nk_offset_hex": f"0x{nk_offset:08x}" if nk_offset is not None else None,
        "security_key_offset": security_offset,
        "security_key_offset_hex": f"0x{security_offset:08x}" if security_offset is not None else None,
        "locator": _locator(material.get("path"), key_path, security_offset),
    }

    if security_offset is None or security_offset in _MISSING_OFFSETS:
        evidence.update(
            {
                "collected": False,
                "collection_status": NOT_COLLECTED,
                "reason": "security_descriptor_reference_absent",
                "semantic_sha256": None,
                "raw_sha256": None,
            }
        )
        return evidence

    stream = getattr(nk, "_stream", None)
    if stream is not None:
        absolute_offset = REGF_HEADER_SIZE + security_offset
        stream.seek(absolute_offset)
        security_key = SECURITY_KEY_v1_1.parse_stream(stream)  # type: ignore[union-attr]
        raw_descriptor = bytes(security_key.security_descriptor)
        semantic = parse_security_descriptor(raw_descriptor)
        evidence.update(
            {
                "security_descriptor_offset": security_offset + 24,
                "security_descriptor_offset_hex": f"0x{security_offset + 24:08x}",
                "security_key_cell_size": abs(int(getattr(security_key, "security_descriptor_size", 0)) + 24),
                "reference_count": int(security_key.reference_count),
                "previous_security_key_offset": int(security_key.prev_sk_offset),
                "next_security_key_offset": int(security_key.next_sk_offset),
                "security_descriptor_size": int(security_key.security_descriptor_size),
                "raw_sha256": _raw_hash(raw_descriptor),
                "semantic_sha256": stable_hash(semantic),
                "semantic_descriptor": semantic,
            }
        )
    else:
        compatible_info = _json_safe(nk.get_security_key_info())
        evidence.update(
            {
                "security_info": compatible_info,
                "semantic_sha256": stable_hash(compatible_info),
                "raw_sha256": None,
                "semantic_descriptor": compatible_info,
            }
        )

    with contextlib.suppress(Exception):
        evidence["security_info"] = _json_safe(nk.get_security_key_info())

    return evidence


def _iter_nk_records(hive: Any):
    def walk(nk: Any, path: str):
        yield path, nk
        children = nk.iter_subkeys()
        if not children:
            return
        for child in children:
            if not hasattr(child, "header") or not hasattr(child, "name"):
                continue

            separator = chr(92)
            if path == separator:
                child_path = separator + child.name
            else:
                child_path = path + separator + child.name
            yield from walk(child, child_path)

    yield from walk(hive.root, chr(92))


def _material_context(material: Any, role: str, name: str | None) -> dict[str, Any]:
    if material is None:
        return {
            "role": role,
            "name": name or f"{role}_material",
            "path": None,
            "hive": None,
            "collected": False,
        }

    if hasattr(material, "root") and hasattr(material, "header"):
        hive = material
        path = getattr(hive, "hive_path", None)
    else:
        from regipy.registry import RegistryHive

        path = os.fspath(material)
        hive = RegistryHive(path)

    return {
        "role": role,
        "name": name or (os.path.basename(path) if path else f"{role}_material"),
        "path": path,
        "hive": hive,
        "collected": True,
    }


def build_security_index(
    material: Any,
    role: str = "first",
    name: str | None = None,
    uncollected_keys: Iterable[str] | None = None,
) -> dict[str, Any]:
    """Collect key-level security references and shared-descriptor indexes."""
    context = _material_context(material, role, name)
    uncollected = {key.casefold() for key in (uncollected_keys or [])}
    if not context["collected"]:
        context.update({"evidence": {}, "reference_index": {}, "semantic_index": {}})
        return context

    evidence: dict[str, dict[str, Any]] = {}
    for key_path, nk in _iter_nk_records(context["hive"]):
        if key_path.casefold() in uncollected:
            item = _missing_evidence(context, key_path, NOT_COLLECTED, present_in_hive=True)
        else:
            try:
                item = _evidence_for_nk(nk, key_path, context)
            except Exception as exc:
                item = _missing_evidence(context, key_path, SECURITY_UNAVAILABLE, present_in_hive=True)
                item["collected"] = False
                item["reason"] = f"{type(exc).__name__}: {exc}"
        evidence[key_path] = item

    reference_index: dict[str, list[str]] = {}
    semantic_index: dict[str, list[str]] = {}
    for key_path, item in evidence.items():
        offset = item.get("security_key_offset")
        semantic_id = item.get("semantic_sha256")
        if item.get("collected") and offset not in _MISSING_OFFSETS and offset is not None:
            reference_index.setdefault(str(offset), []).append(key_path)
        if semantic_id:
            semantic_index.setdefault(semantic_id, []).append(key_path)

    for key_path, item in evidence.items():
        offset = item.get("security_key_offset")
        semantic_id = item.get("semantic_sha256")
        ref_keys = sorted(reference_index.get(str(offset), [])) if offset is not None else [key_path]
        sem_keys = sorted(semantic_index.get(semantic_id, [])) if semantic_id else [key_path]
        item["shared_reference_keys"] = ref_keys
        item["shared_semantic_keys"] = sem_keys
        item["reference_is_shared"] = len(ref_keys) > 1
        item["semantic_descriptor_is_shared"] = len(sem_keys) > 1

    context["evidence"] = evidence
    context["reference_index"] = reference_index
    context["semantic_index"] = semantic_index
    return context


def _case_key(key_path: str | None) -> str:
    return (key_path or chr(92)).casefold()


def _key_lookup(index: dict[str, Any]) -> dict[str, str]:
    return {_case_key(path): path for path in index.get("evidence", {})}


def _semantic_side(index: dict[str, Any], semantic_id: str) -> dict[str, Any]:
    paths = sorted(index.get("semantic_index", {}).get(semantic_id, []))
    evidence = index.get("evidence", {})
    offsets = sorted(
        {
            int(item["security_key_offset"])
            for item in (evidence.get(path) for path in paths)
            if item and item.get("security_key_offset") not in _MISSING_OFFSETS and item.get("security_key_offset") is not None
        }
    )
    reference_counts = sorted(
        {
            int(item["reference_count"])
            for item in (evidence.get(path) for path in paths)
            if item and item.get("reference_count") is not None
        }
    )
    descriptor = None
    if paths:
        descriptor = evidence[paths[0]].get("semantic_descriptor")
    return {
        "collected": bool(index.get("collected")),
        "keys": paths,
        "key_count": len(paths),
        "reference_locations": offsets,
        "reference_locations_hex": [f"0x{offset:08x}" for offset in offsets],
        "reference_counts": reference_counts,
        "semantic_descriptor": descriptor,
    }


def _build_descriptor_findings(first: dict[str, Any], second: dict[str, Any]) -> list[dict[str, Any]]:
    semantic_ids = set(first.get("semantic_index", {})) | set(second.get("semantic_index", {}))
    findings = []
    for semantic_id in sorted(semantic_ids):
        first_side = _semantic_side(first, semantic_id)
        second_side = _semantic_side(second, semantic_id)
        if first_side["keys"] and second_side["keys"]:
            status = "shared_semantic_descriptor"
        elif first_side["keys"]:
            status = "first_material_only"
        else:
            status = "second_material_only"
        findings.append(
            {
                "semantic_sha256": semantic_id,
                "semantic_id": semantic_id,
                "status": status,
                "classification": status,
                "first": first_side,
                "second": second_side,
            }
        )
    return findings


def _build_reference_layer(first: dict[str, Any], second: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for side in (first, second):
        evidence = side.get("evidence", {})
        for offset_text, paths in sorted(side.get("reference_index", {}).items(), key=lambda item: int(item[0])):
            offset = int(offset_text)
            sample = evidence[paths[0]] if paths else {}
            rows.append(
                {
                    "material_role": side["role"],
                    "material": side["name"],
                    "hive_path": side.get("path"),
                    "security_key_offset": offset,
                    "security_key_offset_hex": f"0x{offset:08x}",
                    "semantic_sha256": sample.get("semantic_sha256"),
                    "reference_count": sample.get("reference_count"),
                    "keys": sorted(paths),
                    "key_count": len(paths),
                }
            )
    return rows


def _acl_diff(first_descriptor: dict[str, Any], second_descriptor: dict[str, Any], field_name: str) -> dict[str, Any]:
    first_aces = first_descriptor.get(field_name) or []
    second_aces = second_descriptor.get(field_name) or []
    changes = []
    for index in range(max(len(first_aces), len(second_aces))):
        first_ace = first_aces[index] if index < len(first_aces) else None
        second_ace = second_aces[index] if index < len(second_aces) else None
        if first_ace != second_ace:
            changes.append({"index": index, "first": first_ace, "second": second_ace})
    return {
        "changed": bool(changes) or (first_descriptor.get(field_name) is None) != (second_descriptor.get(field_name) is None),
        "first_count": len(first_aces),
        "second_count": len(second_aces),
        "ace_changes": changes,
    }


def _semantic_differences(first_evidence: dict[str, Any], second_evidence: dict[str, Any]) -> dict[str, Any] | None:
    first_descriptor = first_evidence.get("semantic_descriptor")
    second_descriptor = second_evidence.get("semantic_descriptor")
    if not isinstance(first_descriptor, Mapping) or not isinstance(second_descriptor, Mapping):
        return None

    differences: dict[str, Any] = {}
    for field_name in ("revision", "control_value", "owner", "group"):
        first_value = first_descriptor.get(field_name)
        second_value = second_descriptor.get(field_name)
        if first_value != second_value:
            differences[field_name] = {"first": first_value, "second": second_value}

    for acl_name in ("dacl", "sacl"):
        acl_difference = _acl_diff(first_descriptor, second_descriptor, acl_name)
        if acl_difference["changed"]:
            differences[acl_name] = acl_difference

    return differences or None


def _pick_option(options: dict[str, Any], primary: str, aliases: Iterable[str], default: Any = None) -> Any:
    if primary in options:
        return options.pop(primary)
    for alias in aliases:
        if alias in options:
            return options.pop(alias)
    return default


def _public_index(index: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in index.items() if key != "hive"}


def _category_for(conclusion: str) -> str:
    categories = {
        REAL_CHANGE: "semantic_descriptor_change",
        EQUIVALENT_REREFERENCE: "reference_location_only",
        NOT_COLLECTED: "collection_gap",
        SECURITY_UNAVAILABLE: "parse_or_reference_error",
        UNCHANGED: "no_change",
        KEY_ONLY_FIRST: "key_present_only_in_first_material",
        KEY_ONLY_SECOND: "key_present_only_in_second_material",
    }
    return categories.get(conclusion, conclusion)


def _offset(evidence: dict[str, Any] | None) -> int | None:
    if not evidence:
        return None
    offset = evidence.get("security_key_offset")
    return None if offset is None else int(offset)


def _pair_conclusion(
    first_index: dict[str, Any],
    second_index: dict[str, Any],
    first_path: str | None,
    second_path: str | None,
    first_evidence: dict[str, Any],
    second_evidence: dict[str, Any],
) -> str:
    if first_path is None or second_path is None:
        if not first_index.get("collected", True) or not second_index.get("collected", True):
            return NOT_COLLECTED
        if first_path is None:
            return KEY_ONLY_SECOND
        return KEY_ONLY_FIRST

    first_status = first_evidence.get("collection_status")
    second_status = second_evidence.get("collection_status")
    if first_status == NOT_COLLECTED or second_status == NOT_COLLECTED:
        return NOT_COLLECTED
    if not first_evidence.get("collected", True) or not second_evidence.get("collected", True):
        return SECURITY_UNAVAILABLE

    first_semantic = first_evidence.get("semantic_sha256")
    second_semantic = second_evidence.get("semantic_sha256")
    if first_semantic != second_semantic:
        return REAL_CHANGE
    if _offset(first_evidence) != _offset(second_evidence):
        return EQUIVALENT_REREFERENCE
    return UNCHANGED


def _make_key_finding(
    key_path: str,
    first_path: str | None,
    second_path: str | None,
    conclusion: str,
    first_evidence: dict[str, Any],
    second_evidence: dict[str, Any],
) -> dict[str, Any]:
    semantic_equal: bool | None = None
    raw_equal: bool | None = None
    reference_equal: bool | None = None
    semantic_differences = None

    if conclusion in (REAL_CHANGE, EQUIVALENT_REREFERENCE, UNCHANGED):
        semantic_equal = first_evidence.get("semantic_sha256") == second_evidence.get("semantic_sha256")
        raw_equal = first_evidence.get("raw_sha256") == second_evidence.get("raw_sha256")
        reference_equal = _offset(first_evidence) == _offset(second_evidence)
        if conclusion == REAL_CHANGE:
            semantic_differences = _semantic_differences(first_evidence, second_evidence)

    status = ComparisonStatus(conclusion, _STATUS_ALIASES.get(conclusion, ()))

    finding = {
        "key_path": key_path,
        "first_key_path": first_path,
        "second_key_path": second_path,
        "status": status,
        "conclusion": status,
        "classification": status,
        "result": status,
        "state": status,
        "category": _category_for(conclusion),
        "semantic_equal": semantic_equal,
        "raw_descriptor_equal": raw_equal,
        "reference_location_equal": reference_equal,
        "reference_relation": "same_location" if reference_equal else None,
        "is_reference_swap": False,
        "swap_partner_key": None,
        "swap_partner_keys": [],
        "real_change": conclusion == REAL_CHANGE,
        "equivalent_rereference": conclusion == EQUIVALENT_REREFERENCE,
        "equivalent_re_reference": conclusion == EQUIVALENT_REREFERENCE,
        "not_collected": conclusion == NOT_COLLECTED,
        "uncollected": conclusion == NOT_COLLECTED,
        "unchanged": conclusion == UNCHANGED,
        "first": first_evidence,
        "second": second_evidence,
        "evidence": {"first": first_evidence, "second": second_evidence},
        "citations": [first_evidence.get("locator"), second_evidence.get("locator")],
        "semantic_differences": semantic_differences,
    }
    return finding


def compare_security_descriptors(first_hive: Any = None, second_hive: Any = None, **options: Any) -> dict[str, Any]:
    """Compare security descriptors semantically and by NK/SK reference location."""
    first_material = first_hive
    if first_material is None:
        first_material = _pick_option(
            options,
            "first_hive_path",
            ("first_path", "first_snapshot", "old_hive", "hive1", "first_material"),
            None,
        )
    second_material = second_hive
    if second_material is None:
        second_material = _pick_option(
            options,
            "second_hive_path",
            ("second_path", "second_snapshot", "new_hive", "hive2", "second_material"),
            None,
        )

    first_name = _pick_option(options, "first_name", ("first_label", "first_material_name", "old_name"), None)
    second_name = _pick_option(options, "second_name", ("second_label", "second_material_name", "new_name"), None)
    material_names = options.pop("material_names", None) or options.pop("names", None)
    if material_names:
        first_name = first_name or material_names[0]
        second_name = second_name or material_names[1]

    common_uncollected = options.pop("uncollected_keys", None) or options.pop("not_collected_keys", None)
    first_uncollected = (
        options.pop("first_uncollected_keys", None) or options.pop("first_not_collected_keys", None) or common_uncollected
    )
    second_uncollected = (
        options.pop("second_uncollected_keys", None) or options.pop("second_not_collected_keys", None) or common_uncollected
    )
    include_unchanged = options.pop("include_unchanged", True)
    include_descriptor_details = options.pop("include_descriptor_details", True)
    options.pop("verbose", None)

    first_index = build_security_index(first_material, "first", first_name, first_uncollected)
    second_index = build_security_index(second_material, "second", second_name, second_uncollected)

    first_lookup = _key_lookup(first_index)
    second_lookup = _key_lookup(second_index)
    case_keys = set(first_lookup) | set(second_lookup)
    findings: list[dict[str, Any]] = []

    for case_key in sorted(case_keys):
        first_path = first_lookup.get(case_key)
        second_path = second_lookup.get(case_key)
        key_path = first_path or second_path or chr(92)

        if first_path is None:
            reason = NOT_COLLECTED if not first_index.get("collected") else KEY_ONLY_SECOND
            first_evidence = _missing_evidence(first_index, second_path, reason, present_in_hive=False)
        else:
            first_evidence = first_index["evidence"][first_path]

        if second_path is None:
            reason = NOT_COLLECTED if not second_index.get("collected") else KEY_ONLY_FIRST
            second_evidence = _missing_evidence(second_index, first_path, reason, present_in_hive=False)
        else:
            second_evidence = second_index["evidence"][second_path]

        conclusion = _pair_conclusion(
            first_index,
            second_index,
            first_path,
            second_path,
            first_evidence,
            second_evidence,
        )
        findings.append(
            _make_key_finding(
                key_path,
                first_path,
                second_path,
                conclusion,
                first_evidence,
                second_evidence,
            )
        )

    pair_index: dict[tuple[int | None, int | None], list[str]] = {}
    for finding in findings:
        if finding["conclusion"] == EQUIVALENT_REREFERENCE:
            pair = (_offset(finding["first"]), _offset(finding["second"]))
            pair_index.setdefault(pair, []).append(finding["key_path"])

    swap_count = 0
    for finding in findings:
        if finding["conclusion"] != EQUIVALENT_REREFERENCE:
            continue
        first_offset = _offset(finding["first"])
        second_offset = _offset(finding["second"])
        partners = [path for path in pair_index.get((second_offset, first_offset), []) if path != finding["key_path"]]
        if partners:
            finding["reference_relation"] = "swapped"
            finding["is_reference_swap"] = True
            finding["swap_partner_keys"] = sorted(partners)
            finding["swap_partner_key"] = sorted(partners)[0]
            swap_count += 1
        else:
            finding["reference_relation"] = "moved"

    descriptor_findings = _build_descriptor_findings(first_index, second_index)
    reference_layer = _build_reference_layer(first_index, second_index)

    summary = {
        "total_key_findings": len(findings),
        "real_change": sum(item["conclusion"] == REAL_CHANGE for item in findings),
        "equivalent_rereference": sum(item["conclusion"] == EQUIVALENT_REREFERENCE for item in findings),
        "equivalent_reference_swap": swap_count,
        "unchanged": sum(item["conclusion"] == UNCHANGED for item in findings),
        "not_collected": sum(item["conclusion"] == NOT_COLLECTED for item in findings),
        "security_unavailable": sum(item["conclusion"] == SECURITY_UNAVAILABLE for item in findings),
        "key_only_in_first": sum(item["conclusion"] == KEY_ONLY_FIRST for item in findings),
        "key_only_in_second": sum(item["conclusion"] == KEY_ONLY_SECOND for item in findings),
        "shared_semantic_descriptors": sum(item["status"] == "shared_semantic_descriptor" for item in descriptor_findings),
        "reference_location_records": len(reference_layer),
    }
    summary.update(
        {
            "real_changes": summary["real_change"],
            "equivalent_rereferences": summary["equivalent_rereference"],
            "uncollected": summary["not_collected"],
            "reference_swaps": summary["equivalent_reference_swap"],
        }
    )

    visible_findings = findings if include_unchanged else [item for item in findings if item["conclusion"] != UNCHANGED]
    materials = [
        {
            "role": index["role"],
            "name": index["name"],
            "hive_path": index.get("path"),
            "collected": index.get("collected", False),
            "key_count": len(index.get("evidence", {})),
        }
        for index in (first_index, second_index)
    ]

    report = {
        "schema_version": "1.0",
        "materials": materials,
        "first_material": _public_index(first_index),
        "second_material": _public_index(second_index),
        "summary": summary,
        "key_findings": visible_findings,
        "all_key_findings": findings,
        "keys": visible_findings,
        "key_comparisons": visible_findings,
        "findings": visible_findings,
        "descriptor_findings": descriptor_findings,
        "descriptor_comparisons": descriptor_findings,
        "descriptors": descriptor_findings,
        "semantic_layer": descriptor_findings,
        "reference_layer": reference_layer,
        "reference_location_findings": reference_layer,
        "reference_locations": reference_layer,
    }

    if not include_descriptor_details:
        for finding in findings:
            for side_name in ("first", "second"):
                side = finding.get(side_name) or {}
                side.pop("semantic_descriptor", None)
                side.pop("security_info", None)
        for descriptor in descriptor_findings:
            descriptor.get("first", {}).pop("semantic_descriptor", None)
            descriptor.get("second", {}).pop("semantic_descriptor", None)

    return _json_safe(report)


compare_security = compare_security_descriptors
compare_hive_security = compare_security_descriptors
compare_security_keys = compare_security_descriptors
compare_security_references = compare_security_descriptors
compare_hive_security_descriptors = compare_security_descriptors
compare_security_descriptor_references = compare_security_descriptors


def render_security_report(report, output_format="markdown"):
    output_format = (output_format or "markdown").lower()
    if output_format in ("json", "application/json"):
        return json.dumps(report, indent=2, ensure_ascii=False, default=str)
    if output_format in ("dict", "object"):
        return report

    lines = ["# Security descriptor comparison", ""]
    lines.append("Materials:")
    for material in report.get("materials", []):
        status = "collected" if material.get("collected") else "not collected"
        lines.append(f"- {material.get('role')}: {material.get('name')} [{status}] {material.get('hive_path') or ''}")
    lines.append("")
    summary = report.get("summary", {})
    lines.append("Summary: " + ", ".join(f"{key}={value}" for key, value in sorted(summary.items()) if isinstance(value, int)))
    lines.append("")
    lines.append("| Key | Conclusion | Semantic equal | Reference equal | First SK | Second SK |")
    lines.append("| --- | --- | --- | --- | --- | --- |")
    for finding in report.get("key_findings", []):
        first_offset = (finding.get("first") or {}).get("security_key_offset_hex")
        second_offset = (finding.get("second") or {}).get("security_key_offset_hex")
        lines.append(
            "| {key} | {conclusion} | {semantic_equal} | {reference_location_equal} | {first_offset} | {second_offset} |".format(
                key=finding.get("key_path"),
                conclusion=finding.get("conclusion"),
                semantic_equal=finding.get("semantic_equal"),
                reference_location_equal=finding.get("reference_location_equal"),
                first_offset=first_offset or "-",
                second_offset=second_offset or "-",
            )
        )
    return "\n".join(lines)


def format_security_report(report, output_format="markdown"):
    return render_security_report(report, output_format)


def generate_security_report(*args, **options):
    return compare_security_descriptors(*args, **options)


build_security_report = generate_security_report


def security_report_to_differences(report):
    type_by_conclusion = {
        REAL_CHANGE: "security_descriptor_changed",
        EQUIVALENT_REREFERENCE: "security_reference_rereferenced",
        NOT_COLLECTED: "security_descriptor_not_collected",
        SECURITY_UNAVAILABLE: "security_descriptor_unavailable",
        KEY_ONLY_FIRST: "key_only_in_first_hive",
        KEY_ONLY_SECOND: "key_only_in_second_hive",
    }
    rows = []
    for finding in report.get("key_findings", []):
        conclusion = finding.get("conclusion")
        if conclusion == UNCHANGED or conclusion in (KEY_ONLY_FIRST, KEY_ONLY_SECOND):
            continue
        difference_type = type_by_conclusion.get(conclusion)
        if difference_type is None:
            continue
        first = finding.get("first") or {}
        second = finding.get("second") or {}
        rows.append(
            (
                difference_type,
                json.dumps(_evidence_brief(first), sort_keys=True, default=str),
                json.dumps(_evidence_brief(second), sort_keys=True, default=str),
                finding.get("key_path"),
            )
        )
    return rows


def _evidence_brief(evidence):
    return {
        "material": evidence.get("material"),
        "hive_path": evidence.get("hive_path"),
        "key_path": evidence.get("key_path"),
        "collected": evidence.get("collected"),
        "collection_status": evidence.get("collection_status"),
        "nk_offset_hex": evidence.get("nk_offset_hex"),
        "security_key_offset_hex": evidence.get("security_key_offset_hex"),
        "semantic_sha256": evidence.get("semantic_sha256"),
        "raw_sha256": evidence.get("raw_sha256"),
    }
