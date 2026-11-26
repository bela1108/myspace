#!/usr/bin/env python3
"""Offline PE-header observations matched against a delivery contract."""

import argparse
import csv
import hashlib
import json
import struct
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import pefile


ROOT = Path(__file__).resolve().parent
ACCEPTANCE_DIR = ROOT / "acceptance"
DEFAULT_CONTRACT = ACCEPTANCE_DIR / "offline-delivery-contract.json"
DEFAULT_INVENTORY = ACCEPTANCE_DIR / "inventory.csv"
DEFAULT_BATCHES = ACCEPTANCE_DIR / "sealed-batches.json"
DEFAULT_RECEIPT = ACCEPTANCE_DIR / "narrow-receipt.json"
DEFAULT_JSON_REPORT = ACCEPTANCE_DIR / "delivery-audit-report.json"
DEFAULT_MD_REPORT = ACCEPTANCE_DIR / "DELIVERY_REPORT.md"

MAGIC_NAMES = {0x10B: "PE32", 0x20B: "PE32+"}
MACHINE_ARCHITECTURES = {0x014C: "x86", 0x8664: "x64", 0xAA64: "arm64"}
TICK = chr(96)


def code(value: Any) -> str:
    return TICK + str(value) + TICK


def display_value(value: Any) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False)


def parse_version(value: Any) -> Tuple[int, ...]:
    if value is None:
        return ()
    parts: List[int] = []
    for raw_part in str(value).strip().split("."):
        digits = "".join(ch for ch in raw_part if ch.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts)


def version_at_least(actual: Any, minimum: Any) -> bool:
    actual_parts = parse_version(actual)
    minimum_parts = parse_version(minimum)
    width = max(len(actual_parts), len(minimum_parts), 1)
    actual_padded = actual_parts + (0,) * (width - len(actual_parts))
    minimum_padded = minimum_parts + (0,) * (width - len(minimum_parts))
    return actual_padded >= minimum_padded


def version_text(major: int, minor: int) -> str:
    return f"{int(major)}.{int(minor)}"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_json(path: Path) -> Dict[str, Any]:
    with Path(path).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def load_inventory(path: Path) -> List[Dict[str, str]]:
    with Path(path).open("r", encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def decode_flag_names(value: int, mapping: Dict[int, str]) -> List[str]:
    names = []
    bit_names = [(bit, name) for bit, name in mapping.items() if isinstance(bit, int)]
    for bit, name in sorted(bit_names):
        if bit and value & bit == bit:
            names.append(name)
    return names


def inspect_pe(path: Path) -> Dict[str, Any]:
    path = Path(path)
    data = path.read_bytes()
    pe = pefile.PE(data=data, fast_load=True)
    file_header = pe.FILE_HEADER
    optional_header = pe.OPTIONAL_HEADER

    machine_code = int(file_header.Machine)
    subsystem_code = int(optional_header.Subsystem)
    magic_code = int(optional_header.Magic)
    characteristics = int(file_header.Characteristics)
    dll_characteristics = int(getattr(optional_header, "DllCharacteristics", 0))

    machine_name = pefile.MACHINE_TYPE.get(
        machine_code, f"IMAGE_FILE_MACHINE_UNKNOWN_0x{machine_code:04X}"
    )
    subsystem_name = pefile.SUBSYSTEM_TYPE.get(
        subsystem_code, f"IMAGE_SUBSYSTEM_UNKNOWN_{subsystem_code}"
    )
    magic_name = MAGIC_NAMES.get(magic_code, f"UNKNOWN_MAGIC_0x{magic_code:04X}")
    subsystem_version = version_text(
        optional_header.MajorSubsystemVersion, optional_header.MinorSubsystemVersion
    )
    image_version = version_text(
        optional_header.MajorImageVersion, optional_header.MinorImageVersion
    )
    operating_system_version = version_text(
        optional_header.MajorOperatingSystemVersion,
        optional_header.MinorOperatingSystemVersion,
    )
    linker_version = version_text(
        optional_header.MajorLinkerVersion, optional_header.MinorLinkerVersion
    )
    characteristic_names = decode_flag_names(
        characteristics, pefile.IMAGE_CHARACTERISTICS
    )
    dll_characteristic_names = decode_flag_names(
        dll_characteristics, pefile.DLL_CHARACTERISTICS
    )

    header_values = {
        "Machine": machine_name,
        "Magic": magic_name,
        "Architecture": MACHINE_ARCHITECTURES.get(machine_code, "unknown"),
        "NumberOfSections": int(file_header.NumberOfSections),
        "TimeDateStamp": int(file_header.TimeDateStamp),
        "Characteristics": characteristic_names,
        "Subsystem": subsystem_name,
        "SubsystemVersion": subsystem_version,
        "ImageVersion": image_version,
        "OperatingSystemVersion": operating_system_version,
        "LinkerVersion": linker_version,
        "Win32VersionValue": int(getattr(optional_header, "Win32VersionValue", 0)),
        "SizeOfImage": int(optional_header.SizeOfImage),
        "SizeOfHeaders": int(optional_header.SizeOfHeaders),
        "CheckSum": int(optional_header.CheckSum),
        "SectionAlignment": int(optional_header.SectionAlignment),
        "FileAlignment": int(optional_header.FileAlignment),
        "DllCharacteristics": dll_characteristic_names,
        "LoaderFlags": int(getattr(optional_header, "LoaderFlags", 0)),
    }

    return {
        "file_name": path.name,
        "file_size": len(data),
        "sha256": sha256_bytes(data),
        "machine": {
            "code": machine_code,
            "hex": f"0x{machine_code:04X}",
            "name": machine_name,
            "architecture": MACHINE_ARCHITECTURES.get(machine_code, "unknown"),
        },
        "magic": {"code": magic_code, "hex": f"0x{magic_code:04X}", "name": magic_name},
        "subsystem": {"code": subsystem_code, "name": subsystem_name},
        "subsystem_version": subsystem_version,
        "image_version": image_version,
        "image_declaration": {
            "magic": magic_name,
            "image_version": image_version,
            "executable_image": "IMAGE_FILE_EXECUTABLE_IMAGE" in characteristic_names,
            "characteristics": characteristic_names,
        },
        "old_contract_uncovered_fields": {
            "linker_version": linker_version,
            "time_date_stamp": int(file_header.TimeDateStamp),
            "number_of_sections": int(file_header.NumberOfSections),
            "checksum": int(optional_header.CheckSum),
            "dll_characteristics": dll_characteristic_names,
            "section_alignment": int(optional_header.SectionAlignment),
            "file_alignment": int(optional_header.FileAlignment),
            "size_of_image": int(optional_header.SizeOfImage),
            "loader_flags": int(getattr(optional_header, "LoaderFlags", 0)),
        },
        "header_values": header_values,
    }


def make_check(
    check_id: str,
    topic: str,
    clause_id: Optional[str],
    passed: bool,
    expected: Any,
    actual: Any,
    detail: str = "",
) -> Dict[str, Any]:
    return {
        "check_id": check_id,
        "topic": topic,
        "clause_id": clause_id,
        "status": "pass" if passed else "fail",
        "expected": expected,
        "actual": actual,
        "detail": detail,
    }


def filter_inventory(
    inventory: Iterable[Dict[str, str]], contract: Dict[str, Any]
) -> Tuple[Dict[str, Dict[str, str]], List[Dict[str, Any]]]:
    product_rules = {
        str(item["name"]).casefold(): item for item in contract.get("products", [])
    }
    by_id: Dict[str, Dict[str, str]] = {}
    report: List[Dict[str, Any]] = []

    for row in inventory:
        inventory_id = row.get("inventory_id", "")
        product_name = row.get("product_name", "")
        product_version = row.get("product_version", "")
        rule = product_rules.get(product_name.casefold())
        if rule is None:
            status, reason = "excluded", "product_name_not_in_contract"
        elif not version_at_least(product_version, rule.get("minimum_version", "0")):
            status, reason = "excluded", "below_version_floor"
        else:
            status, reason = "eligible", ""
            by_id[inventory_id] = row
        report.append(
            {
                "inventory_id": inventory_id,
                "product_name": product_name,
                "product_version": product_version,
                "status": status,
                "reason": reason,
                "minimum_version": None if rule is None else rule.get("minimum_version"),
            }
        )
    return by_id, report


def receipt_index(receipt: Optional[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    if not receipt:
        return {}
    entries = receipt.get("accepted_batches", receipt.get("entries", []))
    return {str(entry.get("batch_id")): entry for entry in entries}


def receipt_value_checks(
    entry: Dict[str, Any], observation: Dict[str, Any]
) -> List[Dict[str, Any]]:
    checks = []
    for key, expected in entry.get("recorded_values", {}).items():
        if key == "machine":
            actual = observation["machine"]["name"]
        elif key == "subsystem":
            actual = observation["subsystem"]["name"]
        elif key == "subsystem_version":
            actual = observation["subsystem_version"]
        elif key == "image_version":
            actual = observation["image_version"]
        elif key == "magic":
            actual = observation["magic"]["name"]
        else:
            actual = observation["header_values"].get(key)
        checks.append(
            make_check(
                f"receipt-value-{key}", f"签收单记录值 {key}", None,
                actual == expected, expected, actual
            )
        )
    return checks


def evaluate_batch(
    batch: Dict[str, Any],
    inventory_by_id: Dict[str, Dict[str, str]],
    contract: Dict[str, Any],
    receipt_entries: Dict[str, Dict[str, Any]],
    base_dir: Path,
) -> Dict[str, Any]:
    batch_id = batch.get("batch_id", "UNKNOWN-BATCH")
    inventory_id = batch.get("inventory_id", "")
    provenance = {
        "inventory_id": inventory_id,
        "batch_id": batch_id,
        "seal_id": batch.get("seal_id"),
        "sealed_at": batch.get("sealed_at"),
        "sealed_source": batch.get("source"),
    }
    result: Dict[str, Any] = {
        "batch_id": batch_id,
        "inventory_id": inventory_id,
        "provenance": provenance,
        "checks": [],
        "errors": [],
        "decision": "hold",
        "hold_reasons": [],
    }

    inventory_row = inventory_by_id.get(inventory_id)
    if inventory_row is None:
        result["errors"].append("inventory row is absent or filtered by name/version")
        result["hold_reasons"].append("inventory_not_eligible")
    else:
        result["product_name"] = inventory_row.get("product_name")
        result["product_version"] = inventory_row.get("product_version")

    artifact_reference = Path(batch.get("artifact", ""))
    artifact_path = artifact_reference
    if not artifact_path.is_absolute():
        artifact_path = base_dir / artifact_path
    result["artifact_path"] = str(artifact_reference)

    observation = None
    if not artifact_path.is_file():
        result["errors"].append(f"artifact not found: {artifact_reference}")
        result["hold_reasons"].append("artifact_missing")
    else:
        try:
            observation = inspect_pe(artifact_path)
            result["pe_observation"] = observation
        except Exception as exc:
            result["errors"].append(f"PE parse failed: {type(exc).__name__}: {exc}")
            result["hold_reasons"].append("pe_parse_failed")

    if observation is not None:
        expected_sha = batch.get("sealed_sha256")
        if expected_sha:
            result["checks"].append(
                make_check(
                    "seal-hash", "封存哈希", None,
                    observation["sha256"].lower() == str(expected_sha).lower(),
                    expected_sha, observation["sha256"],
                    "hash mismatch indicates post-seal change",
                )
            )

        machine_rule = contract.get("machine", {})
        machine_name = observation["machine"]["name"]
        result["checks"].append(
            make_check(
                "machine-type", "机器类型", machine_rule.get("clause_id"),
                machine_name in machine_rule.get("allowed", []),
                machine_rule.get("allowed", []), machine_name,
            )
        )

        subsystem_rule = contract.get("subsystem", {})
        subsystem_name = observation["subsystem"]["name"]
        subsystem_ok = (
            subsystem_name in subsystem_rule.get("allowed", [])
            and version_at_least(
                observation["subsystem_version"],
                subsystem_rule.get("minimum_version", "0"),
            )
        )
        result["checks"].append(
            make_check(
                "subsystem-version", "子系统与版本",
                subsystem_rule.get("clause_id"), subsystem_ok,
                {
                    "allowed": subsystem_rule.get("allowed", []),
                    "minimum_version": subsystem_rule.get("minimum_version"),
                },
                {
                    "subsystem": subsystem_name,
                    "version": observation["subsystem_version"],
                },
            )
        )

        image_rule = contract.get("image_declaration", {})
        expected_magic = image_rule.get("architecture_magic", {}).get(machine_name)
        image_version_ok = version_at_least(
            observation["image_version"],
            image_rule.get("minimum_image_version", "0"),
        )
        executable_ok = (
            not image_rule.get("require_executable_image", False)
            or observation["image_declaration"]["executable_image"]
        )
        magic_ok = expected_magic in (None, observation["magic"]["name"])
        result["checks"].append(
            make_check(
                "image-declaration", "映像声明", image_rule.get("clause_id"),
                image_version_ok and executable_ok and magic_ok,
                {
                    "minimum_image_version": image_rule.get("minimum_image_version"),
                    "magic": expected_magic,
                    "executable_image": image_rule.get("require_executable_image"),
                },
                observation["image_declaration"],
            )
        )

    receipt_entry = receipt_entries.get(batch_id)
    if receipt_entry is None:
        result["hold_reasons"].append("not_listed_in_narrow_receipt")
    else:
        result["receipt"] = {
            "receipt_id": receipt_entry.get("receipt_id"),
            "attested_fields": receipt_entry.get("attested_fields", []),
        }
        if observation is not None:
            result["checks"].extend(receipt_value_checks(receipt_entry, observation))

    if any(check["status"] == "fail" for check in result["checks"]):
        result["hold_reasons"].append("contract_check_failed")
    if not result["hold_reasons"]:
        result["decision"] = "ready_to_accept"
    return result


def build_provenance_groups(batch_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    groups: Dict[str, Dict[str, Any]] = {}
    for result in batch_results:
        observation = result.get("pe_observation")
        if observation is None:
            continue
        signature = json.dumps(
            observation["header_values"], sort_keys=True, ensure_ascii=False
        )
        group = groups.setdefault(
            signature,
            {
                "header_signature": sha256_bytes(signature.encode("utf-8")),
                "header_values": observation["header_values"],
                "artifacts": [],
                "provenance": [],
            },
        )
        group["provenance"].append(result["provenance"])
        group["artifacts"].append(
            {
                "batch_id": result["batch_id"],
                "file_name": observation["file_name"],
                "sha256": observation["sha256"],
            }
        )
    return list(groups.values())


def build_field_provenance(batch_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    index: Dict[str, Dict[str, Dict[str, Any]]] = {}
    for result in batch_results:
        observation = result.get("pe_observation")
        if observation is None:
            continue
        for field_name, field_value in observation["header_values"].items():
            value_key = json.dumps(field_value, sort_keys=True, ensure_ascii=False)
            field_index = index.setdefault(field_name, {})
            entry = field_index.setdefault(
                value_key,
                {"field": field_name, "value": field_value, "provenance": []},
            )
            entry["provenance"].append(result["provenance"])

    groups = []
    for values in index.values():
        for entry in values.values():
            entry["source_count"] = len(entry["provenance"])
            groups.append(entry)
    return groups


def evaluate_evidence_requirements(
    contract: Dict[str, Any], evidence: Optional[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    evidence = evidence or {}
    results = []
    for requirement in contract.get("evidence_requirements", []):
        if requirement.get("pe_observable", False):
            continue
        key = requirement.get("evidence_key")
        records = evidence.get(key)
        results.append(
            {
                "clause_id": requirement.get("clause_id"),
                "title": requirement.get("title"),
                "evidence_key": key,
                "status": "verified" if records else "unverifiable",
                "reason": "" if records else "required offline evidence is absent",
            }
        )
    return results


def run_audit(
    contract_path: Path = DEFAULT_CONTRACT,
    inventory_path: Path = DEFAULT_INVENTORY,
    batches_path: Path = DEFAULT_BATCHES,
    receipt_path: Optional[Path] = DEFAULT_RECEIPT,
    evidence_path: Optional[Path] = None,
    base_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    contract_path = Path(contract_path)
    contract = load_json(contract_path)
    inventory = load_inventory(Path(inventory_path))
    batches_document = load_json(Path(batches_path))
    receipt = (
        load_json(Path(receipt_path))
        if receipt_path and Path(receipt_path).exists()
        else None
    )
    evidence = (
        load_json(Path(evidence_path))
        if evidence_path and Path(evidence_path).exists()
        else None
    )
    base_dir = Path(base_dir) if base_dir else contract_path.parent

    inventory_by_id, inventory_filter = filter_inventory(inventory, contract)
    receipt_entries = receipt_index(receipt)
    if receipt is not None:
        for entry in receipt_entries.values():
            entry.setdefault("receipt_id", receipt.get("receipt_id"))

    batch_results = [
        evaluate_batch(batch, inventory_by_id, contract, receipt_entries, base_dir)
        for batch in batches_document.get("batches", [])
    ]
    external_clauses = evaluate_evidence_requirements(contract, evidence)
    holds = [
        {"batch_id": item["batch_id"], "reasons": item["hold_reasons"], "errors": item["errors"]}
        for item in batch_results
        if item["decision"] == "hold"
    ]
    unverifiable = [item for item in external_clauses if item["status"] == "unverifiable"]

    return {
        "contract_id": contract.get("contract_id"),
        "old_contract_id": contract.get("old_contract", {}).get("contract_id"),
        "receipt_id": receipt.get("receipt_id") if receipt else None,
        "inventory_filter": inventory_filter,
        "batches": batch_results,
        "provenance_groups": build_provenance_groups(batch_results),
        "field_provenance": build_field_provenance(batch_results),
        "external_clause_checks": external_clauses,
        "holds": holds,
        "unverifiable_clauses": unverifiable,
        "summary": {
            "batch_count": len(batch_results),
            "ready_to_accept": sum(x["decision"] == "ready_to_accept" for x in batch_results),
            "hold_count": len(holds),
            "unverifiable_clause_count": len(unverifiable),
        },
    }


def render_markdown(report: Dict[str, Any]) -> str:
    lines = ["# 离线交付 PE 头部核对报告", ""]
    lines.append(f"- 交付合同：{code(report.get('contract_id'))}")
    lines.append(f"- 旧合同：{code(report.get('old_contract_id'))}")
    lines.append(f"- 签收单：{code(report.get('receipt_id'))}")
    summary = report["summary"]
    lines.append(
        f"- 批次结论：{summary['ready_to_accept']} 批可签收，"
        f"{summary['hold_count']} 批暂停；"
        f"{summary['unverifiable_clause_count']} 条合同外部证据无法核到。"
    )
    lines.append("")

    if report["holds"]:
        names = "、".join(code(item["batch_id"]) for item in report["holds"])
        lines.append(f"**暂停收货：{names}。**")
        for hold in report["holds"]:
            lines.append(f"- {code(hold['batch_id'])} 原因：{code(', '.join(hold['reasons']))}")
    for clause in report["unverifiable_clauses"]:
        lines.append(
            f"**无法核到的合同条款：{code(clause['clause_id'])} {clause['title']}。**"
        )
    lines.append("")

    lines.extend(["## 库存筛选", "", "| 库存 ID | 产品 | 版本 | 门槛 | 结论 | 原因 |", "| --- | --- | ---: | ---: | --- | --- |"])
    for item in report["inventory_filter"]:
        lines.append(
            f"| {code(item['inventory_id'])} | {item['product_name']} | "
            f"{item['product_version']} | {item.get('minimum_version') or '—'} | "
            f"{item['status']} | {item['reason'] or '—'} |"
        )
    lines.append("")

    lines.extend([
        "## 批次与 PE 头部确认",
        "",
        "| 批次 | 封存号 | 库存行 | 机器类型 | 子系统 | 子系统版本 | 映像 | 结论 |",
        "| --- | --- | --- | --- | --- | ---: | --- | --- |",
    ])
    for batch in report["batches"]:
        obs = batch.get("pe_observation")
        if obs is None:
            lines.append(
                f"| {code(batch['batch_id'])} | {code(batch['provenance']['seal_id'])} | "
                f"{code(batch['inventory_id'])} | 无法读取 | — | — | — | {code(batch['decision'])} |"
            )
            continue
        lines.append(
            f"| {code(batch['batch_id'])} | {code(batch['provenance']['seal_id'])} | "
            f"{code(batch['inventory_id'])} | {obs['machine']['name']} ({obs['machine']['hex']}) | "
            f"{obs['subsystem']['name']} | {obs['subsystem_version']} | "
            f"{obs['image_version']} / {obs['magic']['name']} | {code(batch['decision'])} |"
        )
    lines.append("")

    lines.extend(["### 逐项合同检查", ""])
    for batch in report["batches"]:
        lines.append(f"- {code(batch['batch_id'])}")
        receipt = batch.get("receipt")
        if receipt:
            fields = ", ".join(receipt.get("attested_fields", [])) or "未誊写字段"
            lines.append(
                f"  - 窄签收单 {code(receipt['receipt_id'])} 誊写范围：{fields}；"
                "未誊写的映像声明仍以 pefile 直接观察为准。"
            )
        else:
            lines.append("  - 窄签收单中没有该批次行，不能用同值批次的签收替代。")
        for check in batch["checks"]:
            clause = f"（{check['clause_id']}）" if check.get("clause_id") else ""
            mark = "PASS" if check["status"] == "pass" else "FAIL"
            lines.append(
                f"  - [{mark}] {check['topic']}{clause}: actual={code(json.dumps(check['actual'], ensure_ascii=False))}"
            )
    lines.append("")

    lines.extend(["## 不同封存批次的出处保留", ""])
    for index, group in enumerate(report["provenance_groups"], 1):
        lines.append(f"- 一致头部值组 {index}：signature={code(group['header_signature'][:16] + '…')}")
        for source in group["provenance"]:
            lines.append(
                f"  - 批次 {code(source['batch_id'])} / 封存 {code(source['seal_id'])} / "
                f"库存 {code(source['inventory_id'])}"
            )
        for artifact in group["artifacts"]:
            lines.append(
                f"  - 文件 {code(artifact['file_name'])} sha256={code(artifact['sha256'])}"
            )
    lines.append("")

    repeated_fields = [
        item for item in report.get("field_provenance", []) if item["source_count"] > 1
    ]
    if repeated_fields:
        lines.extend(["### 同值字段的跨批次出处", ""])
        for item in repeated_fields:
            sources = "、".join(
                f"{source['batch_id']}/{source['seal_id']}"
                for source in item["provenance"]
            )
            lines.append(
                f"- {code(item['field'])}={code(display_value(item['value']))} ← {sources}"
            )
        lines.append("")

    lines.extend(["## 旧合同未覆盖、本次仅留证的字段", ""])
    seen = set()
    for batch in report["batches"]:
        obs = batch.get("pe_observation")
        if not obs:
            continue
        key = json.dumps(obs["old_contract_uncovered_fields"], sort_keys=True)
        if key in seen:
            lines.append(f"- {code(batch['batch_id'])} 与前述批次值一致，但出处仍独立保留。")
            continue
        seen.add(key)
        lines.append(f"- {code(batch['batch_id'])}：")
        for name, value in obs["old_contract_uncovered_fields"].items():
            lines.append(f"  - {code(name)} = {code(display_value(value))}")
    lines.append("")

    lines.extend(["## 合同外部证据", ""])
    for clause in report["external_clause_checks"]:
        lines.append(f"- {code(clause['clause_id'])} {clause['title']}: {code(clause['status'])}")
    lines.append("")
    return "\n".join(lines)


def minimal_pe_bytes(architecture: str) -> bytes:
    architecture = architecture.lower()
    if architecture in {"x86", "i386", "pe32"}:
        machine, magic, optional_size = 0x014C, 0x10B, 0xE0
        image_base, characteristics = 0x00400000, 0x0102
        code = b"\x31\xC0\xC3"
        is_plus = False
    elif architecture in {"x64", "amd64", "pe32+"}:
        machine, magic, optional_size = 0x8664, 0x20B, 0xF0
        image_base, characteristics = 0x0000000140000000, 0x0022
        code = b"\x48\x31\xC0\xC3"
        is_plus = True
    else:
        raise ValueError(f"unsupported architecture: {architecture}")

    dos_header = bytearray(64)
    dos_header[0:2] = b"MZ"
    struct.pack_into("<I", dos_header, 60, 64)
    coff_header = struct.pack(
        "<HHIIIHH", machine, 1, 0, 0, 0, optional_size, characteristics
    )

    optional = bytearray(optional_size)
    struct.pack_into("<HBB", optional, 0, magic, 14, 0)
    struct.pack_into("<IIIII", optional, 4, 0x200, 0, 0, 0x1000, 0x1000)
    if is_plus:
        struct.pack_into("<Q", optional, 24, image_base)
    else:
        struct.pack_into("<I", optional, 24, 0)
        struct.pack_into("<I", optional, 28, image_base)
    struct.pack_into("<II", optional, 32, 0x1000, 0x200)
    struct.pack_into("<HHHHHH", optional, 40, 6, 1, 1, 0, 6, 1)
    struct.pack_into("<I", optional, 52, 0)
    struct.pack_into("<II", optional, 56, 0x2000, 0x200)
    struct.pack_into("<I", optional, 64, 0)
    struct.pack_into("<HH", optional, 68, 3, 0x8140)
    if is_plus:
        struct.pack_into("<QQQQ", optional, 72, 0x100000, 0x1000, 0x100000, 0x1000)
        struct.pack_into("<II", optional, 104, 0, 16)
    else:
        struct.pack_into("<IIII", optional, 72, 0x100000, 0x1000, 0x100000, 0x1000)
        struct.pack_into("<II", optional, 88, 0, 16)

    section_header = struct.pack(
        "<8sIIIIIIHHI",
        b".text\x00\x00\x00", len(code), 0x1000, 0x200, 0x200,
        0, 0, 0, 0, 0x60000020,
    )
    headers = bytes(dos_header) + b"PE\x00\x00" + coff_header + bytes(optional) + section_header
    blob = headers.ljust(0x200, b"\x00") + code.ljust(0x200, b"\x00")

    pe = pefile.PE(data=blob, fast_load=True)
    checksum = pe.generate_checksum()
    e_lfanew = struct.unpack_from("<I", dos_header, 60)[0]
    checksum_offset = e_lfanew + 4 + 20 + 64
    blob = blob[:checksum_offset] + struct.pack("<I", checksum) + blob[checksum_offset + 4:]
    return blob


def build_default_fixtures(target_dir: Path = ACCEPTANCE_DIR / "artifacts") -> List[Path]:
    target_dir = Path(target_dir)
    target_dir.mkdir(parents=True, exist_ok=True)
    written = []
    for architecture, file_name in [("x86", "empty_x86.exe"), ("x64", "empty_x64.exe")]:
        path = target_dir / file_name
        path.write_bytes(minimal_pe_bytes(architecture))
        written.append(path)
    return written


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT)
    parser.add_argument("--inventory", type=Path, default=DEFAULT_INVENTORY)
    parser.add_argument("--batches", type=Path, default=DEFAULT_BATCHES)
    parser.add_argument("--receipt", type=Path, default=DEFAULT_RECEIPT)
    parser.add_argument("--evidence", type=Path)
    parser.add_argument("--base-dir", type=Path)
    parser.add_argument("--json-output", type=Path, default=DEFAULT_JSON_REPORT)
    parser.add_argument("--markdown-output", type=Path, default=DEFAULT_MD_REPORT)
    parser.add_argument("--build-fixtures", action="store_true")
    args = parser.parse_args(argv)

    if args.build_fixtures:
        for path in build_default_fixtures():
            print(f"wrote {path} sha256={sha256_file(path)}")
        return 0

    report = run_audit(
        contract_path=args.contract,
        inventory_path=args.inventory,
        batches_path=args.batches,
        receipt_path=args.receipt,
        evidence_path=args.evidence,
        base_dir=args.base_dir,
    )
    args.json_output.parent.mkdir(parents=True, exist_ok=True)
    args.json_output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    args.markdown_output.write_text(render_markdown(report), encoding="utf-8")
    print(f"wrote {args.json_output}")
    print(f"wrote {args.markdown_output}")
    print(
        "holds=" + json.dumps([x["batch_id"] for x in report["holds"]], ensure_ascii=False)
        + "; unverifiable="
        + json.dumps([x["clause_id"] for x in report["unverifiable_clauses"]], ensure_ascii=False)
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
