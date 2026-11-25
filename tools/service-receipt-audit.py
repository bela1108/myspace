#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Optional


STOPPED_PROPERTY = "receipt:status"
STOPPED_VALUES = frozenset({"stopped", "decommissioned", "retired"})
RECEIPT_PROPERTY = "receipt:acknowledged"
ACKNOWLEDGED_VALUES = frozenset({"true", "yes", "confirmed", "acknowledged"})


@dataclass(frozen=True)
class NodeKey:
    bom_version: int
    bom_ref: str


@dataclass(frozen=True)
class ServiceNode:
    bom_version: int
    bom_ref: str
    name: str
    stopped: bool
    receipt_acknowledged: Optional[bool]


@dataclass(frozen=True)
class TraceEntry:
    stopped_service: str
    consumer_bom_ref: str
    consumer_name: str
    consumer_direction: str
    status: str
    receipt_acknowledged: Optional[bool]
    path: tuple[str, ...]


@dataclass(frozen=True)
class AuditResult:
    bom_version: int
    missing_receipts: tuple[TraceEntry, ...]
    acknowledged: tuple[TraceEntry, ...]
    unknown: tuple[TraceEntry, ...]


def _text(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


def _bool_property(value: Any) -> Optional[bool]:
    normalized = _text(value).strip().lower()
    if normalized in ACKNOWLEDGED_VALUES:
        return True
    if normalized in {"false", "no", "unacknowledged", "missing"}:
        return False
    return None


def _properties(properties: Any) -> dict[str, str]:
    result: dict[str, str] = {}
    if not isinstance(properties, list):
        return result
    for prop in properties:
        if not isinstance(prop, dict):
            continue
        name = _text(prop.get("name")).strip()
        if name:
            result[name] = _text(prop.get("value")).strip()
    return result


def _load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError(f"BOM root must be an object: {path}")
    return data


def _strip_xml_namespace(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _xml_child(element: ET.Element, name: str) -> Optional[ET.Element]:
    for child in element:
        if _strip_xml_namespace(child.tag) == name:
            return child
    return None


def _xml_properties(element: ET.Element) -> dict[str, str]:
    properties_element = _xml_child(element, "properties")
    if properties_element is None:
        return {}
    result = {}
    for prop in properties_element:
        if _strip_xml_namespace(prop.tag) != "property":
            continue
        name = prop.attrib.get("name", "").strip()
        if name:
            result[name] = prop.attrib.get("value", "").strip()
    return result


def _load_xml(path: Path) -> dict[str, Any]:
    root = ET.parse(path).getroot()
    services: list[dict[str, Any]] = []
    services_element = _xml_child(root, "services")
    if services_element is not None:
        for service in services_element:
            if _strip_xml_namespace(service.tag) != "service":
                continue
            name_element = _xml_child(service, "name")
            services.append({
                "bom-ref": service.attrib.get("bom-ref", ""),
                "name": "" if name_element is None or name_element.text is None
                else name_element.text,
                "properties": [
                    {"name": name, "value": value}
                    for name, value in _xml_properties(service).items()
                ],
            })
    dependencies: list[dict[str, Any]] = []
    dependencies_element = _xml_child(root, "dependencies")
    if dependencies_element is not None:
        for dependency in dependencies_element:
            if _strip_xml_namespace(dependency.tag) != "dependency":
                continue
            dependencies.append({
                "ref": dependency.attrib.get("ref", ""),
                "dependsOn": [
                    child.attrib.get("ref", "")
                    for child in dependency
                    if _strip_xml_namespace(child.tag) == "dependency"
                ],
            })
    return {
        "version": root.attrib.get("version", ""),
        "services": services,
        "dependencies": dependencies,
    }


def load_bom(path: Path) -> dict[str, Any]:
    suffix = path.suffix.lower()
    if suffix == ".json":
        return _load_json(path)
    if suffix == ".xml":
        return _load_xml(path)
    raise ValueError(f"Unsupported BOM format: {path.suffix}")


def _bom_version(bom: dict[str, Any], path: Path) -> int:
    try:
        return int(bom["version"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(f"BOM version must be an integer: {path}") from exc


def _services(bom: dict[str, Any], bom_version: int) -> dict[str, ServiceNode]:
    result: dict[str, ServiceNode] = {}
    for raw_service in bom.get("services", []):
        if not isinstance(raw_service, dict):
            continue
        bom_ref = _text(raw_service.get("bom-ref")).strip()
        if not bom_ref:
            continue
        props = _properties(raw_service.get("properties"))
        stopped = props.get(STOPPED_PROPERTY, "").lower() in STOPPED_VALUES
        receipt = _bool_property(props.get(RECEIPT_PROPERTY))
        result[bom_ref] = ServiceNode(
            bom_version=bom_version,
            bom_ref=bom_ref,
            name=_text(raw_service.get("name")).strip() or bom_ref,
            stopped=stopped,
            receipt_acknowledged=receipt,
        )
    return result


def _reverse_edges(bom: dict[str, Any]) -> dict[str, set[str]]:
    result: dict[str, set[str]] = defaultdict(set)
    for dependency in bom.get("dependencies", []):
        if not isinstance(dependency, dict):
            continue
        consumer = _text(dependency.get("ref")).strip()
        if not consumer:
            continue
        targets = dependency.get("dependsOn", [])
        if not isinstance(targets, list):
            continue
        for target in targets:
            target_ref = _text(target).strip()
            if target_ref:
                result[target_ref].add(consumer)
    return result


def _consumer_direction(path: tuple[str, ...], services: dict[str, ServiceNode]) -> str:
    if len(path) == 2:
        return "direct"
    intermediate = path[1:-1]
    if any(ref in services for ref in intermediate):
        return "proxy"
    return "forwarding"


def audit_bom(bom: dict[str, Any], path: Path) -> AuditResult:
    bom_version = _bom_version(bom, path)
    services = _services(bom, bom_version)
    reverse_edges = _reverse_edges(bom)
    entries: list[TraceEntry] = []

    for stopped_ref in sorted(ref for ref, service in services.items() if service.stopped):
        stopped_service = services[stopped_ref]
        queue: list[tuple[str, tuple[str, ...]]] = [
            (consumer, (stopped_ref, consumer))
            for consumer in sorted(reverse_edges.get(stopped_ref, ()))
        ]
        visited: set[str] = {stopped_ref}
        while queue:
            consumer_ref, path = queue.pop(0)
            if consumer_ref in visited:
                continue
            visited.add(consumer_ref)
            consumer = services.get(consumer_ref)
            if consumer is not None:
                receipt = consumer.receipt_acknowledged
                if receipt is True:
                    status = "acknowledged"
                elif receipt is False:
                    status = "missing_receipt"
                else:
                    status = "unknown"
                entries.append(TraceEntry(
                    stopped_service=stopped_service.name,
                    consumer_bom_ref=consumer_ref,
                    consumer_name=consumer.name,
                    consumer_direction=_consumer_direction(path, services),
                    status=status,
                    receipt_acknowledged=receipt,
                    path=path,
                ))
            for next_consumer in sorted(reverse_edges.get(consumer_ref, ())):
                if next_consumer not in visited:
                    queue.append((next_consumer, path + (next_consumer,)))

    def sort_key(entry: TraceEntry) -> tuple[str, str, str, tuple[str, ...]]:
        return entry.stopped_service, entry.consumer_direction, entry.consumer_bom_ref, entry.path

    grouped = {
        "missing_receipt": tuple(sorted(
            (entry for entry in entries if entry.status == "missing_receipt"), key=sort_key)),
        "acknowledged": tuple(sorted(
            (entry for entry in entries if entry.status == "acknowledged"), key=sort_key)),
        "unknown": tuple(sorted(
            (entry for entry in entries if entry.status == "unknown"), key=sort_key)),
    }
    return AuditResult(bom_version=bom_version, **grouped)


def audit_boms(paths: list[Path]) -> list[AuditResult]:
    loaded = [(path, load_bom(path)) for path in paths]
    versions = [_bom_version(bom, path) for path, bom in loaded]
    if len(set(versions)) != len(versions):
        raise ValueError("BOM versions must be unique")
    return [audit_bom(bom, path) for path, bom in sorted(loaded, key=lambda item: _bom_version(item[1], item[0]))]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Audit stopped-service consumer receipts across CycloneDX BOMs.")
    parser.add_argument("bom", nargs="+", type=Path, help="CycloneDX JSON or XML BOM files")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        results = audit_boms(args.bom)
    except (OSError, ValueError, ET.ParseError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    payload = [
        {
            "bom_version": result.bom_version,
            "missing_receipts": [asdict(entry) for entry in result.missing_receipts],
            "acknowledged": [asdict(entry) for entry in result.acknowledged],
            "unknown": [asdict(entry) for entry in result.unknown],
        }
        for result in results
    ]
    if args.json:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return 0

    for result in results:
        print(f"BOM {result.bom_version}")
        for label, entries in (
            ("missing_receipts", result.missing_receipts),
            ("acknowledged", result.acknowledged),
            ("unknown", result.unknown),
        ):
            print(f"  {label}: {len(entries)}")
            for entry in entries:
                print(f"    - {entry.stopped_service} -> {entry.consumer_name} "
                      f"({entry.consumer_direction}) path={' -> '.join(entry.path)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
