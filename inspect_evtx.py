#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import re
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from Evtx.Evtx import Evtx

EVENT_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
MEMBER_ATTRS = {"member", "members"}


@dataclass(frozen=True)
class ChangeEvent:
    source_file: str
    domain_controller: str
    record_number: int
    time_utc: str
    event_id: int
    operation: str
    correlation_id: str
    object_guid: str
    attribute: str
    value_guid: str
    value_text: str
    subject_user: str
    xml_sha256: str


@dataclass(frozen=True)
class InventorySnapshot:
    source_file: str
    snapshot_time: str
    value_guid: str
    value_text: str
    present: bool


def text_of(node: ET.Element | None, path: str) -> str:
    value = node.findtext(path, namespaces=EVENT_NS) if node is not None else None
    return "" if value is None else value.strip()


def parse_time(value: str) -> datetime:
    if not value:
        return datetime.max.replace(tzinfo=timezone.utc)
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def data_items(root: ET.Element) -> dict[str, list[str]]:
    items: dict[str, list[str]] = defaultdict(list)
    for item in root.findall(".//e:EventData/e:Data", EVENT_NS):
        name = item.attrib.get("Name", "")
        items[name].append("" if item.text is None else item.text.strip())
    return dict(items)


def first(items: dict[str, list[str]], name: str) -> str:
    values = items.get(name, [])
    return values[0] if values else ""


def extract_guid(value: str) -> str:
    match = re.search(r"[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}", value)
    return match.group(0).lower() if match else ""


def classify_operation(value: str) -> str:
    normalized = value.lower().replace(" ", "")
    if "%%14674" in normalized or "addvalue" in normalized or "加值" in value:
        return "add"
    if "%%14675" in normalized or "deletevalue" in normalized or "删值" in value:
        return "delete"
    return normalized or "unknown"


def parse_evtx(path: Path) -> tuple[list[ChangeEvent], Counter[str], list[str]]:
    changes: list[ChangeEvent] = []
    event_counts: Counter[str] = Counter()
    errors: list[str] = []
    with Evtx(str(path)) as log:
        for record in log.records:
            try:
                xml = record.xml()
                root = ET.fromstring(xml)
                event_id = int(text_of(root, "./e:System/e:EventID"))
                event_counts[str(event_id)] += 1
                if event_id != 5136:
                    continue
                items = data_items(root)
                attribute = first(items, "AttributeLDAPDisplayName").lower()
                if attribute not in MEMBER_ATTRS:
                    continue
                value_text = first(items, "AttributeValue")
                object_guid = first(items, "ObjectGUID").lower()
                value_guid = extract_guid(value_text)
                operation = classify_operation(first(items, "OperationType"))
                computer = text_of(root, "./e:System/e:Computer")
                correlation = text_of(root, "./e:System/e:Correlation")
                activity_id = root.find("./e:System/e:Correlation", EVENT_NS)
                correlation_id = ""
                if activity_id is not None:
                    correlation_id = activity_id.attrib.get("ActivityID", "").strip()
                changes.append(
                    ChangeEvent(
                        source_file=path.name,
                        domain_controller=computer.lower(),
                        record_number=record.record_num(),
                        time_utc=text_of(root, "./e:System/e:TimeCreated/@SystemTime"),
                        event_id=event_id,
                        operation=operation,
                        correlation_id=correlation_id or correlation,
                        object_guid=object_guid,
                        attribute=attribute,
                        value_guid=value_guid,
                        value_text=value_text,
                        subject_user=first(items, "SubjectUserName"),
                        xml_sha256=__import__("hashlib").sha256(xml.encode("utf-8")).hexdigest(),
                    )
                )
            except Exception as exc:
                errors.append(f"{path}:{getattr(record, 'record_num', lambda: '?')()}: {type(exc).__name__}: {exc}")
    return changes, event_counts, errors


def load_inventory(path: Path) -> list[InventorySnapshot]:
    suffix = path.suffix.lower()
    if suffix != ".csv":
        return []
    rows: list[InventorySnapshot] = []
    with path.open(newline="", encoding="utf-8-sig") as handle:
        for row in csv.DictReader(handle):
            value = (row.get("value_guid") or row.get("member_guid") or "").strip().lower()
            present_text = (row.get("present") or "true").strip().lower()
            rows.append(
                InventorySnapshot(
                    source_file=path.name,
                    snapshot_time=(row.get("snapshot_time") or "").strip(),
                    value_guid=value,
                    value_text=(row.get("value_text") or row.get("member") or "").strip(),
                    present=present_text not in {"0", "false", "no", "absent", "排除"},
                )
            )
    return rows


def pair_events(events: Iterable[ChangeEvent]) -> list[dict[str, str]]:
    grouped: dict[tuple[str, str, str, str], list[ChangeEvent]] = defaultdict(list)
    for event in events:
        key = (
            event.domain_controller,
            event.object_guid,
            event.attribute,
            event.value_guid or event.value_text,
        )
        grouped[key].append(event)
    rows = []
    for key, group_events in sorted(grouped.items()):
        ordered = sorted(group_events, key=lambda item: (parse_time(item.time_utc), item.record_number))
        adds = [item for item in ordered if item.operation == "add"]
        deletes = [item for item in ordered if item.operation == "delete"]
        pair_count = min(len(adds), len(deletes))
        rows.append(
            {
                "domain_controller": key[0],
                "object_guid": key[1],
                "attribute": key[2],
                "member_guid": key[3],
                "add_count": str(len(adds)),
                "delete_count": str(len(deletes)),
                "paired_count": str(pair_count),
                "unpaired_count": str(abs(len(adds) - len(deletes))),
                "add_records": ";".join(str(item.record_number) for item in adds),
                "delete_records": ";".join(str(item.record_number) for item in deletes),
                "first_time_utc": ordered[0].time_utc,
                "last_time_utc": ordered[-1].time_utc,
            }
        )
    return rows


def member_state_at(
    member: str,
    target: datetime,
    events: list[ChangeEvent],
    inventories: list[InventorySnapshot],
) -> tuple[str, list[str]]:
    member_events = [
        event
        for event in events
        if (event.value_guid or event.value_text) == member
        and parse_time(event.time_utc) <= target
    ]
    evidence = [
        f"{event.source_file}#{event.record_number} {event.operation}@{event.time_utc} dc={event.domain_controller}"
        for event in sorted(member_events, key=lambda item: parse_time(item.time_utc))
    ]
    inventory_matches = [item for item in inventories if item.value_guid == member or item.value_text == member]
    evidence.extend(
        f"{item.source_file} snapshot={item.snapshot_time} present={item.present}" for item in inventory_matches
    )
    if any(event.operation == "delete" for event in member_events):
        latest = max(member_events, key=lambda item: parse_time(item.time_utc))
        if latest.operation == "delete":
            return "excluded_if_later_unobserved_change_is_not_assumed", evidence
    if any(event.operation == "add" for event in member_events):
        latest = max(member_events, key=lambda item: parse_time(item.time_utc))
        if latest.operation == "add":
            return "certain_or_possible_depending_on_observation_gaps", evidence
    if any(item.present for item in inventory_matches):
        return "possible_inventory_only", evidence
    if inventory_matches and not any(item.present for item in inventory_matches):
        return "excluded_by_inventory_subject_to_snapshot_scope", evidence
    return "not_seen_in_supplied_records", evidence


def write_csv(path: Path, rows: list[dict[str, str]]) -> None:
    fieldnames = sorted({key for row in rows for key in row})
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit AD group member 5136 add/delete events.")
    parser.add_argument("--evtx", nargs="*", type=Path, default=sorted(Path("tests/data").glob("*.evtx")))
    parser.add_argument("--inventory", nargs="*", type=Path, default=[])
    parser.add_argument("--target-time", default="")
    parser.add_argument("--output-dir", type=Path, default=Path("analysis_output"))
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    all_events: list[ChangeEvent] = []
    counts_rows = []
    errors = []
    for evtx_path in args.evtx:
        events, counts, parse_errors = parse_evtx(evtx_path)
        all_events.extend(events)
        errors.extend(parse_errors)
        for event_id, count in sorted(counts.items()):
            counts_rows.append({"source_file": evtx_path.name, "event_id": event_id, "count": str(count)})
    inventories: list[InventorySnapshot] = []
    for inventory_path in args.inventory:
        inventories.extend(load_inventory(inventory_path))
    event_rows = [asdict(event) for event in all_events]
    write_csv(args.output_dir / "5136_events.csv", event_rows)
    write_csv(args.output_dir / "event_counts.csv", counts_rows)
    write_csv(args.output_dir / "paired_members.csv", pair_events(all_events))
    write_csv(args.output_dir / "inventory.csv", [asdict(item) for item in inventories])
    target = parse_time(args.target_time) if args.target_time else datetime.max.replace(tzinfo=timezone.utc)
    members = sorted({(event.value_guid or event.value_text) for event in all_events} | {item.value_guid for item in inventories})
    state_rows = []
    for member in members:
        state, evidence = member_state_at(member, target, all_events, inventories)
        state_rows.append({"member": member, "state": state, "evidence": " | ".join(evidence)})
    write_csv(args.output_dir / "member_states.csv", state_rows)
    (args.output_dir / "parse_errors.txt").write_text("\n".join(errors), encoding="utf-8")
    print(f"processed_evtx={len(args.evtx)} events_5136={len(all_events)} inventories={len(inventories)}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
