#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import re
import sys
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from dataclasses import dataclass, asdict
from pathlib import Path

from Evtx.Evtx import Evtx

EVENT_NS = "http://schemas.microsoft.com/win/2004/08/events/event"
NS = {"e": EVENT_NS}
MEMBERSHIP_ATTRS = {"member", "msDS-Non-Simple-Bind-Allowed", "msDS-GroupMSAMembership"}


@dataclass
class ChangeEvent:
    source_file: str
    computer: str
    record_num: int
    time: str
    correlation_id: str
    operation: str
    object_guid: str
    attribute: str
    value_guid: str
    value_text: str
    xml_sha256: str


def text_at(root: ET.Element, path: str) -> str:
    value = root.findtext(path, namespaces=NS)
    return (value or "").strip()


def data_by_name(root: ET.Element, name: str) -> str:
    for item in root.findall("./e:EventData/e:Data", NS):
        if item.attrib.get("Name", "").lower() == name.lower():
            return (item.text or "").strip()
    return ""

GUID_RE = re.compile(r"[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}")


def extract_guid(value: str) -> str:
    match = GUID_RE.search(value or "")
    return match.group(0).lower() if match else ""


def parse_5136(path: Path) -> tuple[list[ChangeEvent], Counter]:
    events: list[ChangeEvent] = []
    counts: Counter = Counter()
    with Evtx(str(path)) as log:
        for record in log.records:
            xml = record.xml()
            root = ET.fromstring(xml)
            event_id = int(text_at(root, "./e:System/e:EventID"))
            counts[event_id] += 1
            if event_id != 5136:
                continue
            attribute = data_by_name(root, "AttributeLDAPDisplayName")
            if attribute.lower() not in MEMBERSHIP_ATTRS:
                continue
            operation = data_by_name(root, "AttributeValue").strip()
            value_text = data_by_name(root, "AttributeValue")
            object_guid = data_by_name(root, "ObjectGUID")
            value_guid = extract_guid(value_text)
            events.append(
                ChangeEvent(
                    source_file=str(path),
                    computer=text_at(root, "./e:System/e:Computer"),
                    record_num=record.record_num(),
                    time=text_at(root, "./e:System/e:TimeCreated"),
                    correlation_id=text_at(root, "./e:System/e:Correlation"),
                    operation=operation,
                    object_guid=object_guid.lower(),
                    attribute=attribute.lower(),
                    value_guid=value_guid.lower(),
                    value_text=value_text,
                    xml_sha256=__import__("hashlib").sha256(xml.encode("utf-8")).hexdigest(),
                )
            )
    return events, counts


def read_inventory(path: Path) -> dict[str, set[str]]:
    if not path.exists():
        return {}
    if path.suffix.lower() == ".json":
        import json

        raw = json.loads(path.read_text(encoding="utf-8"))
        return {str(key): {extract_guid(value) or value for value in values} for key, values in raw.items()}
    with path.open(newline="", encoding="utf-8-sig") as handle:
        rows = list(csv.DictReader(handle))
    grouped: dict[str, set[str]] = defaultdict(set)
    for row in rows:
        snapshot = row.get("snapshot") or row.get("inventory") or path.stem
        guid = extract_guid(row.get("member_guid", "")) or row.get("member_guid", "").strip()
        if guid:
            grouped[snapshot].add(guid.lower())
    return dict(grouped)


def classify(member: str, before: set[str], after: set[str], changes: list[ChangeEvent], target: str) -> str:
    observed_before_target = [event for event in changes if event.value_guid == member and event.time < target]
    observed_after_target = [event for event in changes if event.value_guid == member and event.time >= target]
    add_before = any(event.operation.lower() == "%%14674" for event in observed_before_target)
    delete_before = any(event.operation.lower() == "%%14675" for event in observed_before_target)
    add_after = any(event.operation.lower() == "%%14674" for event in observed_after_target)
    delete_after = any(event.operation.lower() == "%%14675" for event in observed_after_target)
    if add_before and not delete_before:
        return "一定存在"
    if delete_before and not add_before:
        return "已能排除"
    if member in before and member not in after and delete_after:
        return "可能存在"
    if member not in before and member in after and add_after:
        return "可能存在"
    if member in before and member in after:
        return "一定存在"
    if member in before or member in after:
        return "可能存在"
    return "已能排除"


def main() -> int:
    parser = argparse.ArgumentParser(description="Review AD group 5136 membership changes without cross-DC ordering.")
    parser.add_argument("--evtx-dir", type=Path, default=Path("tests/data"))
    parser.add_argument("--before", type=Path)
    parser.add_argument("--after", type=Path)
    parser.add_argument("--target-time", required=True)
    parser.add_argument("--out-dir", type=Path, default=Path("review_output"))
    args = parser.parse_args()

    args.out_dir.mkdir(parents=True, exist_ok=True)
    all_events: list[ChangeEvent] = []
    summary_lines: list[str] = []
    for path in sorted(args.evtx_dir.rglob("*.evtx")):
        try:
            events, counts = parse_5136(path)
        except Exception as exc:
            summary_lines.append(f"{path}: parse_error={exc}")
            continue
        all_events.extend(events)
        summary_lines.append(f"{path}: records={sum(counts.values())} eid5136={counts[5136]} membership5136={len(events)}")

    fieldnames = list(asdict(all_events[0]).keys()) if all_events else list(ChangeEvent.__dataclass_fields__.keys())
    with (args.out_dir / "membership_5136_events.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for event in all_events:
            writer.writerow(asdict(event))

    before_inventory = read_inventory(args.before) if args.before else {}
    after_inventory = read_inventory(args.after) if args.after else {}
    before_members = set.union(*before_inventory.values()) if before_inventory else set()
    after_members = set.union(*after_inventory.values()) if after_inventory else set()
    event_members = {event.value_guid for event in all_events if event.value_guid}
    members = sorted((before_members | after_members | event_members))

    grouped: dict[tuple[str, str, str, str], list[ChangeEvent]] = defaultdict(list)
    for event in all_events:
        grouped[(event.object_guid, event.attribute, event.computer, event.correlation_id)].append(event)
    with (args.out_dir / "unpaired_events.txt").open("w", encoding="utf-8") as handle:
        for key, events in sorted(grouped.items()):
            operations = Counter(event.operation for event in events)
            if operations.get("%%14674") != operations.get("%%14675"):
                handle.write(repr(key) + "\n")
                for event in events:
                    handle.write(f"  {event.time} record={event.record_num} op={event.operation} member={event.value_guid}\n")

    with (args.out_dir / "membership_conclusions.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["member_guid", "conclusion", "evidence_scope_note"])
        for member in members:
            writer.writerow([member, classify(member, before_members, after_members, all_events, args.target_time), "仅同一域控内按时间排序；跨副本事件不建立全局顺序；缺采区间允许未观察变更"])

    (args.out_dir / "scan_summary.txt").write_text("\n".join(summary_lines) + "\n", encoding="utf-8")
    if not all_events:
        print("NO_5136_MEMBERSHIP_EVENTS_FOUND", file=sys.stderr)
    print(f"wrote {args.out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
