#!/usr/bin/env python3

import argparse
import json
from datetime import datetime
from pathlib import Path

from LnkParse3.extra.distributed_tracker import DistributedTracker
from LnkParse3.lnk_file import LnkFile


ZERO_GUID = "00000000-0000-0000-0000-000000000000"


def record_from_lnk(lnk, node_id=None, source=None, collection_order=0, hardware_generation=None):
    tracker = distributed_tracker(lnk)
    header = lnk.get_json().get("header", {})
    return {
        "node_id": node_id or source or str(collection_order),
        "source": source,
        "collection_order": collection_order,
        "hardware_generation": hardware_generation,
        "tracker": tracker,
        "header_times": {
            "creation_time": _datetime_to_string(header.get("creation_time")),
            "accessed_time": _datetime_to_string(header.get("accessed_time")),
            "modified_time": _datetime_to_string(header.get("modified_time")),
        },
    }


def record_from_path(path, node_id=None, collection_order=0, hardware_generation=None, cp=None):
    path = str(path)
    with open(path, "rb") as handle:
        lnk = LnkFile(fhandle=handle, cp=cp)
        return record_from_lnk(
            lnk,
            node_id=node_id,
            source=path,
            collection_order=collection_order,
            hardware_generation=hardware_generation,
        )


def distributed_tracker(lnk):
    for extra in lnk.extras:
        if isinstance(extra, DistributedTracker):
            data = extra.as_dict()
            return {
                "machine_identifier": data["machine_identifier"],
                "current_volume_identifier": data["droid_volume_identifier"],
                "current_file_identifier": data["droid_file_identifier"],
                "current_identifier_pair": [
                    data["droid_volume_identifier"],
                    data["droid_file_identifier"],
                ],
                "birth_volume_identifier": data["birth_droid_volume_identifier"],
                "birth_file_identifier": data["birth_droid_file_identifier"],
                "birth_identifier_pair": [
                    data["birth_droid_volume_identifier"],
                    data["birth_droid_file_identifier"],
                ],
            }
    return None


def build_lineage(records):
    nodes = [_normalize_record(record) for record in records]
    nodes.sort(key=lambda item: (item["collection_order"], item["input_order"]))

    edges = []
    for target_index, target in enumerate(nodes):
        for source_index, source in enumerate(nodes[:target_index]):
            edges.extend(_edges_between(source, target, source_index, target_index))

    return {
        "nodes": [_node_output(node) for node in nodes],
        "edges": edges,
    }


def export_lineage_edges(records, output_path=None):
    lineage = build_lineage(records)
    payload = json.dumps(lineage, indent=4, sort_keys=True)
    if output_path:
        with open(output_path, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.write("\n")
    return payload


def load_records(input_path, cp=None):
    with open(input_path, "r", encoding="utf-8") as handle:
        raw_records = json.load(handle)

    records = []
    for index, raw_record in enumerate(raw_records):
        record = dict(raw_record)
        record.setdefault("collection_order", index)
        if "path" in record:
            path = record.pop("path")
            lnk_record = record_from_path(
                path,
                node_id=record.get("node_id"),
                collection_order=record["collection_order"],
                hardware_generation=record.get("hardware_generation"),
                cp=cp,
            )
            record.setdefault("source", path)
            record["tracker"] = lnk_record["tracker"]
            record["header_times"] = lnk_record["header_times"]
        records.append(record)
    return records


def _normalize_record(record, input_order=0):
    if isinstance(record, LnkFile):
        record = record_from_lnk(record, collection_order=input_order)
    normalized = dict(record)
    normalized["input_order"] = input_order
    normalized.setdefault("node_id", normalized.get("source") or str(input_order))
    normalized.setdefault("source", normalized["node_id"])
    normalized.setdefault("collection_order", input_order)
    normalized.setdefault("hardware_generation", None)
    normalized.setdefault("header_times", {})
    if "lnk" in normalized:
        lnk = normalized.pop("lnk")
        parsed = record_from_lnk(
            lnk,
            node_id=normalized["node_id"],
            source=normalized["source"],
            collection_order=normalized["collection_order"],
            hardware_generation=normalized["hardware_generation"],
        )
        normalized["tracker"] = parsed["tracker"]
        normalized["header_times"] = parsed["header_times"]
    elif "data" in normalized:
        data = normalized.pop("data")
        lnk = LnkFile(indata=data, cp=normalized.get("codepage"))
        parsed = record_from_lnk(
            lnk,
            node_id=normalized["node_id"],
            source=normalized["source"],
            collection_order=normalized["collection_order"],
            hardware_generation=normalized["hardware_generation"],
        )
        normalized["tracker"] = parsed["tracker"]
        normalized["header_times"] = parsed["header_times"]
    return normalized


def _edges_between(source, target, source_index, target_index):
    source_tracker = source.get("tracker")
    target_tracker = target.get("tracker")
    if not source_tracker or not target_tracker:
        return []

    candidate_matches = [
        (
            "lineage_continuation",
            source_tracker["current_identifier_pair"],
            target_tracker["birth_identifier_pair"],
            "current_to_birth",
        ),
        (
            "shared_origin",
            source_tracker["birth_identifier_pair"],
            target_tracker["birth_identifier_pair"],
            "birth_to_birth",
        ),
        (
            "snapshot_reuse",
            source_tracker["current_identifier_pair"],
            target_tracker["current_identifier_pair"],
            "current_to_current",
        ),
    ]

    edges = []
    for relation, left_pair, right_pair, match_path in candidate_matches:
        evidence = _pair_evidence(left_pair, right_pair)
        if not evidence:
            continue
        edges.append(
            {
                "id": f"edge-{source_index + 1}-{target_index + 1}-{relation}",
                "source_node": source["node_id"],
                "target_node": target["node_id"],
                "relation": relation,
                "match_path": match_path,
                "evidence": evidence,
                "constraints": _constraints(source, target),
                "provenance": {
                    "source": _provenance(source),
                    "target": _provenance(target),
                },
            }
        )
    return edges


def _pair_evidence(left_pair, right_pair):
    matched = []
    identifiers = ("volume", "file")
    for identifier, left_value, right_value in zip(identifiers, left_pair, right_pair):
        if _valid_guid(left_value) and left_value == right_value:
            matched.append(
                {
                    "identifier": f"{identifier}_identifier",
                    "value": left_value,
                }
            )
    if not matched:
        return None
    support = "full_identifier_pair" if len(matched) == 2 else "partial_identifier"
    return {
        "support_level": support,
        "matched_identifiers": matched,
        "source_identifier_pair": left_pair,
        "target_identifier_pair": right_pair,
    }


def _constraints(source, target):
    return {
        "collection_order": _order_constraint(source, target),
        "hardware_generation": _hardware_constraint(source, target),
        "header_times": _time_constraints(source, target),
    }


def _order_constraint(source, target):
    if source["collection_order"] == target["collection_order"]:
        status = "undetermined"
    elif source["collection_order"] < target["collection_order"]:
        status = "satisfied"
    else:
        status = "violated"
    return {
        "status": status,
        "source_collection_order": source["collection_order"],
        "target_collection_order": target["collection_order"],
    }


def _hardware_constraint(source, target):
    source_generation = source["hardware_generation"]
    target_generation = target["hardware_generation"]
    if source_generation is None or target_generation is None:
        status = "not_supplied"
        transition = "unknown"
    elif source_generation == target_generation:
        status = "satisfied"
        transition = "same_generation"
    elif source_generation < target_generation:
        status = "satisfied"
        transition = "cross_generation"
    else:
        status = "violated"
        transition = "earger_generation"
    return {
        "status": status,
        "transition": transition,
        "source_hardware_generation": source_generation,
        "target_hardware_generation": target_generation,
    }


def _time_constraints(source, target):
    result = {}
    for name in ("creation_time", "accessed_time", "modified_time"):
        source_time = source.get("header_times", {}).get(name)
        target_time = target.get("header_times", {}).get(name)
        if not source_time or not target_time:
            status = "not_supplied"
        elif source_time <= target_time:
            status = "satisfied"
        else:
            status = "violated"
        result[name] = {
            "status": status,
            "source_value": source_time,
            "target_value": target_time,
        }
    return result


def _provenance(node):
    tracker = node.get("tracker") or {}
    return {
        "node_id": node["node_id"],
        "source": node["source"],
        "collection_order": node["collection_order"],
        "hardware_generation": node["hardware_generation"],
        "machine_identifier": tracker.get("machine_identifier"),
    }


def _node_output(node):
    return {
        "node_id": node["node_id"],
        "source": node["source"],
        "collection_order": node["collection_order"],
        "hardware_generation": node["hardware_generation"],
        "header_times": node["header_times"],
        "tracker": node.get("tracker"),
    }


def _valid_guid(value):
    return bool(value) and value.upper() != ZERO_GUID


def _datetime_to_string(value):
    if isinstance(value, datetime):
        return value.isoformat()
    return value


def main():
    parser = argparse.ArgumentParser(description="Build offline Distributed Link Tracker lineage edges")
    parser.add_argument("--input", required=True, help="JSON file containing collected LNK records")
    parser.add_argument("--output", help="Optional JSON output path")
    parser.add_argument("--codepage", help="Code page used by LNK ASCII strings")
    args = parser.parse_args()

    records = load_records(Path(args.input), cp=args.codepage)
    payload = export_lineage_edges(records, args.output)
    if not args.output:
        print(payload)


if __name__ == "__main__":
    main()
