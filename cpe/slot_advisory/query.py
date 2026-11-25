"""Local JSON query orchestration for slot-scoped advisory decisions."""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from .engine import (
    adjudicate_slot,
    create_closure,
    responsibility_rules,
    verify_closure,
)
from .lifecycle import migrate_slot, shared_component_report, supplement_evidence
from .model import (
    Advisory,
    Cabinet,
    SlotSnapshot,
    advisory_from,
    as_mapping,
    cabinet_from,
    snapshot_from,
)


def _advisories(payload: Dict[str, Any]) -> List[Advisory]:
    raw = payload.get("advisories")
    if raw is None:
        raw = [payload["advisory"]] if payload.get("advisory") else []
    return [advisory_from(item) for item in raw]


def _find_advisory(advisories: List[Advisory], advisory_id: str) -> Advisory:
    for advisory in advisories:
        if advisory.advisory_id == advisory_id:
            return advisory
    raise KeyError("unknown advisory_id: " + str(advisory_id))


def _decision_map(decisions: List[Dict[str, Any]]) -> Dict[tuple, Dict[str, Any]]:
    return {(item["advisory_id"], item["slot_id"]): item for item in decisions}


def _create_requested_closures(
    requests: List[Dict[str, Any]],
    advisories: List[Advisory],
    decisions: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    by_key = _decision_map(decisions)
    created: List[Dict[str, Any]] = []
    for request in requests or []:
        advisory_id = request["advisory_id"]
        _find_advisory(advisories, advisory_id)
        slot_id = request.get("slot_id")
        if slot_id:
            decision = by_key[(advisory_id, slot_id)]
        else:
            candidates = [item for item in decisions if item["advisory_id"] == advisory_id]
            if not candidates:
                raise KeyError("no decisions found for advisory " + advisory_id)
            if candidates[0]["closure_scope"] != "host":
                raise ValueError("slot_id is required for a slot-scoped closure request")
            decision = candidates[0]
        created.append(
            create_closure(
                decision,
                closed_by=request["closed_by"],
                disposition=request.get("disposition", "fixed"),
                closed_at=request.get("closed_at"),
                reason_zh=request.get("reason_zh") or request.get("reason"),
                closure_id=request.get("closure_id"),
            )
        )
    return created


def run_query(payload: Any) -> Dict[str, Any]:
    """Evaluate a cabinet, snapshots, closures, and optional lifecycle actions."""
    data = payload if isinstance(payload, dict) else json.loads(payload)
    cabinet = cabinet_from(data["cabinet"])
    advisories = _advisories(data)
    snapshots = [snapshot_from(item) for item in data.get("snapshots", [])]
    if len({item.slot_id for item in snapshots}) != len(snapshots):
        raise ValueError("snapshots must use distinct slot_id values")

    decisions: List[Dict[str, Any]] = []
    for snapshot in snapshots:
        for advisory in advisories:
            decisions.append(adjudicate_slot(advisory, cabinet, snapshot))

    closure_records = [as_mapping(item) for item in data.get("closure_records", [])]
    created_closures = _create_requested_closures(
        data.get("closure_requests", []), advisories, decisions
    )
    closure_records.extend(created_closures)

    slot_reports: List[Dict[str, Any]] = []
    for snapshot in snapshots:
        slot_decisions = [
            item for item in decisions if item["slot_id"] == snapshot.slot_id
        ]
        closure_checks: List[Dict[str, Any]] = []
        for closure in closure_records:
            advisory = _find_advisory(advisories, closure["advisory_id"])
            closure_checks.append(verify_closure(closure, advisory, cabinet, snapshot))

        foreign = [
            check
            for check in closure_checks
            if check.get("source_slot_id")
            and check["source_slot_id"] != snapshot.slot_id
        ]
        slot_reports.append(
            {
                "slot_id": snapshot.slot_id,
                "snapshot_id": snapshot.snapshot_id,
                "slot_owner": snapshot.slot_owner,
                "application": snapshot.application,
                "host_id": snapshot.host_id or cabinet.host_id,
                "applicability": slot_decisions,
                "closure_checks": closure_checks,
                "other_slot_closure_substitutions": foreign,
            }
        )

    lifecycle: Dict[str, Any] = {}
    supplements = data.get("evidence_supplements", [])
    if supplements:
        lifecycle["evidence_supplements"] = [
            supplement_evidence(cabinet, snapshots, advisories, item)
            for item in supplements
        ]
    migrations = data.get("migrations", [])
    if migrations:
        lifecycle["migrations"] = [
            migrate_slot(
                cabinet,
                snapshots,
                advisories,
                item,
                closure_records=closure_records,
            )
            for item in migrations
        ]

    verdict_counts = {
        "applicable": sum(item["verdict"] == "applicable" for item in decisions),
        "not_applicable": sum(item["verdict"] == "not_applicable" for item in decisions),
        "unknown": sum(item["verdict"] == "unknown" for item in decisions),
    }
    return {
        "query_id": data.get("query_id", "slot-advisory-query"),
        "cabinet": cabinet.to_dict(),
        "host_aggregation_guard": {
            "host_id": cabinet.host_id,
            "cabinet_id": cabinet.cabinet_id,
            "slot_ids": [item.slot_id for item in snapshots],
            "warning_zh": (
                "一个主机编号不等于一个处置责任主体；slot_strict 公告必须按应用槽、"
                "快照和见证部件身份分别裁定。"
            ),
            "safe_host_level_closure_only_for": "closure_scope=host 且公告没有 slot_strict 条件",
        },
        "summary": {
            "snapshot_count": len(snapshots),
            "slot_count": len(snapshots),
            "advisory_count": len(advisories),
            "closure_count": len(closure_records),
            "verdict_counts": verdict_counts,
        },
        "slots": slot_reports,
        "created_closures": created_closures,
        "closure_records": closure_records,
        "shared_components": shared_component_report(cabinet, snapshots, advisories, decisions),
        "responsibility_rules": responsibility_rules(),
        "lifecycle": lifecycle,
    }


def query_file(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as handle:
        return run_query(json.load(handle))
