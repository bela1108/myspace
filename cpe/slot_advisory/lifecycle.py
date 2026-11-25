"""Responsibility transitions for shared components, supplements, and migration."""

from __future__ import annotations

import copy
from typing import Any, Dict, List, Optional

from .engine import adjudicate_slot, create_closure, verify_closure
from .matching import normalize_component, sha256_text
from .model import (
    HOST_COMMON,
    SLOT_STRICT,
    Advisory,
    Cabinet,
    SlotSnapshot,
    advisory_from,
    as_mapping,
    cabinet_from,
    snapshot_from,
)


def _cabinet(value: Any) -> Cabinet:
    return value if isinstance(value, Cabinet) else cabinet_from(value)


def _snapshots(values: List[Any]) -> List[SlotSnapshot]:
    return [item if isinstance(item, SlotSnapshot) else snapshot_from(item) for item in values]


def _advisories(values: List[Any]) -> List[Advisory]:
    return [item if isinstance(item, Advisory) else advisory_from(item) for item in values]


def _find_snapshot(snapshots: List[SlotSnapshot], slot_id: str) -> SlotSnapshot:
    for snapshot in snapshots:
        if snapshot.slot_id == slot_id:
            return snapshot
    raise KeyError("unknown slot_id: " + str(slot_id))


def _find_advisory(advisories: List[Advisory], advisory_id: str) -> Advisory:
    for advisory in advisories:
        if advisory.advisory_id == advisory_id:
            return advisory
    raise KeyError("unknown advisory_id: " + str(advisory_id))


def _decisions(
    cabinet: Cabinet,
    snapshots: List[SlotSnapshot],
    advisories: List[Advisory],
    advisory_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    return [
        adjudicate_slot(advisory, cabinet, snapshot)
        for snapshot in snapshots
        for advisory in advisories
        if advisory_id is None or advisory.advisory_id == advisory_id
    ]


def _replace_component(pool: List[Dict[str, Any]], component: Dict[str, Any], replaces_id: str) -> str:
    for index, existing in enumerate(pool):
        if existing.get("component_id") in (replaces_id, component["component_id"]):
            pool[index] = component
            return "replaced"
    pool.append(component)
    return "added"


def shared_component_report(
    cabinet: Any,
    snapshots: List[Any],
    advisories: List[Any],
    decisions: Optional[List[Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    cabinet_obj = _cabinet(cabinet)
    snapshot_objs = _snapshots(snapshots)
    advisory_objs = _advisories(advisories)
    decision_items = decisions or _decisions(cabinet_obj, snapshot_objs, advisory_objs)
    usage: Dict[str, List[Dict[str, Any]]] = {}

    for decision in decision_items:
        for result in decision.get("condition_results", []):
            if result.get("scope") != HOST_COMMON:
                continue
            for witness in result.get("witnesses", []):
                component_id = witness.get("component_id")
                usage.setdefault(component_id, []).append({
                    "advisory_id": decision["advisory_id"],
                    "slot_id": decision["slot_id"],
                    "condition_id": result["condition_id"],
                    "decision_verdict": decision["verdict"],
                    "condition_status": result["status"],
                    "witness_id": witness.get("witness_id"),
                    "relation": witness.get("relation"),
                })

    reports = []
    for component in cabinet_obj.common_components:
        reports.append({
            "component_id": component["component_id"],
            "cpe": component["cpe"],
            "version": component.get("version"),
            "digest": component.get("digest"),
            "owner": component.get("owner") or cabinet_obj.host_owner,
            "identity_fingerprint": component["fingerprint"],
            "used_by": usage.get(component["component_id"], []),
            "responsibility_zh": (
                "主机公共组件由主机/平台责任方修复和举证；身份变化会同时影响所有槽的公共条件，"
                "但不替代任何 slot_strict 见证。"
            ),
        })
    return reports


def supplement_evidence(
    cabinet: Any,
    snapshots: List[Any],
    advisories: List[Any],
    supplement: Dict[str, Any],
) -> Dict[str, Any]:
    cabinet_obj = _cabinet(cabinet)
    snapshot_objs = _snapshots(snapshots)
    advisory_objs = _advisories(advisories)
    advisory_id = supplement.get("advisory_id")
    scope = supplement.get("scope", SLOT_STRICT)
    component = normalize_component(supplement["component"], scope)
    replaces_id = supplement.get("replaces_component_id") or component["component_id"]

    if scope == HOST_COMMON:
        updated_cabinet = copy.deepcopy(cabinet_obj)
        change = _replace_component(updated_cabinet.common_components, component, replaces_id)
        after = _decisions(updated_cabinet, snapshot_objs, advisory_objs, advisory_id)
        result: Dict[str, Any] = {
            "scope": HOST_COMMON,
            "change": change,
            "component_id": component["component_id"],
            "affected_slot_ids": [item.slot_id for item in snapshot_objs],
            "decisions_after": after,
            "responsibility_change_zh": (
                "单槽提交的公共部件证据会更新主机公共事实；主机/平台责任方不变，"
                "所有槽的公共条件都要重算，但各槽 strict 条件和结项责任仍归各槽。"
            ),
            "updated_cabinet": updated_cabinet.to_dict(),
        }
        if supplement.get("create_closure"):
            candidates = [item for item in after if item["closure_scope"] == "host"]
            if not candidates:
                raise ValueError("host-scoped closure requires a host-only advisory")
            result["closure"] = create_closure(candidates[0], **_closure_kwargs(supplement))
        return result

    slot_id = supplement["slot_id"]
    snapshot = _find_snapshot(snapshot_objs, slot_id)
    if supplement.get("snapshot_id") and supplement["snapshot_id"] != snapshot.snapshot_id:
        raise ValueError("supplement snapshot_id does not match target snapshot")

    before = _decisions(cabinet_obj, [snapshot], advisory_objs, advisory_id)
    updated_snapshot = copy.deepcopy(snapshot)
    change = _replace_component(updated_snapshot.components, component, replaces_id)
    suffix = sha256_text(snapshot.snapshot_id + component["fingerprint"])[:10]
    updated_snapshot.snapshot_id = supplement.get("new_snapshot_id") or (
        snapshot.snapshot_id + "+supp-" + suffix
    )
    after = _decisions(cabinet_obj, [updated_snapshot], advisory_objs, advisory_id)
    other_slots = [
        {"slot_id": item.slot_id, "changed": False}
        for item in snapshot_objs
        if item.slot_id != slot_id
    ]
    slot_result: Dict[str, Any] = {
        "scope": SLOT_STRICT,
        "change": change,
        "slot_id": slot_id,
        "component_id": component["component_id"],
        "snapshot_id_before": snapshot.snapshot_id,
        "snapshot_id_after": updated_snapshot.snapshot_id,
        "decisions_before": before,
        "decisions_after": after,
        "unaffected_slot_ids": [item["slot_id"] for item in other_slots],
        "responsibility_change_zh": (
            "单槽补证只更新该槽的当前快照和举证责任；提交方不替代槽责任方，"
            "其他槽的裁定、告警和结项责任均不改变。"
        ),
        "updated_snapshot": updated_snapshot.to_dict(),
    }
    if supplement.get("create_closure"):
        if not advisory_id:
            raise ValueError("advisory_id is required to create a closure from supplement")
        slot_result["closure"] = create_closure(after[0], **_closure_kwargs(supplement))
    return slot_result


def _closure_kwargs(source: Dict[str, Any]) -> Dict[str, Any]:
    closure = source.get("closure", source)
    if "closed_by" not in closure:
        raise ValueError("closed_by is required for closure creation")
    return {
        "closed_by": closure["closed_by"],
        "disposition": closure.get("disposition", "supplemented-evidence"),
        "closed_at": closure.get("closed_at"),
        "reason_zh": closure.get("reason_zh") or closure.get("reason"),
        "closure_id": closure.get("closure_id"),
    }


def migrate_slot(
    cabinet: Any,
    snapshots: List[Any],
    advisories: List[Any],
    migration: Dict[str, Any],
    closure_records: Optional[List[Any]] = None,
) -> Dict[str, Any]:
    cabinet_obj = _cabinet(cabinet)
    snapshot_objs = _snapshots(snapshots)
    advisory_objs = _advisories(advisories)
    from_slot = migration["from_slot_id"]
    to_slot = migration["to_slot_id"]
    old_snapshot = _find_snapshot(snapshot_objs, from_slot)

    new_snapshot = snapshot_from(migration["new_snapshot"])
    if new_snapshot.slot_id != to_slot:
        raise ValueError("migration new_snapshot.slot_id must equal to_slot_id")

    advisory_id = migration.get("advisory_id")
    new_decisions = _decisions(cabinet_obj, [new_snapshot], advisory_objs, advisory_id)
    records = [as_mapping(item) for item in (closure_records or [])]
    old_closures = [
        item for item in records
        if item.get("slot_id") == from_slot
        and (advisory_id is None or item.get("advisory_id") == advisory_id)
    ]

    substitution_checks = []
    for record in old_closures:
        advisory = _find_advisory(advisory_objs, record["advisory_id"])
        substitution_checks.append(verify_closure(record, advisory, cabinet_obj, new_snapshot))

    new_fingerprints = {item["fingerprint"] for item in new_snapshot.components}
    strict_continuity = []
    common_continuity = []
    common_fingerprints = {item["fingerprint"] for item in cabinet_obj.common_components}
    for record in old_closures:
        for witness in record.get("witnesses", []):
            item = {
                "closure_id": record.get("closure_id"),
                "witness_id": witness.get("witness_id"),
                "component_id": witness.get("component_id"),
                "identity_fingerprint": witness.get("identity_fingerprint"),
            }
            if witness.get("condition_scope") == SLOT_STRICT:
                item["identity_present_in_new_slot"] = witness.get("identity_fingerprint") in new_fingerprints
                item["new_slot_re_witness_required"] = True
                strict_continuity.append(item)
            elif witness.get("identity_fingerprint") in common_fingerprints:
                common_continuity.append(item)

    result: Dict[str, Any] = {
        "migration_id": migration.get("migration_id"),
        "from_slot_id": from_slot,
        "to_slot_id": to_slot,
        "old_snapshot_id": old_snapshot.snapshot_id,
        "new_snapshot_id": new_snapshot.snapshot_id,
        "new_slot_decisions": new_decisions,
        "old_closure_substitution_checks": substitution_checks,
        "strict_witness_continuity": strict_continuity,
        "verified_common_continuity": common_continuity,
        "responsibility_change_zh": (
            "切换前由旧槽责任方负责；切换点后由新槽责任方负责。迁移实施方只负责交接和重扫，"
            "主机公共组件责任不变。旧槽结项不能作为新槽结项，必须以新槽快照重新见证 strict 部件。"
        ),
    }
    closure_request = migration.get("closure_request")
    if closure_request:
        target_advisory_id = closure_request.get("advisory_id") or advisory_id
        if not target_advisory_id:
            raise ValueError("advisory_id is required for migration closure")
        decision = next(
            item for item in new_decisions if item["advisory_id"] == target_advisory_id
        )
        result["new_slot_closure"] = create_closure(decision, **_closure_kwargs(closure_request))
    return result
