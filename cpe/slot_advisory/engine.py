"""Slot-scoped advisory adjudication and witness-bound closure records."""

from __future__ import annotations

import copy
from typing import Any, Dict, List, Optional

from .matching import (
    canonical_json,
    identity_fingerprint,
    is_affected_component,
    normalize_component,
    product_matches,
    sha256_text,
)
from .model import (
    HOST_COMMON,
    CLOSURE_SCOPE_HOST as HOST,
    CLOSURE_SCOPE_SLOT as SLOT,
    SLOT_STRICT,
    VERDICT_APPLICABLE,
    VERDICT_NOT_APPLICABLE,
    VERDICT_UNKNOWN,
    Advisory,
    Cabinet,
    SlotSnapshot,
    advisory_from,
    as_mapping,
    cabinet_from,
    snapshot_from,
)


class SlotAdvisoryError(ValueError):
    """Base error for invalid slot adjudication operations."""


class ClosureNotAllowedError(SlotAdvisoryError):
    """Raised when an applicable or unknown verdict cannot be closed."""



def _scope_pool(cabinet: Cabinet, snapshot: SlotSnapshot, scope: str) -> List[Dict[str, Any]]:
    if scope == HOST_COMMON:
        return cabinet.common_components
    return snapshot.components


def _witness(
    condition: Dict[str, Any],
    component: Dict[str, Any],
    cabinet: Cabinet,
    snapshot: SlotSnapshot,
    relation: str,
) -> Dict[str, Any]:
    scope = condition["scope"]
    strict = scope == SLOT_STRICT
    witness_seed = canonical_json(
        [condition["id"], scope, snapshot.slot_id if strict else None, component["fingerprint"]]
    )
    return {
        "witness_id": "WIT-" + sha256_text(witness_seed)[:16],
        "condition_id": condition["id"],
        "condition_scope": scope,
        "slot_id": snapshot.slot_id if strict else None,
        "host_id": cabinet.host_id,
        "cabinet_id": cabinet.cabinet_id,
        "snapshot_id": snapshot.snapshot_id if strict else cabinet.common_snapshot_id or "host-common",
        "component_id": component["component_id"],
        "component_cpe": component["cpe"],
        "component_version": component.get("version"),
        "digest": component.get("digest"),
        "path": component.get("path"),
        "owner": component.get("owner"),
        "identity_fingerprint": component["fingerprint"],
        "relation": relation,
        "observed_at": snapshot.captured_at if strict else None,
    }


def evaluate_condition(
    condition: Dict[str, Any], cabinet: Cabinet, snapshot: SlotSnapshot
) -> Dict[str, Any]:
    pool = _scope_pool(cabinet, snapshot, condition["scope"])
    product_observations = [item for item in pool if product_matches(condition, item)]

    if not product_observations:
        status = "not_found"
        reason_zh = "未在{}清单中找到条件指向的 CPE 产品。".format(
            "主机公共组件" if condition["scope"] == HOST_COMMON else "本槽组件"
        )
        return {
            "condition_id": condition["id"],
            "scope": condition["scope"],
            "status": status,
            "description_zh": condition.get("description_zh"),
            "reason_zh": reason_zh,
            "witnesses": [],
        }

    witnesses: List[Dict[str, Any]] = []
    affected: List[Dict[str, Any]] = []
    for component in product_observations:
        is_vulnerable = is_affected_component(condition, component)
        relation = "affected" if is_vulnerable else "unaffected"
        witness = _witness(condition, component, cabinet, snapshot, relation)
        witnesses.append(witness)
        if is_vulnerable:
            affected.append(witness)

    if affected:
        status = "matched"
        reason_zh = "找到满足公告条件的受影响部件。"
    else:
        status = "unaffected"
        reason_zh = "找到同产品部件，但其当前身份/版本不满足受影响条件。"

    return {
        "condition_id": condition["id"],
        "scope": condition["scope"],
        "status": status,
        "description_zh": condition.get("description_zh"),
        "reason_zh": reason_zh,
        "witnesses": witnesses,
    }


def _responsibility(
    condition: Dict[str, Any],
    result: Dict[str, Any],
    cabinet: Cabinet,
    snapshot: SlotSnapshot,
) -> Dict[str, Any]:
    owners = [witness.get("owner") for witness in result.get("witnesses", []) if witness.get("owner")]
    component_owner = owners[0] if owners else None

    if condition["scope"] == HOST_COMMON:
        owner = component_owner or cabinet.host_owner or "host-common-owner"
        return {
            "condition_id": condition["id"],
            "scope": HOST_COMMON,
            "responsible_owner": owner,
            "basis": "component.owner" if component_owner else "cabinet.host_owner",
            "cross_slot_effect_zh": "该见证是主机公共事实，可被同一主机上的所有槽复用。",
            "closure_effect_zh": "它能证明公共条件的状态，但不能代替任何 slot_strict 条件的本槽见证。",
        }

    owner = component_owner or snapshot.slot_owner or "slot:" + snapshot.slot_id + ":owner"
    return {
        "condition_id": condition["id"],
        "scope": SLOT_STRICT,
        "responsible_owner": owner,
        "basis": "component.owner" if component_owner else "snapshot.slot_owner",
        "cross_slot_effect_zh": "该见证严格绑定槽位、快照和部件身份，不能转移到其他应用槽。",
        "closure_effect_zh": "只有该槽的结项记录可以使用该见证关闭对应严格条件。",
    }


def adjudicate_slot(
    advisory: Any, cabinet: Any, snapshot: Any
) -> Dict[str, Any]:
    advisory_obj = advisory if isinstance(advisory, Advisory) else advisory_from(advisory)
    cabinet_obj = cabinet if isinstance(cabinet, Cabinet) else cabinet_from(cabinet)
    snapshot_obj = snapshot if isinstance(snapshot, SlotSnapshot) else snapshot_from(snapshot)

    if snapshot_obj.host_id and snapshot_obj.host_id != cabinet_obj.host_id:
        raise SlotAdvisoryError("snapshot host_id does not match cabinet host_id")

    advisory_data = advisory_obj.to_dict()
    results = [
        evaluate_condition(condition, cabinet_obj, snapshot_obj)
        for condition in advisory_data["conditions"]
    ]
    statuses = [item["status"] for item in results]
    operator = advisory_data["operator"]

    if operator == "all":
        if all(status == "matched" for status in statuses):
            verdict = VERDICT_APPLICABLE
            reason_codes = ["ALL_CONDITIONS_MATCHED"]
            explanation = "所有条件均命中，公告对该应用槽适用。"
        elif any(status == "unaffected" for status in statuses):
            verdict = VERDICT_NOT_APPLICABLE
            decisive = [r["condition_id"] for r in results if r["status"] == "unaffected"]
            reason_codes = ["DEFINITIVE_UNAFFECTED:" + item for item in decisive]
            explanation = "至少一个必要条件已由当前部件身份证明不受影响，公告对该槽不适用。"
        else:
            verdict = VERDICT_UNKNOWN
            missing = [r["condition_id"] for r in results if r["status"] == "not_found"]
            reason_codes = ["MISSING_EVIDENCE:" + item for item in missing]
            explanation = "缺少可判定条件的部件见证，不能把未扫到直接当作已修复。"
    else:
        if any(status == "matched" for status in statuses):
            verdict = VERDICT_APPLICABLE
            reason_codes = ["ANY_CONDITION_MATCHED"]
            explanation = "至少一个替代条件命中，公告对该应用槽适用。"
        elif all(status == "unaffected" for status in statuses):
            verdict = VERDICT_NOT_APPLICABLE
            reason_codes = ["ALL_CONDITIONS_UNAFFECTED"]
            explanation = "所有替代条件均有明确的不受影响见证，公告对该槽不适用。"
        else:
            verdict = VERDICT_UNKNOWN
            reason_codes = ["NO_MATCH_AND_INCOMPLETE_EVIDENCE"]
            explanation = "没有命中条件，但存在缺失证据，不能作出确定不适用裁定。"

    has_strict = any(condition["scope"] == SLOT_STRICT for condition in advisory_data["conditions"])
    closure_scope = SLOT if has_strict else HOST
    responsibilities = [
        _responsibility(condition, result, cabinet_obj, snapshot_obj)
        for condition, result in zip(advisory_data["conditions"], results)
    ]
    decision_seed = {
        "advisory_id": advisory_obj.advisory_id,
        "slot_id": snapshot_obj.slot_id,
        "snapshot_id": snapshot_obj.snapshot_id,
        "verdict": verdict,
        "results": [
            {
                "condition_id": item["condition_id"],
                "status": item["status"],
                "fingerprints": [w["identity_fingerprint"] for w in item["witnesses"]],
            }
            for item in results
        ],
    }

    return {
        "decision_id": "DEC-" + identity_fingerprint(decision_seed)[:12],
        "advisory_id": advisory_obj.advisory_id,
        "advisory_title": advisory_obj.title,
        "cabinet_id": cabinet_obj.cabinet_id,
        "host_id": cabinet_obj.host_id,
        "slot_id": snapshot_obj.slot_id,
        "snapshot_id": snapshot_obj.snapshot_id,
        "slot_owner": snapshot_obj.slot_owner,
        "application": snapshot_obj.application,
        "verdict": verdict,
        "applicable": verdict == VERDICT_APPLICABLE,
        "closure_scope": closure_scope,
        "reason_codes": reason_codes,
        "explanation_zh": explanation,
        "condition_results": results,
        "responsibility": responsibilities,
    }


def create_closure(
    decision: Dict[str, Any],
    *,
    closed_by: str,
    disposition: str = "fixed",
    closed_at: Optional[str] = None,
    reason_zh: Optional[str] = None,
    closure_id: Optional[str] = None,
) -> Dict[str, Any]:
    if decision["verdict"] == VERDICT_APPLICABLE:
        raise ClosureNotAllowedError("cannot close an advisory that is currently applicable")
    if decision["verdict"] == VERDICT_UNKNOWN:
        raise ClosureNotAllowedError("insufficient witness evidence; supplement evidence before closure")

    witnesses: List[Dict[str, Any]] = []
    decisive: List[str] = []
    for result in decision["condition_results"]:
        result_witnesses = result.get("witnesses", [])
        witnesses.extend(result_witnesses)
        if result["status"] == "unaffected":
            decisive.extend(w["witness_id"] for w in result_witnesses if w["relation"] == "unaffected")

    scope = decision["closure_scope"]
    record: Dict[str, Any] = {
        "record_type": "slot-advisory-closure/v1",
        "closure_id": closure_id,
        "advisory_id": decision["advisory_id"],
        "decision_id": decision["decision_id"],
        "cabinet_id": decision["cabinet_id"],
        "host_id": decision["host_id"],
        "closure_scope": scope,
        "slot_id": decision["slot_id"] if scope == SLOT else None,
        "snapshot_id": decision["snapshot_id"] if scope == SLOT else None,
        "verdict_at_closure": VERDICT_NOT_APPLICABLE,
        "disposition": disposition,
        "closed_by": closed_by,
        "closed_at": closed_at,
        "reason_zh": reason_zh,
        "witnesses": witnesses,
        "decisive_witness_ids": decisive,
        "responsibility": decision["responsibility"],
    }
    if not record["closure_id"]:
        seed = canonical_json([
            decision["decision_id"], decision["slot_id"], closed_by, closed_at, disposition
        ])
        record["closure_id"] = "CLS-" + sha256_text(seed)[:12].upper()
    record["record_hash"] = sha256_text(
        canonical_json({key: value for key, value in record.items() if key != "record_hash"})
    )
    return record


def _hash_without_stored(record: Dict[str, Any]) -> str:
    return sha256_text(
        canonical_json({key: value for key, value in record.items() if key != "record_hash"})
    )


def verify_closure(
    closure: Any,
    advisory: Any,
    cabinet: Any,
    snapshot: Any,
) -> Dict[str, Any]:
    record = closure if isinstance(closure, dict) else as_mapping(closure)
    advisory_obj = advisory if isinstance(advisory, Advisory) else advisory_from(advisory)
    cabinet_obj = cabinet if isinstance(cabinet, Cabinet) else cabinet_from(cabinet)
    snapshot_obj = snapshot if isinstance(snapshot, SlotSnapshot) else snapshot_from(snapshot)
    issues: List[Dict[str, str]] = []

    def add_issue(code: str, message: str, expected: Any = None, actual: Any = None) -> None:
        issues.append({"code": code, "message_zh": message, "expected": expected, "actual": actual})

    if record.get("record_hash") != _hash_without_stored(record):
        add_issue("RECORD_TAMPERED", "结项记录哈希不一致，记录内容可能已被改动。")
    if record.get("cabinet_id") != cabinet_obj.cabinet_id:
        add_issue("CABINET_MISMATCH", "结项记录不属于当前控制柜。", cabinet_obj.cabinet_id, record.get("cabinet_id"))
    if record.get("host_id") != cabinet_obj.host_id:
        add_issue("HOST_MISMATCH", "结项记录的主机编号与当前控制柜不一致。", cabinet_obj.host_id, record.get("host_id"))
    if record.get("advisory_id") != advisory_obj.advisory_id:
        add_issue("ADVISORY_MISMATCH", "结项记录对应其他公告。", advisory_obj.advisory_id, record.get("advisory_id"))

    if record.get("closure_scope") == SLOT or record.get("slot_id"):
        if record.get("slot_id") != snapshot_obj.slot_id:
            add_issue(
                "SLOT_MISMATCH",
                "结项记录绑定的是另一个应用槽，不能作为本槽结项。",
                snapshot_obj.slot_id,
                record.get("slot_id"),
            )
        if record.get("snapshot_id") and record.get("snapshot_id") != snapshot_obj.snapshot_id:
            add_issue(
                "SNAPSHOT_MISMATCH",
                "结项见证来自另一份快照，必须用当前槽快照重新核对或补证。",
                snapshot_obj.snapshot_id,
                record.get("snapshot_id"),
            )

    common_by_id = {item["component_id"]: item for item in cabinet_obj.common_components}
    slot_by_id = {item["component_id"]: item for item in snapshot_obj.components}
    verified_common: List[str] = []
    verified_strict: List[str] = []

    for witness in record.get("witnesses", []):
        component_id = witness.get("component_id")
        if witness.get("condition_scope") == HOST_COMMON:
            component = common_by_id.get(component_id)
            if not component:
                add_issue("COMMON_WITNESS_NOT_FOUND", "主机公共清单中找不到结项记录的公共部件身份。", component_id)
            elif component["fingerprint"] != witness.get("identity_fingerprint"):
                add_issue("COMMON_WITNESS_CHANGED", "主机公共部件身份或版本已变化，旧公共见证不能直接沿用。", component_id)
            else:
                verified_common.append(witness.get("witness_id"))
            continue

        if witness.get("slot_id") != snapshot_obj.slot_id:
            add_issue(
                "STRICT_WITNESS_SLOT_MISMATCH",
                "严格本槽部件见证绑定在其他槽，不能在当前槽使用。",
                snapshot_obj.slot_id,
                witness.get("slot_id"),
            )
        component = slot_by_id.get(component_id)
        if not component:
            add_issue("STRICT_WITNESS_NOT_IN_SLOT", "当前槽快照中找不到结项记录见证的严格部件身份。", component_id)
        elif component["fingerprint"] != witness.get("identity_fingerprint"):
            add_issue("STRICT_WITNESS_CHANGED", "当前槽同 ID 部件的 CPE、版本或摘要已变化，旧见证失效。", component_id)
        else:
            verified_strict.append(witness.get("witness_id"))

    current_decision = adjudicate_slot(advisory_obj, cabinet_obj, snapshot_obj)
    if current_decision["verdict"] == VERDICT_APPLICABLE:
        add_issue("TARGET_STILL_APPLICABLE", "按当前槽快照重新裁定，公告仍然适用；其他槽的修复不能消除本槽责任。")
    elif current_decision["verdict"] == VERDICT_UNKNOWN:
        add_issue("TARGET_EVIDENCE_INCOMPLETE", "当前槽证据不足，不能用旧结项代替补证。")

    codes = [item["code"] for item in issues]
    accepted = not issues
    if accepted:
        explanation = "槽位、快照、见证指纹和当前裁定均匹配；该结项记录可用于此槽。"
    else:
        explanation = (
            "不能用该结项代替当前槽结项：主机编号只说明它们共用控制柜/主机，"
            "slot_strict 条件要求当前槽自己的部件身份和快照见证。"
        )
        if "TARGET_STILL_APPLICABLE" in codes:
            explanation += " 当前快照仍判定公告适用。"
        if verified_common:
            explanation += " 已核对的公共见证只能作为主机公共事实复用，不能跨越严格槽位边界。"

    return {
        "accepted": accepted,
        "closure_id": record.get("closure_id"),
        "closure_scope": record.get("closure_scope"),
        "source_slot_id": record.get("slot_id"),
        "target_slot_id": snapshot_obj.slot_id,
        "reason_codes": codes,
        "issues": issues,
        "explanation_zh": explanation,
        "verified_common_witness_ids": verified_common,
        "verified_strict_witness_ids": verified_strict,
        "current_decision_id": current_decision["decision_id"],
        "current_verdict": current_decision["verdict"],
    }


def responsibility_rules() -> List[Dict[str, str]]:
    return [
        {
            "case": "host_common",
            "rule_zh": "主机公共组件由主机/平台责任方维护；其见证是全主机事实，可被各槽复用。",
        },
        {
            "case": "slot_strict",
            "rule_zh": "严格本槽组件由该应用槽责任方维护；结项必须绑定本槽快照和部件身份。",
        },
        {
            "case": "shared_component",
            "rule_zh": "共享组件修复只改变公共条件；所有槽都要重新裁定各自严格条件，不能生成主机级一锅端结项。",
        },
        {
            "case": "migration",
            "rule_zh": "迁到新槽后责任在切换点转移给新槽；旧槽结项只能作历史记录，新槽必须重新见证严格部件。",
        },
        {
            "case": "single_slot_supplement",
            "rule_zh": "单槽补证默认只改变该槽；若补的是经确认的主机公共事实，可重算所有槽的公共条件，但不转移各槽严格责任。",
        },
    ]
