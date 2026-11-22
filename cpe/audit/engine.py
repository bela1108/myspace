#! /usr/bin/env python
# -*- coding: utf-8 -*-

"""
Advisory withdrawal impact decisions.

The engine combines four independent inputs:

* the CPE applicability expression published with the advisory;
* the inventory scope explicitly approved by the caller;
* an inventory snapshot before withdrawal and one after withdrawal;
* replacement credentials for individual component slots.

Every conclusion is emitted with the facts and evidence references that
support it.  Absence of a match is never used as proof that an asset family
is outside the advisory scope; that requires complete family inventory
coverage for the advisory applicability interval.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .matching import (
    MATCH,
    NO_MATCH,
    UNKNOWN,
    ExpressionEvaluation,
    cpe_relation,
    evaluate_expression,
)
from .model import (
    Advisory,
    ComponentRecord,
    InventoryScope,
    InventorySnapshot,
    ReplacementEvidence,
    format_timestamp,
)


CONFIRMED_CLOSED = "confirmed_closed"
STILL_AFFECTED = "still_affected"
INSUFFICIENT_EVIDENCE = "insufficient_evidence"
OUT_OF_SCOPE = "out_of_scope"

STATUS_LABELS = {
    CONFIRMED_CLOSED: "确已关闭",
    STILL_AFFECTED: "仍受影响",
    INSUFFICIENT_EVIDENCE: "缺证",
    OUT_OF_SCOPE: "不在调用者认可范围",
}

FAMILY_EXCLUDED = "excluded"
FAMILY_RESOLVED = "resolved"
FAMILY_UNRESOLVED = "unresolved"

FAMILY_LABELS = {
    FAMILY_EXCLUDED: "已排除",
    FAMILY_RESOLVED: "已定性",
    FAMILY_UNRESOLVED: "缺证",
}


@dataclass
class ReplacementCheck:
    """Validation result for replacement evidence."""

    provided: bool = False
    valid: bool = False
    reasons: List[str] = field(default_factory=list)
    evidence_ref: str = ""
    evidence: Optional[ReplacementEvidence] = None

    def to_dict(self):
        return {
            "provided": self.provided,
            "valid": self.valid,
            "reasons": list(self.reasons),
            "evidence_ref": self.evidence_ref,
            "evidence": self.evidence.to_dict() if self.evidence else None,
        }


@dataclass
class AssetAuditResult:
    """Final decision for one asset together with its audit trail."""

    asset_id: str
    family: str
    status: str
    basis: List[str]
    evidence_refs: List[str]
    before: Optional[ExpressionEvaluation] = None
    after: Optional[ExpressionEvaluation] = None
    replacement: ReplacementCheck = field(default_factory=ReplacementCheck)
    snapshot_evidence: Dict[str, str] = field(default_factory=dict)

    @property
    def label(self):
        return STATUS_LABELS.get(self.status, self.status)

    def to_dict(self):
        return {
            "asset_id": self.asset_id,
            "family": self.family,
            "status": self.status,
            "label": self.label,
            "basis": list(self.basis),
            "evidence_refs": list(self.evidence_refs),
            "before": self.before.to_dict() if self.before else None,
            "after": self.after.to_dict() if self.after else None,
            "replacement": self.replacement.to_dict()
            if self.replacement.provided else None,
            "snapshot_evidence": dict(self.snapshot_evidence),
        }


@dataclass
class FamilyAssessment:
    """Family-level conclusion, including the exclusion guard."""

    family: str
    status: str
    basis: List[str]
    evidence_refs: List[str]
    asset_ids: List[str] = field(default_factory=list)

    @property
    def label(self):
        return FAMILY_LABELS.get(self.status, self.status)

    def to_dict(self):
        return {
            "family": self.family,
            "status": self.status,
            "label": self.label,
            "asset_ids": list(self.asset_ids),
            "basis": list(self.basis),
            "evidence_refs": list(self.evidence_refs),
        }


@dataclass
class AuditReport:
    """Serializable result of one withdrawal re-audit."""

    advisory: Advisory
    scope: InventoryScope
    before_snapshot: Optional[InventorySnapshot]
    after_snapshot: InventorySnapshot
    results: List[AssetAuditResult]
    families: List[FamilyAssessment]
    out_of_scope: List[dict]
    snapshot_evaluations: Dict[str, dict]

    def by_status(self, status):
        return [result for result in self.results if result.status == status]

    @property
    def complete(self):
        return (not self.by_status(INSUFFICIENT_EVIDENCE) and
                not [family for family in self.families
                     if family.status == FAMILY_UNRESOLVED])

    def _summary(self):
        closed = len(self.by_status(CONFIRMED_CLOSED))
        affected = len(self.by_status(STILL_AFFECTED))
        missing = len(self.by_status(INSUFFICIENT_EVIDENCE))
        status = "完整" if self.complete else "不完整"
        return ("可证明范围{0}：{1} 台已审计资产中，"
                "{2} 台确已关闭、{3} 台仍受影响、{4} 台缺证。").format(
                    status, len(self.results), closed, affected, missing)

    def to_dict(self):
        def bucket(status):
            return [result.to_dict() for result in self.by_status(status)]

        excluded = [family for family in self.families
                    if family.status == FAMILY_EXCLUDED]
        resolved = [family for family in self.families
                    if family.status == FAMILY_RESOLVED]
        unresolved = [family for family in self.families
                      if family.status == FAMILY_UNRESOLVED]

        reconciliation = []
        for result in self.results:
            reconciliation.append({
                "asset_id": result.asset_id,
                "family": result.family,
                "before_snapshot": (self.before_snapshot.snapshot_id
                                    if self.before_snapshot else None),
                "before_match": result.before.value if result.before else None,
                "after_snapshot": self.after_snapshot.snapshot_id,
                "after_match": result.after.value if result.after else None,
                "result": result.status,
                "result_label": result.label,
            })

        return {
            "advisory": self.advisory.to_dict(),
            "caller_scope": self.scope.to_dict(),
            "provable_scope": {
                "complete": self.complete,
                "summary": self._summary(),
                "confirmed_closed": [result.asset_id
                                     for result in self.by_status(CONFIRMED_CLOSED)],
                "still_affected": [result.asset_id
                                   for result in self.by_status(STILL_AFFECTED)],
                "insufficient_evidence": [result.asset_id
                                          for result in self.by_status(INSUFFICIENT_EVIDENCE)],
                "out_of_scope_assets": [item["asset_id"]
                                        for item in self.out_of_scope],
                "excluded_families": [family.to_dict() for family in excluded],
                "resolved_families": [family.to_dict() for family in resolved],
                "unresolved_families": [family.to_dict() for family in unresolved],
                "rule": ("排除某族必须有该族完整库存证据，且覆盖公告适用区间；"
                         "未匹配本身不能推出排除。"),
            },
            "results": {
                CONFIRMED_CLOSED: bucket(CONFIRMED_CLOSED),
                STILL_AFFECTED: bucket(STILL_AFFECTED),
                INSUFFICIENT_EVIDENCE: bucket(INSUFFICIENT_EVIDENCE),
                OUT_OF_SCOPE: list(self.out_of_scope),
            },
            "snapshot_reconciliation": reconciliation,
            "snapshots": self.snapshot_evaluations,
        }


def _components_with_override(components, slot, cpe, evidence_ref):
    replaced = False
    result = []
    for component in components:
        if component.slot == slot:
            result.append(ComponentRecord(slot=slot, cpe=cpe,
                                          evidence_ref=evidence_ref))
            replaced = True
        else:
            result.append(component)
    if not replaced:
        result.append(ComponentRecord(slot=slot, cpe=cpe,
                                      evidence_ref=evidence_ref))
    return result


def _validate_replacement(evidence, advisory, before_asset, after_asset):
    """Check that one credential proves an affected slot became safe."""

    check = ReplacementCheck(
        provided=True,
        evidence_ref=evidence.evidence_ref or evidence.credential_ref,
        evidence=evidence,
    )
    reasons = check.reasons

    if not evidence.verified:
        reasons.append("替换凭据 {0} 未经核实（verified=false）。".format(
            evidence.credential_ref or evidence.evidence_ref or "<unnamed>"))
    if not evidence.credential_ref:
        reasons.append("替换凭据缺少 credential_ref，无法追溯变更单。")

    before_component = before_asset.component_for_slot(evidence.slot)
    after_component = after_asset.component_for_slot(evidence.slot)
    if before_component is None:
        reasons.append("撤回前快照缺少槽位 {0}，无法证明旧组件曾存在。".format(
            evidence.slot))
    if after_component is None:
        reasons.append("撤回后快照缺少槽位 {0}，无法证明新组件已落地。".format(
            evidence.slot))

    old_components = _components_with_override(
        before_asset.components, evidence.slot, evidence.old_cpe,
        evidence.evidence_ref or evidence.credential_ref)
    old_eval = evaluate_expression(advisory.expression, old_components,
                                   before_asset.manifest_complete)
    reasons.append("用旧组件 {0} 回放撤回前上下文，公告判断为 {1}。".format(
        evidence.old_cpe, old_eval.value))
    reasons.extend(old_eval.basis)
    if old_eval.value != MATCH:
        reasons.append("旧组件不能证明在公告适用表达式内命中。")

    new_components = _components_with_override(
        after_asset.components, evidence.slot, evidence.new_cpe,
        evidence.evidence_ref or evidence.credential_ref)
    new_eval = evaluate_expression(advisory.expression, new_components,
                                   after_asset.manifest_complete)
    reasons.append("用新组件 {0} 回放撤回后上下文，公告判断为 {1}。".format(
        evidence.new_cpe, new_eval.value))
    reasons.extend(new_eval.basis)
    if new_eval.value != NO_MATCH:
        reasons.append("新组件不能证明与公告表达式不相交。")

    if before_component is not None:
        relation, detail = cpe_relation(evidence.old_cpe, before_component.cpe)
        reasons.append("撤回前快照槽位实际值为 {0}，与凭据旧组件关系为 {1}（{2}）。".format(
            before_component.cpe, relation, detail))
        if relation != MATCH:
            reasons.append("凭据旧组件与撤回前快照不一致。")

    if after_component is not None:
        relation, detail = cpe_relation(evidence.new_cpe, after_component.cpe)
        reasons.append("撤回后快照槽位实际值为 {0}，与凭据新组件关系为 {1}（{2}）。".format(
            after_component.cpe, relation, detail))
        if relation != MATCH:
            reasons.append("凭据新组件与撤回后快照不一致。")

    if evidence.effective_at < advisory.published_at:
        reasons.append("替换生效时间 {0} 早于公告发布时间 {1}。".format(
            format_timestamp(evidence.effective_at),
            format_timestamp(advisory.published_at)))
    if evidence.effective_at < before_asset.observed_at:
        reasons.append("替换生效时间 {0} 早于撤回前快照观测时间 {1}。".format(
            format_timestamp(evidence.effective_at),
            format_timestamp(before_asset.observed_at)))
    if evidence.effective_at > after_asset.observed_at:
        reasons.append("替换生效时间 {0} 晚于撤回后快照观测时间 {1}。".format(
            format_timestamp(evidence.effective_at),
            format_timestamp(after_asset.observed_at)))

    disqualifiers = (
        not evidence.verified or
        not evidence.credential_ref or
        before_component is None or
        after_component is None or
        old_eval.value != MATCH or
        new_eval.value != NO_MATCH or
        evidence.effective_at < advisory.published_at or
        evidence.effective_at < before_asset.observed_at or
        evidence.effective_at > after_asset.observed_at
    )
    if before_component is not None:
        disqualifiers = disqualifiers or (
            cpe_relation(evidence.old_cpe, before_component.cpe)[0] != MATCH)
    if after_component is not None:
        disqualifiers = disqualifiers or (
            cpe_relation(evidence.new_cpe, after_component.cpe)[0] != MATCH)

    check.valid = not disqualifiers
    if check.valid:
        reasons.append(
            "替换凭据通过校验：旧组件命中公告，新组件不相交，且生效时间"
            "位于公告发布之后、撤回后快照之前。")
    return check


def _replacement_check(asset_id, replacements, advisory, before_asset,
                       after_asset):
    candidates = [item for item in replacements if item.asset_id == asset_id]
    if not candidates:
        return ReplacementCheck(
            provided=False,
            valid=False,
            reasons=["未提供该资产的组件替换凭据。"],
        )
    checks = [_validate_replacement(item, advisory, before_asset, after_asset)
              for item in candidates]
    valid = [check for check in checks if check.valid]
    if valid:
        return valid[0]
    if len(checks) > 1:
        checks[0].reasons.append("共提供 {0} 份替换凭据，均不能证明关闭。".format(
            len(checks)))
    return checks[0]


def _scope_basis(scope, asset_id):
    return ("调用者认可的库存范围包含资产 {0}（scope_ref={1}, approved_by={2}, "
            "approved_at={3}）。").format(
                asset_id,
                scope.scope_ref or "<none>",
                scope.approved_by or "<unspecified>",
                format_timestamp(scope.approved_at) or "<unspecified>")


def _interval_basis(advisory, before_asset, after_asset):
    basis = ["公告适用区间为 {0}。".format(
        advisory.applicability_interval.label())]
    for name, asset in (("撤回前", before_asset), ("撤回后", after_asset)):
        if asset is None:
            basis.append("{0}没有该资产的库存快照。".format(name))
            continue
        inside = advisory.applicability_interval.contains(asset.observed_at)
        basis.append("{0}快照观测时间 {1} {2}公告适用区间内。".format(
            name,
            format_timestamp(asset.observed_at),
            "位于" if inside else "不在"))
    return basis


def _evaluate_snapshot(snapshot, advisory):
    if snapshot is None:
        return {}
    result = {}
    for asset_id, asset in sorted(snapshot.assets.items()):
        evaluation = evaluate_expression(
            advisory.expression, asset.components, asset.manifest_complete)
        result[asset_id] = {
            "asset_id": asset.asset_id,
            "family": asset.family,
            "observed_at": format_timestamp(asset.observed_at),
            "manifest_complete": asset.manifest_complete,
            "evidence_ref": asset.evidence_ref,
            "match": evaluation.value,
            "basis": list(evaluation.basis),
            "facts": [fact.to_dict() for fact in evaluation.facts],
        }
    return result


def _audit_asset(advisory, scope, asset_id, before_asset, after_asset,
                 replacements):
    evidence_refs = []
    basis = []

    family = (after_asset.family if after_asset is not None
              else before_asset.family if before_asset is not None else "")

    if after_asset is None:
        basis.append("撤回后库存没有资产 {0} 的记录。".format(asset_id))
        return AssetAuditResult(
            asset_id=asset_id,
            family=family,
            status=INSUFFICIENT_EVIDENCE,
            basis=basis,
            evidence_refs=evidence_refs,
            before=None,
            after=None,
            replacement=ReplacementCheck(
                provided=False,
                reasons=["撤回后库存没有该资产记录。"]),
        )

    before_eval = None
    after_eval = evaluate_expression(
        advisory.expression, after_asset.components,
        after_asset.manifest_complete)

    basis.append(_scope_basis(scope, asset_id))
    basis.extend(_interval_basis(advisory, before_asset, after_asset))

    if before_asset is not None:
        before_eval = evaluate_expression(
            advisory.expression, before_asset.components,
            before_asset.manifest_complete)
        basis.append("撤回前快照 {0} 对公告表达式的判断为 {1}（evidence_ref={2}）。".format(
            format_timestamp(before_asset.observed_at),
            before_eval.value,
            before_asset.evidence_ref or "<none>"))
        basis.extend(before_eval.basis)

    basis.append("撤回后快照 {0} 对公告表达式的判断为 {1}（evidence_ref={2}）。".format(
        format_timestamp(after_asset.observed_at),
        after_eval.value,
        after_asset.evidence_ref or "<none>"))
    basis.extend(after_eval.basis)

    if not after_asset.manifest_complete:
        basis.append("撤回后安装清单 manifest_complete=false：缺项不能当作"
                     "组件不存在。")

    snapshot_evidence = {
        "before": (before_asset.evidence_ref if before_asset else ""),
        "after": after_asset.evidence_ref,
    }
    for ref in snapshot_evidence.values():
        if ref:
            evidence_refs.append(ref)

    replacement = None
    if before_asset is not None:
        replacement = _replacement_check(
            asset_id, replacements, advisory, before_asset, after_asset)
        if replacement.evidence_ref:
            evidence_refs.append(replacement.evidence_ref)

    def status_result(status, extra_basis):
        return AssetAuditResult(
            asset_id=asset_id,
            family=family,
            status=status,
            basis=basis + list(extra_basis),
            evidence_refs=list(dict.fromkeys(evidence_refs)),
            before=before_eval,
            after=after_eval,
            replacement=replacement or ReplacementCheck(provided=False),
            snapshot_evidence=snapshot_evidence,
        )

    if after_eval.value == MATCH:
        if replacement is not None and replacement.valid:
            extra = list(replacement.reasons)
            extra.append("替换后公告判断为 {0}，且撤回后快照已落地新组件，"
                         "故确已关闭。".format(after_eval.value))
            return status_result(CONFIRMED_CLOSED, extra)
        extra = []
        if replacement is not None:
            extra.extend(replacement.reasons)
        extra.append("撤回后库存仍命中公告表达式，且没有通过的替换凭据；"
                     "公告撤回不会移除已安装组件，故仍受影响。")
        return status_result(STILL_AFFECTED, extra)

    if after_eval.value == UNKNOWN:
        extra = ["撤回后判断为 UNKNOWN，无法证明命中或不相交。"]
        coverage = scope.coverage_for(family)
        if coverage is None:
            extra.append("家族 {0} 没有库存完整证据。".format(family))
        elif not coverage.complete:
            extra.append("家族 {0} 的库存证据标记为不完整（{1}）；未匹配不能"
                         "推出该族被排除。".format(
                             family, coverage.evidence_ref or "<none>"))
        if not after_asset.manifest_complete:
            extra.append("安装清单未交齐，缺失槽位使 UNKNOWN 无法消除。")
        if replacement is not None:
            extra.extend(replacement.reasons)
        extra.append("既不能确认关闭，也不能确认仍受影响，故记为缺证。")
        return status_result(INSUFFICIENT_EVIDENCE, extra)

    # after_eval.value == NO_MATCH
    if before_eval is not None and before_eval.value == MATCH:
        if replacement is not None and replacement.valid:
            extra = list(replacement.reasons)
            extra.append("撤回前命中、撤回后不相交，且替换凭据与两次快照一致，"
                         "故确已关闭。")
            return status_result(CONFIRMED_CLOSED, extra)
        extra = ["撤回前命中公告、撤回后不相交，但没有已验证的替换凭据解释"
                 "组件变化。"]
        if replacement is not None:
            extra.extend(replacement.reasons)
        extra.append("变化原因不可证明，故记为缺证。")
        return status_result(INSUFFICIENT_EVIDENCE, extra)

    if before_eval is not None and before_eval.value == NO_MATCH:
        coverage = scope.coverage_for(family)
        if (coverage is not None and coverage.complete and
                coverage.covers(advisory.applicability_interval) and
                asset_id in coverage.asset_ids and
                before_asset.manifest_complete and
                after_asset.manifest_complete):
            extra = [
                "撤回前后两次快照均与公告表达式不相交。",
                "家族 {0} 的库存完整证据 {1} 覆盖公告适用区间 {2}。".format(
                    family,
                    coverage.evidence_ref or "<none>",
                    advisory.applicability_interval.label()),
                "两次安装清单均为完整，故未匹配可以作为排除依据，确已关闭。",
            ]
            return status_result(CONFIRMED_CLOSED, extra)

        extra = ["撤回前后两次快照均不相交，但排除该族所需的完整库存证据"
                 "不足。"]
        if coverage is None:
            extra.append("家族 {0} 没有 family_coverage 证据。".format(family))
        elif not coverage.complete:
            extra.append("家族 {0} 的 family_coverage.complete=false（{1}）。".format(
                family, coverage.evidence_ref or "<none>"))
        elif asset_id not in coverage.asset_ids:
            extra.append("家族 {0} 的覆盖证据未列出资产 {1}。".format(
                family, asset_id))
        elif not coverage.covers(advisory.applicability_interval):
            extra.append("家族 {0} 的覆盖区间 {1} 未覆盖公告适用区间 {2}。".format(
                family,
                coverage.coverage_interval.label()
                if coverage.coverage_interval else "<none>",
                advisory.applicability_interval.label()))
        if (before_asset.manifest_complete is False or
                after_asset.manifest_complete is False):
            extra.append("至少一次安装清单不完整，不能从未匹配推出不存在。")
        extra.append("因此不把该资产或该族排除在可证明范围之外，记为缺证。")
        return status_result(INSUFFICIENT_EVIDENCE, extra)

    extra = []
    if before_asset is None:
        extra.append("缺少撤回前快照，无法证明公告适用区间内的暴露状态。")
    elif before_eval is not None:
        extra.append("撤回前判断为 {0}，不能证明未暴露。".format(
            before_eval.value))
    if replacement is not None:
        extra.extend(replacement.reasons)
    extra.append("证据不足以确认关闭或仍受影响，故记为缺证。")
    return status_result(INSUFFICIENT_EVIDENCE, extra)


def _assess_families(advisory, scope, results):
    families = set(scope.family_coverage)
    families.update(result.family for result in results if result.family)
    assessments = []

    for family in sorted(families):
        family_results = [result for result in results
                          if result.family == family]
        asset_ids = sorted(result.asset_id for result in family_results)
        coverage = scope.coverage_for(family)
        evidence_refs = []
        basis = ["家族 {0} 的调用者认可资产：{1}。".format(
            family, ", ".join(asset_ids) if asset_ids else "<none>")]

        if coverage is not None and coverage.evidence_ref:
            evidence_refs.append(coverage.evidence_ref)
        if coverage is not None:
            basis.append("家族库存证据 {0}：complete={1}，覆盖区间={2}。".format(
                coverage.evidence_ref or "<none>",
                coverage.complete,
                coverage.coverage_interval.label()
                if coverage.coverage_interval else "<none>"))

        affected = [result for result in family_results
                    if result.status == STILL_AFFECTED]
        if affected:
            basis.append("该族至少一台资产仍受影响：{0}。".format(
                ", ".join(result.asset_id for result in affected)))
            if coverage is None or not coverage.complete:
                basis.append("该族库存证据不完整，因此不声称整族已排除；"
                             "已命中的资产仍属于可证明影响范围。")
            assessments.append(FamilyAssessment(
                family=family,
                status=FAMILY_RESOLVED,
                basis=basis,
                evidence_refs=evidence_refs,
                asset_ids=asset_ids,
            ))
            continue

        missing = [result for result in family_results
                   if result.status == INSUFFICIENT_EVIDENCE]
        if missing:
            basis.append("该族存在缺证资产：{0}；不能排除该族。".format(
                ", ".join(result.asset_id for result in missing)))
            if coverage is None:
                basis.append("没有该族的库存完整证据；未匹配不能推出排除。")
            elif not coverage.complete:
                basis.append("family_coverage.complete=false；未匹配不能推出排除。")
            elif not coverage.covers(advisory.applicability_interval):
                basis.append("覆盖区间未覆盖公告适用区间；未匹配不能推出排除。")
            assessments.append(FamilyAssessment(
                family=family,
                status=FAMILY_UNRESOLVED,
                basis=basis,
                evidence_refs=evidence_refs,
                asset_ids=asset_ids,
            ))
            continue

        if coverage is None:
            basis.append("没有该族的库存完整证据；未匹配不能推出排除。")
            assessments.append(FamilyAssessment(
                family=family,
                status=FAMILY_UNRESOLVED,
                basis=basis,
                evidence_refs=evidence_refs,
                asset_ids=asset_ids,
            ))
            continue

        if not coverage.complete:
            basis.append("family_coverage.complete=false；未匹配不能推出排除。")
            assessments.append(FamilyAssessment(
                family=family,
                status=FAMILY_UNRESOLVED,
                basis=basis,
                evidence_refs=evidence_refs,
                asset_ids=asset_ids,
            ))
            continue

        if not coverage.covers(advisory.applicability_interval):
            basis.append("覆盖区间未覆盖公告适用区间；未匹配不能推出排除。")
            assessments.append(FamilyAssessment(
                family=family,
                status=FAMILY_UNRESOLVED,
                basis=basis,
                evidence_refs=evidence_refs,
                asset_ids=asset_ids,
            ))
            continue

        if set(coverage.asset_ids) != set(asset_ids):
            basis.append("覆盖证据中的资产列表与调用者范围不一致：{0}。".format(
                ", ".join(sorted(set(coverage.asset_ids) ^ set(asset_ids)))))
            assessments.append(FamilyAssessment(
                family=family,
                status=FAMILY_UNRESOLVED,
                basis=basis,
                evidence_refs=evidence_refs,
                asset_ids=asset_ids,
            ))
            continue

        all_never_matched = all(
            result.before is not None and result.before.value == NO_MATCH and
            result.after is not None and result.after.value == NO_MATCH
            for result in family_results
        ) if family_results else True

        if all_never_matched:
            basis.append("所有资产在撤回前后均不相交，且完整库存证据覆盖公告"
                         "适用区间，故整族排除。")
            assessments.append(FamilyAssessment(
                family=family,
                status=FAMILY_EXCLUDED,
                basis=basis,
                evidence_refs=evidence_refs,
                asset_ids=asset_ids,
            ))
        else:
            basis.append("该族资产均已定性（例如经替换关闭），不声称整族"
                         "从未暴露。")
            assessments.append(FamilyAssessment(
                family=family,
                status=FAMILY_RESOLVED,
                basis=basis,
                evidence_refs=evidence_refs,
                asset_ids=asset_ids,
            ))

    return assessments


def audit_withdrawal(advisory, scope, before_snapshot, after_snapshot,
                     replacements=None):
    """
    Re-audit a withdrawn advisory against two small inventory snapshots.

    :param Advisory advisory: withdrawn advisory and CPE expression.
    :param InventoryScope scope: caller-approved inventory scope.
    :param InventorySnapshot before_snapshot: inventory before withdrawal.
    :param InventorySnapshot after_snapshot: inventory after withdrawal.
    :param list replacements: verified component replacement evidence.
    :returns: audit report with three outcome buckets and per-asset basis.
    :rtype: AuditReport
    """

    if after_snapshot is None:
        raise ValueError("after_snapshot is required")
    replacements = list(replacements or [])

    results = []
    for asset_id in scope.approved_asset_ids:
        before_asset = before_snapshot.get(asset_id) if before_snapshot else None
        after_asset = after_snapshot.get(asset_id)
        results.append(_audit_asset(
            advisory, scope, asset_id, before_asset, after_asset,
            replacements))

    out_of_scope = []
    seen = set()
    for snapshot in (before_snapshot, after_snapshot):
        if snapshot is None:
            continue
        for asset_id, asset in sorted(snapshot.assets.items()):
            if scope.is_approved(asset_id) or asset_id in seen:
                continue
            seen.add(asset_id)
            out_of_scope.append({
                "asset_id": asset_id,
                "family": asset.family,
                "snapshot_id": snapshot.snapshot_id,
                "reason": ("不在调用者认可的库存范围内；未匹配不能作为"
                           "排除该资产或该族的证据。"),
                "evidence_ref": asset.evidence_ref,
            })

    families = _assess_families(advisory, scope, results)

    snapshot_evaluations = {
        "before": _evaluate_snapshot(before_snapshot, advisory),
        "after": _evaluate_snapshot(after_snapshot, advisory),
    }

    return AuditReport(
        advisory=advisory,
        scope=scope,
        before_snapshot=before_snapshot,
        after_snapshot=after_snapshot,
        results=results,
        families=families,
        out_of_scope=out_of_scope,
        snapshot_evaluations=snapshot_evaluations,
    )


__all__ = [
    "CONFIRMED_CLOSED",
    "STILL_AFFECTED",
    "INSUFFICIENT_EVIDENCE",
    "OUT_OF_SCOPE",
    "STATUS_LABELS",
    "FAMILY_EXCLUDED",
    "FAMILY_RESOLVED",
    "FAMILY_UNRESOLVED",
    "ReplacementCheck",
    "AssetAuditResult",
    "FamilyAssessment",
    "AuditReport",
    "audit_withdrawal",
]
