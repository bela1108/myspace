"""Offline approval reconciliation for Plyara-parsed YARA rules."""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import Any, Mapping, Sequence

from plyara import Plyara

ROUTINE_ARCHIVE_SEARCH = "routine_archive_search"
OUTBOUND_REPORT_ATTACHMENT = "outbound_report_attachment"

USE_LABELS = {
    ROUTINE_ARCHIVE_SEARCH: "例行档案搜索",
    OUTBOUND_REPORT_ATTACHMENT: "外发报告附件",
}

ACTIVE = "active"
WITHDRAWN = "withdrawn"

APPROVED = "approved"
RECHECK_REQUIRED = "recheck_required"
APPROVAL_WITHDRAWN = "approval_withdrawn"
UNAPPROVED = "unapproved"

RULE_REORDERED = "rule_reordered"
SAME_NAME_REPLACEMENT = "same_name_replacement"
MISSING_APPROVAL = "missing_approval_for_use"
APPROVED_RULE_MISSING = "approved_rule_missing"


def _use_label(use: str) -> str:
    return USE_LABELS.get(use, use)


def condition_profile(parsed_rule: Mapping[str, Any]) -> dict[str, Any]:
    """Return the stable syntax facts used by the condition fingerprint."""
    strings = []
    for entry in parsed_rule.get("strings") or []:
        modifiers = sorted(entry.get("modifiers") or [])
        strings.append(
            {
                "name": entry.get("name", ""),
                "type": entry.get("type", ""),
                "value": entry.get("value", ""),
                "modifiers": modifiers,
            }
        )

    strings.sort(
        key=lambda item: json.dumps(item, ensure_ascii=False, sort_keys=True)
    )

    return {
        "condition_terms": list(parsed_rule.get("condition_terms") or []),
        "strings": strings,
    }


def condition_fingerprint(parsed_rule: Mapping[str, Any]) -> str:
    """Hash condition terms and match strings without executing YARA."""
    canonical = json.dumps(
        condition_profile(parsed_rule),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def plain_condition(parsed_rule: Mapping[str, Any]) -> str:
    """Render a readable plain-text view of ordinary text matches and logic."""
    terms = " ".join(parsed_rule.get("condition_terms") or [])
    lines = [f"condition: {terms}"]

    for entry in parsed_rule.get("strings") or []:
        if entry.get("type") != "text":
            continue

        value = json.dumps(entry.get("value", ""), ensure_ascii=False)
        line = f"{entry.get('name', '$')} = {value}"
        modifiers = entry.get("modifiers") or []
        if modifiers:
            line += f" modifiers={','.join(modifiers)}"
        lines.append(line)

    return "\n".join(lines)


@dataclass(frozen=True)
class RuleApproval:
    """A rule/condition binding recorded on a review form."""

    approval_id: str
    rule_name: str
    condition_fingerprint: str
    plain_condition: str
    approved_position: int | None = None
    approved_start_line: int | None = None
    status: str = ACTIVE
    note: str | None = None


def bind_parsed_rule(
    parsed_rule: Mapping[str, Any],
    *,
    approval_id: str,
    approved_position: int | None = None,
    status: str = ACTIVE,
    note: str | None = None,
) -> RuleApproval:
    """Bind one Plyara rule result to an approval identifier."""
    if status not in (ACTIVE, WITHDRAWN):
        raise ValueError(f"unsupported approval status: {status}")

    return RuleApproval(
        approval_id=approval_id,
        rule_name=parsed_rule["rule_name"],
        condition_fingerprint=condition_fingerprint(parsed_rule),
        plain_condition=plain_condition(parsed_rule),
        approved_position=approved_position,
        approved_start_line=parsed_rule.get("start_line"),
        status=status,
        note=note,
    )


@dataclass(frozen=True)
class ReviewForm:
    """A review form that grants one use to its rule bindings."""

    form_id: str
    use: str
    rules: Sequence[RuleApproval]


def form_from_parsed_rules(
    form_id: str,
    use: str,
    parsed_rules: Sequence[Mapping[str, Any]],
    *,
    approval_id_prefix: str,
) -> ReviewForm:
    """Create a review form from rules parsed at approval time."""
    approvals = tuple(
        bind_parsed_rule(
            rule,
            approval_id=f"{approval_id_prefix}-{position + 1}",
            approved_position=position,
        )
        for position, rule in enumerate(parsed_rules)
    )
    return ReviewForm(form_id=form_id, use=use, rules=approvals)


@dataclass(frozen=True)
class Finding:
    """A reconciliation signal."""

    code: str
    severity: str
    message: str
    rule_name: str | None = None
    use: str | None = None
    approval_id: str | None = None
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class UseDecision:
    """Authorization decision for one rule/use pair."""

    rule_name: str
    use: str
    allowed: bool
    status: str
    current_position: int
    condition_fingerprint: str
    plain_condition: str
    current_start_line: int | None = None
    reordered: bool = False
    approval_ids: list[str] = field(default_factory=list)
    prior_approval_ids: list[str] = field(default_factory=list)
    evidence: list[dict[str, Any]] = field(default_factory=list)
    messages: list[str] = field(default_factory=list)

    @property
    def needs_recheck(self) -> bool:
        return self.status == RECHECK_REQUIRED


@dataclass
class AuditReport:
    """Decisions and findings from an offline reconciliation."""

    decisions: list[UseDecision]
    findings: list[Finding]
    rule_count: int

    def decision(self, rule_name: str, use: str) -> UseDecision:
        for item in self.decisions:
            if item.rule_name == rule_name and item.use == use:
                return item
        raise KeyError(f"no decision for {rule_name!r}/{use!r}")

    def allowed(self, rule_name: str, use: str) -> bool:
        return self.decision(rule_name, use).allowed

    def evidence_for(self, rule_name: str, use: str) -> list[dict[str, Any]]:
        return self.decision(rule_name, use).evidence

    def findings_for(
        self, code: str | None = None, rule_name: str | None = None, use: str | None = None
    ) -> list[Finding]:
        return [
            item
            for item in self.findings
            if (code is None or item.code == code)
            and (rule_name is None or item.rule_name == rule_name)
            and (use is None or item.use == use)
        ]

    @property
    def blockers(self) -> list[Finding]:
        return [item for item in self.findings if item.severity == "blocker"]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class _BoundApproval:
    approval: RuleApproval
    form_id: str
    use: str

    @property
    def rule_name(self) -> str:
        return self.approval.rule_name

    @property
    def fingerprint(self) -> str:
        return self.approval.condition_fingerprint


def _parse_current_rules(current_rules: str | Sequence[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    if isinstance(current_rules, str):
        return Plyara().parse_string(current_rules)
    return list(current_rules)


def _evidence(bound: _BoundApproval) -> dict[str, Any]:
    approval = bound.approval
    return {
        "approval_id": approval.approval_id,
        "form_id": bound.form_id,
        "use": bound.use,
        "basis": f"{bound.form_id}/{approval.approval_id}",
        "approved_position": approval.approved_position,
        "approved_start_line": approval.approved_start_line,
        "condition_fingerprint": approval.condition_fingerprint,
        "plain_condition": approval.plain_condition,
        "status": approval.status,
    }


def audit_rules(
    current_rules: str | Sequence[Mapping[str, Any]],
    review_forms: Sequence[ReviewForm] | ReviewForm,
    *,
    uses: Sequence[str] | None = None,
) -> AuditReport:
    """Reconcile current Plyara rules against use-specific review forms."""
    parsed_rules = _parse_current_rules(current_rules)
    forms = [review_forms] if isinstance(review_forms, ReviewForm) else list(review_forms)

    bound_approvals: list[_BoundApproval] = []
    form_uses: list[str] = []
    for form in forms:
        form_uses.append(form.use)
        for approval in form.rules:
            if approval.status not in (ACTIVE, WITHDRAWN):
                raise ValueError(f"unsupported approval status: {approval.status}")
            bound_approvals.append(
                _BoundApproval(approval=approval, form_id=form.form_id, use=form.use)
            )

    requested_uses = list(uses) if uses is not None else list(dict.fromkeys(form_uses))

    current_by_name: dict[str, list[tuple[int, Mapping[str, Any], str, str]]] = {}
    for position, parsed_rule in enumerate(parsed_rules):
        name = parsed_rule["rule_name"]
        current_by_name.setdefault(name, []).append(
            (
                position,
                parsed_rule,
                condition_fingerprint(parsed_rule),
                plain_condition(parsed_rule),
            )
        )

    decisions: list[UseDecision] = []
    findings: list[Finding] = []

    for name, occurrences in current_by_name.items():
        for position, parsed_rule, fingerprint, plain in occurrences:
            current_start_line = parsed_rule.get("start_line")

            for use in requested_uses:
                same_use = [
                    bound
                    for bound in bound_approvals
                    if bound.rule_name == name and bound.use == use
                ]
                active = [bound for bound in same_use if bound.approval.status == ACTIVE]
                withdrawn = [
                    bound for bound in same_use if bound.approval.status == WITHDRAWN
                ]
                exact_active = [bound for bound in active if bound.fingerprint == fingerprint]
                exact_withdrawn = [
                    bound for bound in withdrawn if bound.fingerprint == fingerprint
                ]
                stale_active = [bound for bound in active if bound.fingerprint != fingerprint]
                stale_any = [bound for bound in same_use if bound.fingerprint != fingerprint]

                decision = UseDecision(
                    rule_name=name,
                    use=use,
                    allowed=bool(exact_active),
                    status=APPROVED if exact_active else UNAPPROVED,
                    current_position=position,
                    condition_fingerprint=fingerprint,
                    plain_condition=plain,
                    current_start_line=current_start_line,
                )

                if exact_active:
                    decision.approval_ids = [
                        bound.approval.approval_id for bound in exact_active
                    ]
                    decision.evidence = [_evidence(bound) for bound in exact_active]

                    for bound in exact_active:
                        approved_position = bound.approval.approved_position
                        if approved_position is not None and approved_position != position:
                            decision.reordered = True
                            message = (
                                f"规则 {name} 在用途“{_use_label(use)}”中发生重排："
                                f"审批位置为第 {approved_position + 1} 条，"
                                f"当前为第 {position + 1} 条；名称与普通文本条件未变，审批依据仍有效。"
                            )
                            decision.messages.append(message)
                            findings.append(
                                Finding(
                                    code=RULE_REORDERED,
                                    severity="notice",
                                    message=message,
                                    rule_name=name,
                                    use=use,
                                    approval_id=bound.approval.approval_id,
                                    details={
                                        "form_id": bound.form_id,
                                        "approved_position": approved_position,
                                        "current_position": position,
                                        "basis": f"{bound.form_id}/{bound.approval.approval_id}",
                                    },
                                )
                            )

                elif stale_any:
                    decision.status = RECHECK_REQUIRED
                    decision.prior_approval_ids = [
                        bound.approval.approval_id for bound in stale_any
                    ]
                    if use == OUTBOUND_REPORT_ATTACHMENT:
                        external_notice = "；外发许可必须明确重新核对"
                    else:
                        external_notice = "；使用许可必须重新核对"
                    message = (
                        f"同名规则 {name} 的普通文本条件已变化，用途“{_use_label(use)}”不能沿用旧审批"
                        f"{external_notice}。"
                    )
                    decision.messages.append(message)

                    for bound in stale_active:
                        findings.append(
                            Finding(
                                code=SAME_NAME_REPLACEMENT,
                                severity="blocker",
                                message=message,
                                rule_name=name,
                                use=use,
                                approval_id=bound.approval.approval_id,
                                details={
                                    "form_id": bound.form_id,
                                    "approved_fingerprint": bound.fingerprint,
                                    "current_fingerprint": fingerprint,
                                    "approved_plain_condition": bound.approval.plain_condition,
                                    "current_plain_condition": plain,
                                },
                            )
                        )

                elif exact_withdrawn:
                    decision.status = APPROVAL_WITHDRAWN
                    decision.prior_approval_ids = [
                        bound.approval.approval_id for bound in exact_withdrawn
                    ]
                    message = (
                        f"规则 {name} 在用途“{_use_label(use)}”下没有有效审批；"
                        f"对应旧审批已撤回，不得继续使用。"
                    )
                    decision.messages.append(message)

                elif not same_use:
                    message = f"规则 {name} 未获得用途“{_use_label(use)}”的审批。"
                    decision.messages.append(message)
                    findings.append(
                        Finding(
                            code=MISSING_APPROVAL,
                            severity="blocker",
                            message=message,
                            rule_name=name,
                            use=use,
                        )
                    )

                decisions.append(decision)

    emitted_withdrawals: set[tuple[str, str]] = set()
    for bound in bound_approvals:
        if bound.approval.status != WITHDRAWN:
            continue

        key = (bound.form_id, bound.approval.approval_id)
        if key in emitted_withdrawals:
            continue
        emitted_withdrawals.add(key)

        occurrences = current_by_name.get(bound.rule_name, [])
        active_decision = next(
            (
                item
                for item in decisions
                if item.rule_name == bound.rule_name and item.use == bound.use and item.allowed
            ),
            None,
        )
        current_basis = [item["basis"] for item in active_decision.evidence] if active_decision else []

        if current_basis and occurrences:
            new_basis = ", ".join(current_basis)
            message = (
                f"旧审批 {bound.form_id}/{bound.approval.approval_id} 已撤回；"
                f"规则 {bound.rule_name} 的当前名称与条件已有新的有效绑定，用途“{_use_label(bound.use)}”"
                f"可依据新审批 {new_basis} 继续。"
            )
            severity = "warning"
        elif occurrences and bound.fingerprint != occurrences[0][2]:
            message = (
                f"旧审批 {bound.form_id}/{bound.approval.approval_id} 已撤回，"
                f"且同名规则 {bound.rule_name} 的条件已变化；用途“{_use_label(bound.use)}”需重新核对。"
            )
            severity = "blocker"
        elif occurrences:
            message = (
                f"旧审批 {bound.form_id}/{bound.approval.approval_id} 已撤回；"
                f"规则 {bound.rule_name} 的用途“{_use_label(bound.use)}”不得沿用该审批。"
            )
            severity = "blocker"
        else:
            message = (
                f"旧审批 {bound.form_id}/{bound.approval.approval_id} 已撤回，"
                f"当前规则集中也不存在规则 {bound.rule_name}。"
            )
            severity = "warning"

        findings.append(
            Finding(
                code=APPROVAL_WITHDRAWN,
                severity=severity,
                message=message,
                rule_name=bound.rule_name,
                use=bound.use,
                approval_id=bound.approval.approval_id,
                details={
                    "form_id": bound.form_id,
                    "basis": f"{bound.form_id}/{bound.approval.approval_id}",
                    "superseded_by": current_basis,
                },
            )
        )

    current_names = set(current_by_name)
    for bound in bound_approvals:
        if bound.approval.status == ACTIVE and bound.rule_name not in current_names:
            findings.append(
                Finding(
                    code=APPROVED_RULE_MISSING,
                    severity="warning",
                    message=f"已审批规则 {bound.rule_name} 不在当前 Plyara 解析结果中。",
                    rule_name=bound.rule_name,
                    use=bound.use,
                    approval_id=bound.approval.approval_id,
                    details={"form_id": bound.form_id},
                )
            )

    return AuditReport(
        decisions=decisions,
        findings=findings,
        rule_count=len(parsed_rules),
    )
