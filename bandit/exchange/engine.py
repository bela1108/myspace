#
# Copyright 2026 PyCQA
#
# SPDX-License-Identifier: Apache-2.0
"""Core engine matching Bandit findings against exception mappings.

The engine is deterministic and side-effect free: given the same scan
report, mapping document and reference time it always produces the same
decisions.  Both the local and exchange views are derived from those
decisions, which is what guarantees that the two views never disagree.
"""
import collections
import copy

from bandit.exchange.errors import MappingValidationError
from bandit.exchange.model import (
    APPROVED,
    CONFLICT,
    EXPIRED,
    MISSING_EVIDENCE,
    NO_MATCH,
    ExceptionMapping,
    Finding,
    utcnow,
)


class TargetDecision:
    """Decision recorded for one external target rule of one mapping."""

    def __init__(
        self,
        mapping,
        target,
        state,
        matched_findings=None,
        conflict_with=None,
        reason="",
    ):
        self.mapping = mapping
        self.target = target
        self.state = state
        self.matched_findings = list(matched_findings or [])
        self.conflict_with = list(conflict_with or [])
        self.reason = reason

    @property
    def mapping_id(self):
        return self.mapping.mapping_id

    @property
    def source_rule(self):
        return self.mapping.source_rule

    @property
    def external_rule(self):
        return self.target.rule_id

    def as_dict(self):
        payload = {
            "mapping_id": self.mapping_id,
            "source_rule": self.source_rule,
            "external_rule": self.external_rule,
            "state": self.state,
            "reason": self.reason,
            "valid_from": _ts(self.mapping.valid_from),
            "valid_until": _ts(self.mapping.valid_until),
            "matched_findings": [
                _finding_ref(finding) for finding in self.matched_findings
            ],
        }
        if self.conflict_with:
            payload["conflict_with"] = list(self.conflict_with)
        return payload


class ExceptionExchange:
    """Evaluate exception mappings against a Bandit scan report.

    :param findings: Bandit findings parsed from a JSON scan report.
    :param mappings: Exception mappings supplied by the caller.
    :param now: Reference time used for validity checks (UTC by default).
    """

    def __init__(self, findings, mappings, now=None):
        self.findings = list(findings)
        self.mappings = list(mappings)
        self.now = now or utcnow()
        self._validate_mapping_ids()
        self.findings_by_rule = collections.defaultdict(list)
        for finding in self.findings:
            self.findings_by_rule[finding.test_id].append(finding)
        self.decisions = []
        self.conflicts = []
        self._run()

    def _validate_mapping_ids(self):
        seen = set()
        for mapping in self.mappings:
            if mapping.mapping_id in seen:
                raise MappingValidationError(
                    f"Duplicate mapping id: {mapping.mapping_id}"
                )
            seen.add(mapping.mapping_id)

    def _run(self):
        self.decisions = []
        for mapping in self.mappings:
            for target in mapping.target_rules:
                self.decisions.append(self._evaluate_target(mapping, target))
        self.conflicts = self._detect_conflicts()

    def _evaluate_target(self, mapping, target):
        if not mapping.is_active(self.now):
            return TargetDecision(
                mapping,
                target,
                EXPIRED,
                reason="mapping is outside its validity period",
            )

        candidate_findings = self.findings_by_rule.get(mapping.source_rule, [])
        if not candidate_findings:
            return TargetDecision(
                mapping,
                target,
                MISSING_EVIDENCE,
                reason=(
                    f"no finding for source rule {mapping.source_rule}; "
                    "the check was not evidenced in this report"
                ),
            )

        matched = [
            finding
            for finding in candidate_findings
            if mapping.shared_matcher.evaluate(finding)
            and target.matcher.evaluate(finding)
        ]
        if not matched:
            return TargetDecision(
                mapping,
                target,
                NO_MATCH,
                reason="no finding satisfied the target context conditions",
            )

        return TargetDecision(
            mapping,
            target,
            APPROVED,
            matched_findings=matched,
            reason="context conditions satisfied within validity period",
        )

    def _detect_conflicts(self):
        """Keep divergent mappings rather than collapsing them.

        A conflict exists when two active mappings that both produce
        approvals address the same external rule through different Bandit
        source rules.  Every conflicting target decision is flagged while
        both opinions remain available in the output.
        """
        conflicts = []
        active = [
            decision
            for decision in self.decisions
            if decision.state == APPROVED
        ]
        grouped = collections.defaultdict(list)
        for decision in active:
            grouped[decision.external_rule].append(decision)

        for external_rule, group in grouped.items():
            source_rules = {decision.source_rule for decision in group}
            if len(source_rules) > 1:
                mapping_ids = sorted(
                    {decision.mapping_id for decision in group}
                )
                conflicts.append(
                    {
                        "external_rule": external_rule,
                        "source_rules": sorted(source_rules),
                        "mapping_ids": mapping_ids,
                        "reason": (
                            "external rule is claimed by mappings with "
                            "different Bandit source rules; disagreement "
                            "retained for human review"
                        ),
                    }
                )
                for decision in group:
                    decision.state = CONFLICT
                    decision.conflict_with = [
                        other.mapping_id
                        for other in group
                        if other.mapping_id != decision.mapping_id
                    ]
                    decision.reason = (
                        "approved but conflicts with another mapping for "
                        f"external rule {external_rule}"
                    )
        return conflicts

    def approved_findings(self):
        """Return the set of findings currently covered by an approval."""
        approved = set()
        for decision in self.decisions:
            if decision.state == APPROVED:
                approved.update(decision.matched_findings)
        return approved

    def decisions_for_mapping(self, mapping_id):
        return [
            decision
            for decision in self.decisions
            if decision.mapping_id == mapping_id
        ]

    def without_mappings(self, mapping_ids):
        """Re-run the exchange after deleting one or more mappings.

        Only approvals produced by the removed mappings disappear; every
        other decision is recomputed from the same scan report, so an
        auditor deleting a single mapping loses exactly that mapping's
        approvals.
        """
        removed = set(mapping_ids)
        remaining = [
            mapping
            for mapping in self.mappings
            if mapping.mapping_id not in removed
        ]
        return ExceptionExchange(self.findings, remaining, now=self.now)

    def local_view(self):
        """Build the Bandit-centric view of the same findings."""
        approved = self.approved_findings()
        grouped = collections.OrderedDict()
        for finding in sorted(
            self.findings,
            key=lambda item: (
                item.test_id, item.filename,
                item.line_number or 0,
            ),
        ):
            bucket = grouped.setdefault(
                finding.test_id,
                {
                    "source_rule": finding.test_id,
                    "test_name": finding.test_name,
                    "findings": [],
                    "approved": False,
                },
            )
            entry = _finding_ref(finding)
            entry["approved"] = finding in approved
            approving = {
                decision.mapping_id
                for decision in self.decisions
                if decision.state == APPROVED
                and finding in decision.matched_findings
            }
            entry["approved_by"] = sorted(approving)
            bucket["findings"].append(entry)
            if approving:
                bucket["approved"] = True
        return {
            "view": "local",
            "generated_at": _ts(self.now),
            "rules": list(grouped.values()),
        }

    def exchange_view(self):
        """Build the external-scanner-centric view."""
        grouped = collections.OrderedDict()
        for decision in self.decisions:
            bucket = grouped.setdefault(
                decision.external_rule,
                {
                    "external_rule": decision.external_rule,
                    "decisions": [],
                    "states": set(),
                },
            )
            bucket["decisions"].append(decision.as_dict())
            bucket["states"].add(decision.state)

        rules = []
        for external_rule, bucket in sorted(grouped.items()):
            rules.append(
                {
                    "external_rule": external_rule,
                    "has_approval": APPROVED in bucket["states"],
                    "decisions": bucket["decisions"],
                }
            )
        return {
            "view": "exchange",
            "generated_at": _ts(self.now),
            "conflicts": copy.deepcopy(self.conflicts),
            "rules": rules,
        }

    def build_views(self):
        """Return both views, computed from one evaluation pass."""
        return {
            "local": self.local_view(),
            "exchange": self.exchange_view(),
        }


def _finding_ref(finding):
    return {
        "filename": finding.filename,
        "test_id": finding.test_id,
        "test_name": finding.test_name,
        "line_number": finding.line_number,
        "line_range": list(finding.line_range),
        "issue_severity": finding.severity,
        "issue_confidence": finding.confidence,
        "issue_text": finding.issue_text,
        "code": finding.code,
    }


def _ts(value):
    if value is None:
        return None
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")
