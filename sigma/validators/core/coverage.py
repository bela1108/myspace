from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from typing import ClassVar, Iterable, Mapping, Self

from sigma.conditions import (
    ConditionAND,
    ConditionIdentifier,
    ConditionItem,
    ConditionNOT,
    ConditionOR,
    ConditionSelector,
)
from sigma.correlations import SigmaCorrelationRule
from sigma.processing.pipeline import ProcessingPipeline
from sigma.rule import SigmaDetection, SigmaDetectionItem, SigmaRule
from sigma.rule.detection import SigmaDetections
from sigma.types import (
    SigmaBool,
    SigmaCIDRExpression,
    SigmaCompareExpression,
    SigmaExists,
    SigmaExpansion,
    SigmaFieldReference,
    SigmaNull,
    SigmaNumber,
    SigmaQueryExpression,
    SigmaRegularExpression,
    SigmaString,
    SigmaType,
)
from sigma.validators.base import (
    SigmaRuleValidator,
    SigmaValidationIssue,
    SigmaValidationIssueSeverity,
)

field_type_compatibility: dict[str, tuple[type[SigmaType], ...]] = {
    "string": (SigmaString, SigmaRegularExpression, SigmaQueryExpression, SigmaExpansion),
    "number": (SigmaNumber, SigmaCompareExpression),
    "boolean": (SigmaBool,),
    "ip": (SigmaString, SigmaCIDRExpression),
}
"""Mapping of caller-declared log source field types to compatible Sigma value types."""

logsource_scope_dimensions: tuple[str, ...] = ("category", "product", "service")
"""Log source dimensions that are compared against the caller-provided collection scope."""


@dataclass
class LogsourceScopeMismatchIssue(SigmaValidationIssue):
    description: ClassVar[str] = (
        "Rule log source is outside the collection scope of the target log source"
    )
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.HIGH
    logsource_name: str
    dimension: str
    required: str
    collected: list[str]
    remediation: str


@dataclass
class LogsourceFieldCoverageIssue(SigmaValidationIssue):
    """Base class for issues about fields a target log source doesn't provide as required."""

    logsource_name: str
    detection: str | None
    field: str
    detection_item: SigmaDetectionItem | None
    reason: str
    remediation: str


@dataclass
class LogsourcePartialCoverageIssue(LogsourceFieldCoverageIssue):
    description: ClassVar[str] = (
        "Log source misses a field required by an optional part of the detection; "
        "rule coverage is reduced but the rule can still match"
    )
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.MEDIUM


@dataclass
class LogsourceNoCoverageIssue(LogsourceFieldCoverageIssue):
    description: ClassVar[str] = (
        "Log source misses a field required by all detection alternatives; "
        "the rule can never match"
    )
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.HIGH


@dataclass
class _FieldRequirement:
    """A field required by a detection, pointing back to the source detection item."""

    field: str
    detection: str | None
    detection_item: SigmaDetectionItem | None


class LogsourceCoverageValidator(SigmaRuleValidator):
    """
    Validates that a target log source described by the caller supports a Sigma rule before it is
    deployed. The caller provides a description of the log source:

    * fields: mapping of collected field names to their types (e.g. "string", "number", "boolean")
      or a plain list of collected field names if types are unknown.
    * scope: mapping of the log source dimensions category, product and service to the values that
      are actually collected, describing the collection scope of the log source.
    * pipeline: an optional processing pipeline that is applied to a copy of the rule before the
      analysis, so that fields required by the pipeline (renamed fields, injected detection items)
      are checked against the log source together with the fields required by the conditions.

    Two blocking levels are reported:

    * LogsourcePartialCoverageIssue (medium): an optional condition alternative can't be evaluated
      because a field is missing, reducing the coverage of the rule.
    * LogsourceNoCoverageIssue and LogsourceScopeMismatchIssue (high): the rule can never match
      against the log source.

    All issues point back to the source detection item and contain a remediation hint naming the
    field that has to be added to restore partial or full coverage.
    """

    def __init__(
        self: Self,
        fields: Mapping[str, str] | Iterable[str] | None = None,
        scope: Mapping[str, str | Iterable[str]] | None = None,
        pipeline: ProcessingPipeline | None = None,
        logsource_name: str = "target log source",
    ) -> None:
        self.fields = self._normalize_fields(fields)
        self.scope = self._normalize_scope(scope)
        self.pipeline = pipeline
        self.logsource_name = logsource_name

    @staticmethod
    def _normalize_fields(
        fields: Mapping[str, str] | Iterable[str] | None,
    ) -> dict[str, str | None] | None:
        if fields is None:
            return None
        if isinstance(fields, Mapping):
            return {
                str(name): (str(field_type) if field_type is not None else None)
                for name, field_type in fields.items()
            }
        return {str(name): None for name in fields}

    @staticmethod
    def _normalize_scope(
        scope: Mapping[str, str | Iterable[str]] | None,
    ) -> dict[str, frozenset[str]]:
        if scope is None:
            return dict()
        return {
            str(dimension): frozenset([values] if isinstance(values, str) else values)
            for dimension, values in scope.items()
        }

    def validate(self: Self, rule: SigmaRule | SigmaCorrelationRule) -> list[SigmaValidationIssue]:
        super().validate(rule)
        if isinstance(rule, SigmaCorrelationRule):
            return []  # Correlation rules do not have detections
        if self.fields is None and not self.scope:
            return []  # no log source description was provided, nothing to check against
        analysis_rule = rule
        if self.pipeline is not None:
            analysis_rule = deepcopy(rule)
            self.pipeline.apply(analysis_rule)
        issues = self._validate_scope(analysis_rule)
        issues.extend(self._validate_fields(analysis_rule))
        return issues

    def _validate_scope(self: Self, rule: SigmaRule) -> list[SigmaValidationIssue]:
        issues = []
        for dimension in logsource_scope_dimensions:
            collected = self.scope.get(dimension)
            if not collected:
                continue
            required = getattr(rule.logsource, dimension)
            if required is not None and required not in collected:
                issues.append(
                    LogsourceScopeMismatchIssue(
                        rules=[self.rule],
                        logsource_name=self.logsource_name,
                        dimension=dimension,
                        required=required,
                        collected=sorted(collected),
                        remediation=(
                            f"Extend the collection scope of {self.logsource_name} with "
                            f"{dimension} '{required}' or the rule can never match"
                        ),
                    )
                )
        return issues

    def _validate_fields(self: Self, rule: SigmaRule) -> list[SigmaValidationIssue]:
        if self.fields is None:
            return []
        branches = self._requirement_branches(rule)
        if not branches:
            return []

        # Collect the problems of each requirement branch. A branch is unreachable as soon as one
        # of its requirements can't be fulfilled by the log source.
        problems: dict[tuple[str, str, str | None, int], list[int]] = dict()
        problem_items: dict[tuple[str, str, str | None, int], SigmaDetectionItem | None] = dict()
        branch_problem_keys: list[list[tuple[str, str, str | None, int]]] = []
        for branch_index, branch in enumerate(branches):
            branch_keys: list[tuple[str, str, str | None, int]] = []
            for requirement in branch:
                reason = self._check_requirement(requirement)
                if reason is None:
                    continue
                key = (
                    requirement.field,
                    reason,
                    requirement.detection,
                    id(requirement.detection_item),
                )
                if key in branch_keys:
                    continue
                branch_keys.append(key)
                problems.setdefault(key, []).append(branch_index)
                problem_items[key] = requirement.detection_item
            branch_problem_keys.append(branch_keys)

        issues = []
        for key, affected_branches in problems.items():
            field_name, reason, detection, _ = key
            detection_item = problem_items[key]
            blocks_all = len(affected_branches) == len(branches)
            sole_blocker = any(
                branch_keys == [(field_name, reason, detection, id(detection_item))]
                for branch_keys in branch_problem_keys
            )
            issues.append(
                self._build_issue(
                    blocks_all, sole_blocker, field_name, reason, detection, detection_item
                )
            )
        return issues

    def _build_issue(
        self: Self,
        blocks_all: bool,
        sole_blocker: bool,
        field_name: str,
        reason: str,
        detection: str | None,
        detection_item: SigmaDetectionItem | None,
    ) -> LogsourceFieldCoverageIssue:
        if reason == "missing_field":
            if blocks_all:
                remediation = (
                    f"Add field '{field_name}' to {self.logsource_name} to restore rule coverage"
                    if sole_blocker
                    else f"Add field '{field_name}' together with the other missing fields to "
                    f"{self.logsource_name} to restore rule coverage"
                )
            else:
                remediation = (
                    f"Add field '{field_name}' to {self.logsource_name} "
                    f"to restore partial rule coverage"
                )
        else:  # type_mismatch
            declared = self.fields.get(field_name) if self.fields is not None else None
            remediation = (
                f"Collect field '{field_name}' on {self.logsource_name} with a type compatible "
                f"with the detection instead of '{declared}'"
            )
        issue_class = LogsourceNoCoverageIssue if blocks_all else LogsourcePartialCoverageIssue
        return issue_class(
            rules=[self.rule],
            logsource_name=self.logsource_name,
            detection=detection,
            field=field_name,
            detection_item=detection_item,
            reason=reason,
            remediation=remediation,
        )

    def _check_requirement(self: Self, requirement: _FieldRequirement) -> str | None:
        """Check a single field requirement against the log source description."""
        assert self.fields is not None
        declared = self.fields.get(requirement.field)
        if declared is None:
            return "missing_field"
        if requirement.detection_item is not None:
            compatible = field_type_compatibility.get(declared.lower())
            if compatible is not None:
                for value in requirement.detection_item.value:
                    if isinstance(value, (SigmaNull, SigmaExists, SigmaFieldReference)):
                        continue  # presence and field reference checks work on any field type
                    if not isinstance(value, compatible):
                        return "type_mismatch"
        return None

    def _requirement_branches(self: Self, rule: SigmaRule) -> list[list[_FieldRequirement]]:
        """
        Compute the requirement branches of a rule. Each branch is a list of field requirements
        that must all be fulfilled for one alternative of the condition to match. The rule matches
        if at least one branch is fully covered by the log source.
        """
        detections = rule.detection
        branches = []
        for condition in detections.parsed_condition:
            tree = condition.parse(postprocess=False)
            if tree is not None:
                branches.extend(self._condition_branches(tree, detections))
        return branches

    def _condition_branches(
        self: Self, node: ConditionItem, detections: SigmaDetections
    ) -> list[list[_FieldRequirement]]:
        if isinstance(node, ConditionOR):
            return [
                branch
                for arg in node.args
                if arg is not None
                for branch in self._condition_branches(arg, detections)
            ]
        if isinstance(node, ConditionAND):
            branches: list[list[_FieldRequirement]] = [[]]
            for arg in node.args:
                if arg is None:
                    continue
                branches = [
                    left + right
                    for left in branches
                    for right in self._condition_branches(arg, detections)
                ]
            return branches
        if isinstance(node, ConditionNOT):
            # A negated condition part that can't be evaluated doesn't block matching.
            return [[]]
        if isinstance(node, ConditionSelector):
            identifiers = node.resolve_referenced_detections(detections)
            if node.cond_class is ConditionOR:
                return [
                    branch
                    for identifier in identifiers
                    for branch in self._condition_branches(identifier, detections)
                ]
            branches = [[]]
            for identifier in identifiers:
                branches = [
                    left + right
                    for left in branches
                    for right in self._condition_branches(identifier, detections)
                ]
            return branches
        if isinstance(node, ConditionIdentifier):
            detection = detections.detections.get(node.identifier)
            if detection is None:
                return [[]]
            return self._detection_branches(detection, node.identifier)
        return [[]]

    def _detection_branches(
        self: Self, detection: SigmaDetection, name: str | None
    ) -> list[list[_FieldRequirement]]:
        if detection.item_linking is ConditionOR:
            return [
                branch
                for item in detection.detection_items
                for branch in self._item_branches(item, name)
            ]
        branches: list[list[_FieldRequirement]] = [[]]
        for item in detection.detection_items:
            branches = [
                left + right for left in branches for right in self._item_branches(item, name)
            ]
        return branches

    def _item_branches(
        self: Self, item: SigmaDetection | SigmaDetectionItem, name: str | None
    ) -> list[list[_FieldRequirement]]:
        if isinstance(item, SigmaDetection):
            return self._detection_branches(item, name)
        if item.field is None or item.negated:
            # Keyword searches and negated items can't be checked against a field inventory.
            return [[]]
        requirements = [
            _FieldRequirement(field=item.field, detection=name, detection_item=item)
        ]
        for value in item.value:
            if isinstance(value, SigmaFieldReference):
                requirements.append(
                    _FieldRequirement(field=value.field, detection=name, detection_item=item)
                )
        return [requirements]
