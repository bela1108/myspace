#
# SPDX-License-Identifier: Apache-2.0
"""Static review of label combinations exposed by export APIs.

The analyzer is deliberately conservative.  It only reports a combination as
``co_executable`` when it can identify the exported labels and a common
recipient.  Exports under opposite branches are ``mutually_exclusive``.  Any
dynamic value or unsupported control-flow relationship is retained as an
``unprovable`` result together with the reason.
"""
from __future__ import annotations

import ast
import itertools
import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Iterable, Sequence

__all__ = [
    "CombinationStatus",
    "ExportCombinationAnalyzer",
    "ExportCombinationConfig",
    "ExportCombinationFinding",
    "ExportCombinationReport",
    "ExportPoint",
    "Guard",
    "StaticValue",
    "analyze_export_combinations",
    "analyze_exports",
    "analyze_file",
    "analyze_source",
    "find_export_combinations",
    "normalize_protected_combinations",
    "scan_export_combinations",
]


DEFAULT_EXPORT_FUNCTIONS = frozenset(
    {
        "export",
        "export_data",
        "export_record",
        "export_records",
        "export_report",
        "emit_export",
        "publish_report",
        "send_export",
        "send_report",
        "submit_export",
        "submit_report",
    }
)

DEFAULT_RECIPIENT_ARGUMENTS = frozenset(
    {
        "audience",
        "consumer",
        "customer",
        "destination",
        "partner",
        "recipient",
        "recipients",
        "receiver",
        "target",
        "to",
    }
)

DEFAULT_FIELD_ARGUMENTS = frozenset(
    {
        "attributes",
        "columns",
        "data",
        "fields",
        "items",
        "labels",
        "payload",
        "records",
        "tags",
        "values",
    }
)


class CombinationStatus(str, Enum):
    """Outcome of checking one caller-supplied label combination."""

    CO_EXECUTABLE = "co_executable"
    MUTUALLY_EXCLUSIVE = "mutually_exclusive"
    UNPROVABLE = "unprovable"
    INDEPENDENT_RECIPIENTS = "independent_recipients"


@dataclass(frozen=True)
class StaticValue:
    """A small, deliberately finite static representation of an expression."""

    kind: str
    scalar: object = None
    items: tuple["StaticValue", ...] = ()
    mapping: tuple[tuple["StaticValue", "StaticValue"], ...] = ()
    alternatives: tuple["StaticValue", ...] = ()
    reason: str = ""

    @classmethod
    def unknown(cls, reason: str) -> "StaticValue":
        return cls("unknown", reason=reason)

    @classmethod
    def sequence(cls, items: Iterable["StaticValue"]) -> "StaticValue":
        return cls("sequence", items=tuple(items))

    @classmethod
    def mapping_value(
        cls, pairs: Iterable[tuple["StaticValue", "StaticValue"]]
    ) -> "StaticValue":
        return cls("mapping", mapping=tuple(pairs))

    @classmethod
    def choices(cls, values: Iterable["StaticValue"]) -> "StaticValue":
        flattened = []
        for value in values:
            if value.kind == "alternatives":
                flattened.extend(value.alternatives)
            else:
                flattened.append(value)
        if not flattened:
            return cls.unknown("no static value was available")
        if len(flattened) == 1:
            return flattened[0]
        return cls("alternatives", alternatives=tuple(flattened))

    def labels(self) -> frozenset[str]:
        """Return every statically visible string in this value."""
        if self.kind == "scalar":
            if isinstance(self.scalar, str):
                return frozenset({self.scalar})
            return frozenset()
        if self.kind == "sequence":
            result = set()
            for item in self.items:
                result.update(item.labels())
            return frozenset(result)
        if self.kind == "mapping":
            result = set()
            for key, _ in self.mapping:
                result.update(key.labels())
            return frozenset(result)
        if self.kind == "alternatives":
            result = set()
            for alternative in self.alternatives:
                result.update(alternative.labels())
            return frozenset(result)
        return frozenset()

    def may_have_unknown_labels(self) -> bool:
        if self.kind == "unknown":
            return True
        if self.kind == "sequence":
            return any(item.may_have_unknown_labels() for item in self.items)
        if self.kind == "mapping":
            return any(
                key.may_have_unknown_labels() for key, _ in self.mapping
            )
        if self.kind == "alternatives":
            return any(
                alternative.may_have_unknown_labels()
                for alternative in self.alternatives
            )
        return False

    def unknown_reasons(self) -> tuple[str, ...]:
        reasons = []
        if self.kind == "unknown" and self.reason:
            reasons.append(self.reason)
        elif self.kind == "sequence":
            for item in self.items:
                reasons.extend(item.unknown_reasons())
        elif self.kind == "mapping":
            for key, _ in self.mapping:
                reasons.extend(key.unknown_reasons())
        elif self.kind == "alternatives":
            for alternative in self.alternatives:
                reasons.extend(alternative.unknown_reasons())
        return tuple(dict.fromkeys(reasons))

    def recipient_values(self) -> tuple[frozenset[str] | None, str]:
        if self.kind == "scalar":
            if isinstance(self.scalar, str):
                return frozenset({self.scalar}), ""
            return None, "recipient is not a string literal"
        if self.kind == "sequence":
            recipients = set()
            for item in self.items:
                values, reason = item.recipient_values()
                if values is None:
                    return None, reason
                recipients.update(values)
            return frozenset(recipients), ""
        if self.kind == "alternatives":
            recipients = set()
            for alternative in self.alternatives:
                values, reason = alternative.recipient_values()
                if values is None:
                    return None, reason
                recipients.update(values)
            return frozenset(recipients), ""
        if self.kind == "mapping":
            return None, "recipient is a mapping, not a static string"
        return None, self.reason or "recipient value cannot be resolved"

    def sequence_variants(self) -> tuple[tuple["StaticValue", ...], ...]:
        if self.kind == "sequence":
            return (self.items,)
        if self.kind == "alternatives":
            variants = []
            for alternative in self.alternatives:
                variants.extend(alternative.sequence_variants())
            return tuple(variants)
        return ()


@dataclass(frozen=True)
class Guard:
    """A branch fact associated with an export call."""

    group: int
    predicate: str
    choice: str
    truth: bool | None
    expression: str


@dataclass(frozen=True)
class ExportPoint:
    """One export call and the labels known to leave through it."""

    filename: str
    lineno: int
    col_offset: int
    scope: str
    call_name: str
    recipients: frozenset[str] | None
    recipient_reason: str
    fields: frozenset[str]
    field_variants: tuple[frozenset[str], ...]
    fields_reason: str
    guards: tuple[Guard, ...]
    statement: str

    @property
    def identifier(self) -> str:
        return f"{self.filename}:{self.lineno}:{self.col_offset + 1}"

    @property
    def recipient_text(self) -> str:
        if self.recipients is None:
            return f"<unproven: {self.recipient_reason}>"
        if not self.recipients:
            return "<none>"
        return ", ".join(sorted(self.recipients))

    @property
    def line(self) -> int:
        return self.lineno

    @property
    def column(self) -> int:
        return self.col_offset + 1

    @property
    def may_have_unknown_fields(self) -> bool:
        return bool(self.fields_reason)

    def as_dict(self) -> dict:
        return {
            "id": self.identifier,
            "filename": self.filename,
            "line": self.lineno,
            "column": self.col_offset + 1,
            "scope": self.scope,
            "call": self.call_name,
            "statement": self.statement,
            "recipients": (
                sorted(self.recipients)
                if self.recipients is not None
                else None
            ),
            "recipient_reason": self.recipient_reason,
            "fields": sorted(self.fields),
            "field_variants": [
                sorted(variant) for variant in self.field_variants
            ],
            "fields_reason": self.fields_reason,
        }


@dataclass
class ExportCombinationFinding:
    """The judgment for one protected label pair."""

    protected: tuple[str, str]
    status: CombinationStatus
    left: ExportPoint | None
    right: ExportPoint | None
    recipient: str | None
    reason: str
    witnesses: tuple[tuple[ExportPoint, ExportPoint], ...] = ()

    @property
    def judgment(self) -> str:
        return self.status.value.replace("_", "-")

    @property
    def co_executable(self) -> bool:
        return self.status is CombinationStatus.CO_EXECUTABLE

    @property
    def points(self) -> tuple[ExportPoint, ...]:
        return tuple(
            point
            for point in (self.left, self.right)
            if point is not None
        )

    @property
    def export_points(self) -> tuple[ExportPoint, ...]:
        return self.points

    def as_dict(self) -> dict:
        return {
            "protected": list(self.protected),
            "status": self.status.value,
            "judgment": self.judgment,
            "recipient": self.recipient,
            "reason": self.reason,
            "points": [p.as_dict() for p in (self.left, self.right) if p],
            "witnesses": [
                [left.as_dict(), right.as_dict()]
                for left, right in self.witnesses
            ],
        }


@dataclass
class ExportCombinationReport:
    """A complete, serializable export-combination report."""

    filename: str
    findings: tuple[ExportCombinationFinding, ...]
    points: tuple[ExportPoint, ...]
    parse_error: str | None = None

    def as_dict(self) -> dict:
        return {
            "filename": self.filename,
            "parse_error": self.parse_error,
            "findings": [finding.as_dict() for finding in self.findings],
            "export_points": [point.as_dict() for point in self.points],
        }

    def to_json(self) -> str:
        return json.dumps(self.as_dict(), indent=2, sort_keys=True)

    def to_text(self) -> str:
        lines = ["Export combination review", "========================="]
        if self.filename:
            lines.append(f"File: {self.filename}")
        if self.parse_error:
            lines.append(f"Unable to parse source: {self.parse_error}")
            return "\n".join(lines)
        if not self.findings:
            lines.append("No protected combinations were requested.")
            return "\n".join(lines)

        for finding in self.findings:
            labels = " + ".join(finding.protected)
            lines.append("")
            lines.append(f"[{labels}] {finding.judgment.upper()}")
            if finding.recipient:
                lines.append(f"  recipient: {finding.recipient}")
            if finding.left is not None and finding.right is not None:
                lines.append(
                    "  export point 1: "
                    f"{finding.left.identifier} "
                    f"fields={sorted(finding.left.fields)} "
                    f"recipient={finding.left.recipient_text}"
                )
                lines.append(
                    "  export point 2: "
                    f"{finding.right.identifier} "
                    f"fields={sorted(finding.right.fields)} "
                    f"recipient={finding.right.recipient_text}"
                )
                if (
                    finding.left is finding.right
                    or finding.left.identifier == finding.right.identifier
                ):
                    if finding.co_executable:
                        lines.append(
                            "  note: both labels leave through the same "
                            "export point"
                        )
                    else:
                        lines.append(
                            "  note: this export call selects between the "
                            "labels; they do not leave together"
                        )
            if finding.reason:
                lines.append(f"  reason: {finding.reason}")
        return "\n".join(lines)


@dataclass(frozen=True)
class ExportCombinationConfig:
    """Names and bounds used by the finite same-module evaluator."""

    export_functions: frozenset[str] = field(
        default_factory=lambda: DEFAULT_EXPORT_FUNCTIONS
    )
    recipient_arguments: frozenset[str] = field(
        default_factory=lambda: DEFAULT_RECIPIENT_ARGUMENTS
    )
    field_arguments: frozenset[str] = field(
        default_factory=lambda: DEFAULT_FIELD_ARGUMENTS
    )
    max_return_depth: int = 4
    max_return_values: int = 32

    @classmethod
    def from_mapping(cls, data: dict | None) -> "ExportCombinationConfig":
        if not data:
            return cls()
        export_functions = data.get(
            "export_functions",
            data.get("export_names", data.get("api_functions")),
        )
        recipient_arguments = data.get("recipient_arguments")
        field_arguments = data.get("field_arguments")
        return cls(
            export_functions=(
                frozenset(export_functions)
                if export_functions
                else DEFAULT_EXPORT_FUNCTIONS
            ),
            recipient_arguments=(
                frozenset(recipient_arguments)
                if recipient_arguments
                else DEFAULT_RECIPIENT_ARGUMENTS
            ),
            field_arguments=(
                frozenset(field_arguments)
                if field_arguments
                else DEFAULT_FIELD_ARGUMENTS
            ),
            max_return_depth=int(data.get("max_return_depth", 4)),
            max_return_values=int(data.get("max_return_values", 32)),
        )


@dataclass(frozen=True)
class _FunctionInfo:
    name: str
    qualified_name: str
    scope: str
    node: ast.FunctionDef | ast.AsyncFunctionDef


def normalize_protected_combinations(
    combinations: Sequence[Sequence[str]] | Sequence[str] | str | None,
) -> tuple[tuple[str, ...], ...]:
    """Normalize caller input into a tuple of label combinations."""
    if not combinations:
        return ()
    if isinstance(combinations, str):
        raw = [combinations]
    else:
        raw = list(combinations)
    if raw and all(isinstance(item, str) for item in raw):
        if len(raw) == 2 and not any("," in item for item in raw):
            raw = [raw]

    normalized = []
    for combo in raw:
        if isinstance(combo, str):
            labels = tuple(
                label.strip()
                for label in combo.split(",")
                if label.strip()
            )
        else:
            labels = tuple(str(label) for label in combo)
        if len(labels) < 2:
            continue
        if labels not in normalized:
            normalized.append(labels)
    return tuple(normalized)


class ExportCombinationAnalyzer:
    """Analyze one Python module for protected label combinations."""

    def __init__(
        self,
        source: str,
        protected: Sequence[Sequence[str]] | Sequence[str] | str | None,
        filename: str = "<memory>",
        config: ExportCombinationConfig | None = None,
    ):
        self.source = source
        self.filename = filename
        self.protected = normalize_protected_combinations(protected)
        self.config = config or ExportCombinationConfig()
        self.tree = ast.parse(source, filename=filename)
        self.points: list[ExportPoint] = []
        self._guard_groups = itertools.count(1)
        self._module_env: dict[str, StaticValue] = {}
        self._collect_exports = True
        self._function_infos: list[_FunctionInfo] = []
        self._functions_by_scope: dict[
            str, dict[str, _FunctionInfo]
        ] = {}
        self._functions_by_name: dict[str, list[_FunctionInfo]] = {}
        self._index_functions()

    def analyze(self) -> ExportCombinationReport:
        self._collect_exports = False
        self._module_env = self._walk_block(
            self.tree.body, {}, (), "module"
        )
        self._collect_exports = True
        self._walk_block(self.tree.body, dict(self._module_env), (), "module")

        for info in self._function_infos:
            env = dict(self._module_env)
            self._bind_function_parameters(info.node, env)
            self._walk_block(info.node.body, env, (), info.scope)

        self.points.sort(
            key=lambda point: (point.filename, point.lineno, point.col_offset)
        )
        findings = []
        for combination in self.protected:
            for pair in itertools.combinations(combination, 2):
                findings.append(self._judge_pair(pair))
        return ExportCombinationReport(
            filename=self.filename,
            findings=tuple(findings),
            points=tuple(self.points),
        )

    def _index_functions(self) -> None:
        def walk(body, scope):
            for node in body:
                if isinstance(
                    node, (ast.FunctionDef, ast.AsyncFunctionDef)
                ):
                    child_scope = f"{scope}.{node.name}".lstrip(".")
                    info = _FunctionInfo(
                        name=node.name,
                        qualified_name=child_scope,
                        scope=scope,
                        node=node,
                    )
                    self._function_infos.append(info)
                    self._functions_by_scope.setdefault(scope, {})[
                        node.name
                    ] = info
                    if scope == "module":
                        self._functions_by_scope.setdefault("module", {})[
                            node.name
                        ] = info
                    self._functions_by_name.setdefault(node.name, []).append(
                        info
                    )
                    walk(node.body, child_scope)
                elif isinstance(node, ast.ClassDef):
                    walk(node.body, f"{scope}.{node.name}".lstrip("."))

        walk(self.tree.body, "module")

    def _walk_block(
        self,
        statements,
        env: dict[str, StaticValue],
        guards: tuple[Guard, ...],
        scope: str,
    ) -> dict[str, StaticValue]:
        current = dict(env)
        for statement in statements:
            current = self._walk_statement(
                statement, current, guards, scope
            )
        return current

    def _walk_statement(
        self,
        statement,
        env: dict[str, StaticValue],
        guards: tuple[Guard, ...],
        scope: str,
    ) -> dict[str, StaticValue]:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return env
        if isinstance(statement, ast.ClassDef):
            return env

        if isinstance(statement, ast.Assign):
            value = self._eval(statement.value, env, scope, ())
            for target in statement.targets:
                self._bind_target(target, value, env)
            self._collect_export_calls(statement.value, env, guards, scope)
            return env

        if isinstance(statement, ast.AnnAssign):
            if statement.value is not None:
                value = self._eval(statement.value, env, scope, ())
                self._bind_target(statement.target, value, env)
                self._collect_export_calls(
                    statement.value, env, guards, scope
                )
            return env

        if isinstance(statement, ast.AugAssign):
            current = self._eval(statement.target, env, scope, ())
            value = self._eval(statement.value, env, scope, ())
            self._bind_target(
                statement.target,
                StaticValue.choices((current, value)),
                env,
            )
            return env

        if isinstance(statement, ast.If):
            self._collect_export_calls(
                statement.test, env, guards, scope
            )
            group = next(self._guard_groups)
            body_guard, else_guard = self._guards_from_test(
                statement.test, group
            )
            body_env = self._walk_block(
                statement.body,
                dict(env),
                guards + (body_guard,),
                scope,
            )
            else_env = self._walk_block(
                statement.orelse,
                dict(env),
                guards + (else_guard,),
                scope,
            )
            return self._merge_envs(body_env, else_env)

        if isinstance(statement, (ast.For, ast.AsyncFor)):
            iter_value = self._eval(statement.iter, env, scope, ())
            self._collect_export_calls(
                statement.iter, env, guards, scope
            )
            self._bind_target(
                statement.target,
                StaticValue.choices(self._iter_variants(iter_value)),
                env,
            )
            body_env = self._walk_block(
                statement.body, dict(env), guards, scope
            )
            else_env = self._walk_block(
                statement.orelse, dict(body_env), guards, scope
            )
            return self._merge_envs(env, else_env)

        if isinstance(statement, ast.While):
            self._collect_export_calls(
                statement.test, env, guards, scope
            )
            body_env = self._walk_block(
                statement.body, dict(env), guards, scope
            )
            else_env = self._walk_block(
                statement.orelse, dict(body_env), guards, scope
            )
            return self._merge_envs(env, else_env)

        if isinstance(statement, (ast.With, ast.AsyncWith)):
            for item in statement.items:
                self._collect_export_calls(
                    item.context_expr, env, guards, scope
                )
            return self._walk_block(
                statement.body, env, guards, scope
            )

        if isinstance(statement, ast.Try):
            body_env = self._walk_block(
                statement.body, dict(env), guards, scope
            )
            branch_envs = [body_env]
            for handler in statement.handlers:
                branch_envs.append(
                    self._walk_block(
                        handler.body, dict(env), guards, scope
                    )
                )
            if statement.orelse:
                branch_envs.append(
                    self._walk_block(
                        statement.orelse, dict(body_env), guards, scope
                    )
                )
            merged = env
            for branch_env in branch_envs:
                merged = self._merge_envs(merged, branch_env)
            if statement.finalbody:
                merged = self._walk_block(
                    statement.finalbody, merged, guards, scope
                )
            return merged

        if isinstance(statement, ast.Match):
            self._collect_export_calls(
                statement.subject, env, guards, scope
            )
            group = next(self._guard_groups)
            subject = ast.unparse(statement.subject)
            branch_envs = []
            for index, case in enumerate(statement.cases):
                case_guard = Guard(
                    group=group,
                    predicate=f"match:{subject}",
                    choice=f"case:{index}",
                    truth=None,
                    expression=ast.unparse(case.pattern),
                )
                branch_envs.append(
                    self._walk_block(
                        case.body,
                        dict(env),
                        guards + (case_guard,),
                        scope,
                    )
                )
            merged = dict(env)
            for branch_env in branch_envs:
                merged = self._merge_envs(merged, branch_env)
            return merged

        if isinstance(statement, ast.Return):
            if statement.value is not None:
                self._collect_export_calls(
                    statement.value, env, guards, scope
                )
            return env

        if isinstance(statement, ast.Expr):
            self._collect_export_calls(
                statement.value, env, guards, scope
            )
            return env

        if isinstance(statement, ast.Assert):
            self._collect_export_calls(
                statement.test, env, guards, scope
            )
            return env

        return env

    def _collect_export_calls(
        self,
        node,
        env: dict[str, StaticValue],
        guards: tuple[Guard, ...],
        scope: str,
    ) -> None:
        if not self._collect_exports:
            return
        stack = [node]
        while stack:
            current = stack.pop()
            if isinstance(current, ast.Call) and self._is_export_call(current):
                self._record_export(current, env, guards, scope)
            for child in ast.iter_child_nodes(current):
                if isinstance(
                    child, (ast.FunctionDef, ast.AsyncFunctionDef)
                ):
                    continue
                if isinstance(child, ast.ClassDef):
                    continue
                stack.append(child)

    def _record_export(
        self,
        call: ast.Call,
        env: dict[str, StaticValue],
        guards: tuple[Guard, ...],
        scope: str,
    ) -> None:
        recipient_value, field_values, extra_reason = (
            self._parse_export_call(call, env, scope)
        )
        recipients = None
        recipient_reason = (
            extra_reason or "recipient could not be determined"
        )
        if recipient_value is not None:
            recipients, recipient_reason = recipient_value.recipient_values()

        fields = frozenset().union(
            *(value.labels() for value in field_values)
        )
        field_reasons = []
        for value in field_values:
            field_reasons.extend(value.unknown_reasons())
        fields_reason = "; ".join(dict.fromkeys(field_reasons))
        field_variants = self._combine_field_variants(field_values)

        statement = ast.get_source_segment(self.source, call)
        if not statement:
            statement = ast.unparse(call)
        self.points.append(
            ExportPoint(
                filename=self.filename,
                lineno=call.lineno,
                col_offset=call.col_offset,
                scope=scope,
                call_name=self._call_name(call),
                recipients=recipients,
                recipient_reason=recipient_reason,
                fields=fields,
                field_variants=field_variants,
                fields_reason=fields_reason,
                guards=guards,
                statement=statement,
            )
        )

    def _parse_export_call(
        self,
        call: ast.Call,
        env: dict[str, StaticValue],
        scope: str,
    ) -> tuple[StaticValue | None, list[StaticValue], str]:
        positional, keywords, reasons = self._call_arguments(
            call, env, scope
        )

        payload_reason = ""
        for payload_name in ("data", "payload", "record"):
            payload = keywords.get(payload_name)
            if payload is None or payload.kind != "mapping":
                continue
            inner = {}
            for key, value in payload.mapping:
                if key.kind == "scalar" and isinstance(key.scalar, str):
                    inner[key.scalar] = value
            if any(
                name in inner
                for name in (
                    set(self.config.recipient_arguments)
                    | set(self.config.field_arguments)
                )
            ):
                keywords.update(inner)
                keywords.pop(payload_name, None)
                break
            payload_reason = (
                f"payload mapping for {payload_name!r} does not expose "
                "recognized recipient/field keys"
            )

        recipient_value = self._first_keyword(
            keywords, self.config.recipient_arguments
        )

        positional_values = [item[0] for item in positional]
        positional_reasons = [item[1] for item in positional if item[1]]
        field_values = []

        if recipient_value is not None:
            field_values.extend(positional_values)
        elif positional_values and self._looks_like_recipient(
            positional_values[0]
        ):
            recipient_value = positional_values[0]
            field_values.extend(positional_values[1:])
        else:
            field_values.extend(positional_values)

        for name in self.config.field_arguments:
            if name in keywords:
                field_values.append(keywords[name])

        reasons.extend(positional_reasons)
        reasons.extend(kw for kw in keywords.get("__unknown__", ()))
        if payload_reason:
            reasons.append(payload_reason)

        if not field_values:
            reason = "no recognizable field argument was found"
            if reasons:
                reason = f"{reason}: {'; '.join(dict.fromkeys(reasons))}"
            field_values = [StaticValue.unknown(reason)]
        elif reasons:
            field_values.append(
                StaticValue.unknown(
                    "; ".join(dict.fromkeys(reasons))
                )
            )

        if recipient_value is None:
            reason = "recipient could not be determined"
            if reasons:
                reason = f"{reason}: {'; '.join(dict.fromkeys(reasons))}"
            return None, field_values, reason
        return recipient_value, field_values, ""

    def _call_arguments(
        self, call: ast.Call, env: dict[str, StaticValue], scope: str
    ) -> tuple[
        list[tuple[StaticValue, str]],
        dict[str, StaticValue],
        list[str],
    ]:
        positional = []
        keywords = {}
        reasons = []
        for argument in call.args:
            if isinstance(argument, ast.Starred):
                value = self._eval(argument.value, env, scope, ())
                variants = value.sequence_variants()
                if variants:
                    for variant in variants:
                        positional.extend((item, "") for item in variant)
                else:
                    reason = (
                        "starred positional argument cannot be expanded "
                        "statically"
                    )
                    positional.append((StaticValue.unknown(reason), reason))
                    reasons.append(reason)
            else:
                positional.append((self._eval(argument, env, scope, ()), ""))

        unknown_keywords = []
        for keyword in call.keywords:
            if keyword.arg is None:
                value = self._eval(keyword.value, env, scope, ())
                if value.kind == "mapping":
                    for key, item in value.mapping:
                        if key.kind == "scalar" and isinstance(
                            key.scalar, str
                        ):
                            keywords[key.scalar] = item
                        else:
                            unknown_keywords.append(
                                "** argument contains a non-static key"
                            )
                else:
                    unknown_keywords.append(
                        "** argument cannot be expanded statically"
                    )
            else:
                keywords[keyword.arg] = self._eval(
                    keyword.value, env, scope, ()
                )
        if unknown_keywords:
            keywords["__unknown__"] = tuple(
                dict.fromkeys(unknown_keywords)
            )
        return positional, keywords, reasons

    @staticmethod
    def _value_field_variants(
        value: StaticValue,
    ) -> tuple[frozenset[str], ...]:
        if value.kind == "alternatives":
            variants = []
            for alternative in value.alternatives:
                variants.extend(
                    ExportCombinationAnalyzer._value_field_variants(
                        alternative
                    )
                )
            return tuple(dict.fromkeys(variants))
        if value.kind in {"mapping", "sequence"}:
            return (frozenset(value.labels()),)
        if value.kind == "scalar" and isinstance(value.scalar, str):
            return (frozenset({value.scalar}),)
        return (frozenset(),)

    @classmethod
    def _combine_field_variants(
        cls, field_values: Sequence[StaticValue]
    ) -> tuple[frozenset[str], ...]:
        variants = [frozenset()]
        for value in field_values:
            next_variants = []
            for base in variants:
                for addition in cls._value_field_variants(value):
                    next_variants.append(base | addition)
            variants = next_variants
        return tuple(dict.fromkeys(variants))

    @staticmethod
    def _first_keyword(
        keywords: dict[str, StaticValue], names: Iterable[str]
    ) -> StaticValue | None:
        values = [keywords[name] for name in names if name in keywords]
        return StaticValue.choices(values) if values else None

    @staticmethod
    def _looks_like_recipient(value: StaticValue) -> bool:
        if value.kind == "scalar":
            return isinstance(value.scalar, str)
        if value.kind == "alternatives":
            return all(
                alternative.kind == "scalar"
                and isinstance(alternative.scalar, str)
                for alternative in value.alternatives
            )
        return False

    def _is_export_call(self, call: ast.Call) -> bool:
        parts = self._call_parts(call)
        if not parts:
            return False
        last = parts[-1].lower()
        if last in self.config.export_functions:
            return True
        if last.endswith("_export"):
            return True
        return any("export" in part.lower() for part in parts[:-1])

    @staticmethod
    def _call_parts(call: ast.Call) -> tuple[str, ...]:
        function = call.func
        if isinstance(function, ast.Name):
            return (function.id,)
        if isinstance(function, ast.Attribute):
            return tuple(ast.unparse(function).split("."))
        return ()

    def _call_name(self, call: ast.Call) -> str:
        parts = self._call_parts(call)
        return ".".join(parts) if parts else ast.unparse(call.func)

    def _guards_from_test(
        self, test, group: int
    ) -> tuple[Guard, Guard]:
        predicate, truth, expression = self._predicate_from_test(test)
        body_guard = Guard(
            group=group,
            predicate=predicate,
            choice="true" if truth is not False else "false",
            truth=truth,
            expression=expression,
        )
        else_guard = Guard(
            group=group,
            predicate=predicate,
            choice="false" if truth is not False else "true",
            truth=(not truth) if truth is not None else None,
            expression=expression,
        )
        return body_guard, else_guard

    def _predicate_from_test(self, test) -> tuple[str, bool | None, str]:
        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            predicate, truth, expression = self._predicate_from_test(
                test.operand
            )
            return predicate, (not truth) if truth is not None else None, (
                f"not ({expression})"
            )

        if isinstance(test, ast.Compare) and len(test.ops) == 1:
            left = ast.unparse(test.left)
            right = ast.unparse(test.comparators[0])
            operator = test.ops[0]
            if isinstance(operator, ast.Eq):
                return f"eq:{left}:{right}", True, ast.unparse(test)
            if isinstance(operator, ast.NotEq):
                return f"eq:{left}:{right}", False, ast.unparse(test)
            if isinstance(operator, ast.Is):
                return f"is:{left}:{right}", True, ast.unparse(test)
            if isinstance(operator, ast.IsNot):
                return f"is:{left}:{right}", False, ast.unparse(test)
            if isinstance(operator, ast.In):
                return f"in:{left}:{right}", True, ast.unparse(test)
            if isinstance(operator, ast.NotIn):
                return f"in:{left}:{right}", False, ast.unparse(test)

        expression = ast.unparse(test)
        return f"expr:{expression}", True, expression

    @staticmethod
    def _guards_exclusive(
        left: tuple[Guard, ...], right: tuple[Guard, ...]
    ) -> tuple[bool, str]:
        for left_guard in left:
            for right_guard in right:
                if (
                    left_guard.group == right_guard.group
                    and left_guard.choice != right_guard.choice
                ):
                    return (
                        True,
                        "guards are different branches of the same "
                        f"condition ({left_guard.expression!r} vs "
                        f"{right_guard.expression!r})",
                    )
                if (
                    left_guard.predicate == right_guard.predicate
                    and left_guard.truth is not None
                    and right_guard.truth is not None
                    and left_guard.truth != right_guard.truth
                ):
                    return (
                        True,
                        "guards require opposite outcomes for the same "
                        f"predicate ({left_guard.expression!r})",
                    )
        return False, ""

    def _judge_pair(
        self, pair: Sequence[str]
    ) -> ExportCombinationFinding:
        first, second = pair[0], pair[1]
        first_points = [p for p in self.points if first in p.fields]
        second_points = [p for p in self.points if second in p.fields]

        if not first_points or not second_points:
            missing = first if not first_points else second
            unknown_points = [
                p for p in self.points if p.may_have_unknown_fields
            ]
            if unknown_points:
                reason = (
                    f"label {missing!r} is not statically visible; "
                    f"{unknown_points[0].identifier}: "
                    f"{unknown_points[0].fields_reason}"
                )
            else:
                reason = f"label {missing!r} was not found in any export"
            if first_points and second_points:
                left, right = first_points[0], second_points[0]
            elif first_points:
                left = first_points[0]
                right = unknown_points[0] if unknown_points else left
            elif second_points:
                left = (
                    unknown_points[0]
                    if unknown_points
                    else second_points[0]
                )
                right = second_points[0]
            else:
                left = unknown_points[0] if unknown_points else None
                right = left
            return ExportCombinationFinding(
                protected=(first, second),
                status=CombinationStatus.UNPROVABLE,
                left=left,
                right=right,
                recipient=None,
                reason=reason,
            )

        outcomes = {
            CombinationStatus.CO_EXECUTABLE: [],
            CombinationStatus.INDEPENDENT_RECIPIENTS: [],
            CombinationStatus.UNPROVABLE: [],
            CombinationStatus.MUTUALLY_EXCLUSIVE: [],
        }
        for left in first_points:
            for right in second_points:
                if left is right:
                    same_payload = any(
                        first in variant and second in variant
                        for variant in left.field_variants
                    )
                    if same_payload:
                        status = CombinationStatus.CO_EXECUTABLE
                        reason = (
                            "both labels leave through the same export "
                            "point"
                        )
                    else:
                        status = CombinationStatus.MUTUALLY_EXCLUSIVE
                        reason = (
                            "one export call selects between the two "
                            "labels; they do not leave together"
                        )
                elif left.scope != right.scope:
                    status = CombinationStatus.UNPROVABLE
                    reason = (
                        "export points are in different execution scopes "
                        f"({left.scope!r} and {right.scope!r}); their call "
                        "relationship is not modeled"
                    )
                elif left.recipients is None:
                    status = CombinationStatus.UNPROVABLE
                    reason = (
                        "recipient for the first export point is unknown: "
                        f"{left.recipient_reason}"
                    )
                elif right.recipients is None:
                    status = CombinationStatus.UNPROVABLE
                    reason = (
                        "recipient for the second export point is unknown: "
                        f"{right.recipient_reason}"
                    )
                elif left.recipients.isdisjoint(right.recipients):
                    status = CombinationStatus.INDEPENDENT_RECIPIENTS
                    reason = (
                        "export points use independent recipients "
                        f"({left.recipient_text!r} and "
                        f"{right.recipient_text!r}); they must not be "
                        "aggregated"
                    )
                else:
                    exclusive, exclusive_reason = self._guards_exclusive(
                        left.guards, right.guards
                    )
                    if exclusive:
                        status = CombinationStatus.MUTUALLY_EXCLUSIVE
                        reason = exclusive_reason
                    else:
                        status = CombinationStatus.CO_EXECUTABLE
                        common = sorted(
                            left.recipients & right.recipients
                        )
                        reason = (
                            "export points can execute in the same scope "
                            f"for recipient {common[0]!r}"
                        )
                outcomes[status].append((left, right, reason))

        for status in (
            CombinationStatus.CO_EXECUTABLE,
            CombinationStatus.UNPROVABLE,
            CombinationStatus.INDEPENDENT_RECIPIENTS,
            CombinationStatus.MUTUALLY_EXCLUSIVE,
        ):
            candidates = outcomes[status]
            if not candidates:
                continue
            candidates.sort(
                key=lambda item: (
                    item[0].identifier == item[1].identifier,
                    item[0].lineno,
                    item[1].lineno,
                    item[0].col_offset,
                    item[1].col_offset,
                )
            )
            left, right, reason = candidates[0]
            recipient = None
            if left.recipients is not None:
                recipient = ", ".join(sorted(left.recipients))
            return ExportCombinationFinding(
                protected=(first, second),
                status=status,
                left=left,
                right=right,
                recipient=recipient,
                reason=reason if status is not CombinationStatus.UNPROVABLE
                else "; ".join(
                    dict.fromkeys(item[2] for item in candidates)
                ),
                witnesses=tuple(
                    (item[0], item[1]) for item in candidates
                ),
            )

        return ExportCombinationFinding(
            protected=(first, second),
            status=CombinationStatus.UNPROVABLE,
            left=None,
            right=None,
            recipient=None,
            reason="no export relationship could be evaluated",
        )

    def _merge_envs(
        self, left: dict[str, StaticValue], right: dict[str, StaticValue]
    ) -> dict[str, StaticValue]:
        merged = {}
        for name in set(left) | set(right):
            left_value = left.get(name)
            right_value = right.get(name)
            if left_value is None:
                merged[name] = right_value
            elif right_value is None:
                merged[name] = left_value
            elif left_value == right_value:
                merged[name] = left_value
            else:
                merged[name] = StaticValue.choices(
                    (left_value, right_value)
                )
        return merged

    def _bind_target(
        self,
        target,
        value: StaticValue,
        env: dict[str, StaticValue],
    ) -> None:
        if isinstance(target, ast.Name):
            env[target.id] = value
            return
        if isinstance(target, ast.Starred):
            self._bind_target(target.value, value, env)
            return
        if isinstance(target, (ast.Tuple, ast.List)):
            variants = value.sequence_variants()
            for index, element in enumerate(target.elts):
                if isinstance(element, ast.Starred):
                    rest = []
                    for variant in variants:
                        rest.extend(variant[index:])
                    self._bind_target(
                        element.value,
                        StaticValue.sequence(rest)
                        if rest
                        else StaticValue.unknown(
                            "starred unpack target cannot be resolved"
                        ),
                        env,
                    )
                    continue
                choices = []
                for variant in variants:
                    if index < len(variant):
                        choices.append(variant[index])
                if choices:
                    self._bind_target(
                        element, StaticValue.choices(choices), env
                    )
                else:
                    self._bind_target(
                        element,
                        StaticValue.unknown(
                            "unpacked value is not statically available"
                        ),
                        env,
                    )
            return

    @staticmethod
    def _iter_variants(value: StaticValue) -> tuple[StaticValue, ...]:
        if value.kind == "sequence":
            return value.items
        if value.kind == "alternatives":
            items = []
            for alternative in value.alternatives:
                if alternative.kind == "sequence":
                    items.extend(alternative.items)
                else:
                    items.append(
                        StaticValue.unknown(
                            "loop item cannot be resolved statically"
                        )
                    )
            return tuple(items)
        return (
            StaticValue.unknown("loop iterable cannot be resolved"),
        )

    def _bind_function_parameters(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        env: dict[str, StaticValue],
    ) -> None:
        arguments = node.args
        for argument in (
            list(arguments.posonlyargs)
            + list(arguments.args)
            + list(arguments.kwonlyargs)
        ):
            env[argument.arg] = StaticValue.unknown(
                f"parameter {argument.arg!r} is dynamic at the export site"
            )
        if arguments.vararg:
            env[arguments.vararg.arg] = StaticValue.unknown(
                "variadic parameter is dynamic at the export site"
            )
        if arguments.kwarg:
            env[arguments.kwarg.arg] = StaticValue.unknown(
                "variadic keyword parameter is dynamic at the export site"
            )

    def _eval(
        self,
        node,
        env: dict[str, StaticValue],
        scope: str,
        call_stack: tuple[str, ...],
    ) -> StaticValue:
        if isinstance(node, ast.Constant):
            value = node.value
            if isinstance(value, bytes):
                value = value.decode("utf-8", "replace")
            return StaticValue("scalar", scalar=value)

        if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
            return StaticValue.sequence(
                self._eval(item, env, scope, call_stack)
                for item in node.elts
            )

        if isinstance(node, ast.Dict):
            pairs = []
            for key, value in zip(node.keys, node.values):
                if key is None:
                    expanded = self._eval(value, env, scope, call_stack)
                    if expanded.kind == "mapping":
                        pairs.extend(expanded.mapping)
                    else:
                        pairs.append(
                            (
                                StaticValue.unknown(
                                    "mapping unpack key is unknown"
                                ),
                                expanded,
                            )
                        )
                else:
                    pairs.append(
                        (
                            self._eval(key, env, scope, call_stack),
                            self._eval(value, env, scope, call_stack),
                        )
                    )
            return StaticValue.mapping_value(pairs)

        if isinstance(node, ast.Name):
            if node.id in env:
                return env[node.id]
            if node.id in self._module_env:
                return self._module_env[node.id]
            return StaticValue.unknown(
                f"name {node.id!r} has no statically known value"
            )

        if isinstance(node, ast.Starred):
            return self._eval(node.value, env, scope, call_stack)

        if isinstance(node, ast.NamedExpr):
            value = self._eval(node.value, env, scope, call_stack)
            self._bind_target(node.target, value, env)
            return value

        if isinstance(node, ast.IfExp):
            return StaticValue.choices(
                (
                    self._eval(node.body, env, scope, call_stack),
                    self._eval(node.orelse, env, scope, call_stack),
                )
            )

        if isinstance(node, ast.BoolOp):
            return StaticValue.choices(
                self._eval(value, env, scope, call_stack)
                for value in node.values
            )

        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = self._eval(node.left, env, scope, call_stack)
            right = self._eval(node.right, env, scope, call_stack)
            if (
                left.kind == "scalar"
                and right.kind == "scalar"
                and isinstance(left.scalar, str)
                and isinstance(right.scalar, str)
            ):
                return StaticValue("scalar", scalar=left.scalar + right.scalar)
            if left.kind == "sequence" and right.kind == "sequence":
                return StaticValue.sequence(left.items + right.items)
            return StaticValue.unknown("binary expression is not static")

        if isinstance(node, ast.Subscript):
            container = self._eval(node.value, env, scope, call_stack)
            index = self._eval(node.slice, env, scope, call_stack)
            if (
                container.kind == "mapping"
                and index.kind == "scalar"
                and isinstance(index.scalar, (str, int))
            ):
                for key, value in container.mapping:
                    if (
                        key.kind == "scalar"
                        and key.scalar == index.scalar
                    ):
                        return value
            if (
                container.kind == "sequence"
                and index.kind == "scalar"
                and isinstance(index.scalar, int)
                and -len(container.items)
                <= index.scalar
                < len(container.items)
            ):
                return container.items[index.scalar]
            return StaticValue.unknown("subscript is not statically known")

        if isinstance(node, ast.JoinedStr):
            parts = []
            for value in node.values:
                if isinstance(value, ast.Constant):
                    parts.append(str(value.value))
                else:
                    return StaticValue.unknown(
                        "f-string contains a dynamic value"
                    )
            return StaticValue("scalar", scalar="".join(parts))

        if isinstance(node, ast.Await):
            return self._eval(node.value, env, scope, call_stack)

        if isinstance(node, ast.Call):
            parts = self._call_parts(node)
            if parts and parts[-1] in {
                "tuple",
                "list",
                "set",
                "frozenset",
            } and parts[0] in {"tuple", "list", "set", "frozenset"}:
                if not node.args:
                    return StaticValue.sequence(())
                value = self._eval(node.args[0], env, scope, call_stack)
                if value.kind == "sequence":
                    return value
                return StaticValue.unknown(
                    f"{parts[-1]}() argument is not a static sequence"
                )
            if parts and parts[-1] == "keys" and node.args == []:
                value = self._eval(node.func.value, env, scope, call_stack)
                if value.kind == "mapping":
                    return StaticValue.sequence(
                        key for key, _ in value.mapping
                    )
            if parts:
                helper = self._find_function(parts, scope)
                if helper is not None:
                    return self._eval_function_return(
                        helper, node, env, scope, call_stack
                    )
            name = ".".join(parts) if parts else ast.unparse(node.func)
            return StaticValue.unknown(
                f"call to {name!r} is not a finite same-module return"
            )

        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
            if (
                isinstance(node.elt, ast.Constant)
                and len(node.generators) == 1
            ):
                iterable = self._eval(
                    node.generators[0].iter, env, scope, call_stack
                )
                if iterable.kind == "sequence":
                    return StaticValue.sequence(
                        self._eval(node.elt, env, scope, call_stack)
                        for _ in iterable.items
                    )
            return StaticValue.unknown(
                "comprehension cannot be resolved statically"
            )

        return StaticValue.unknown(
            f"{type(node).__name__} cannot be resolved statically"
        )

    def _find_function(
        self, parts: Sequence[str], scope: str
    ) -> _FunctionInfo | None:
        name = parts[-1]
        current = self._functions_by_scope.get(scope, {})
        if name in current:
            return current[name]
        module = self._functions_by_scope.get("module", {})
        if name in module:
            return module[name]
        candidates = self._functions_by_name.get(name, [])
        return candidates[0] if len(candidates) == 1 else None

    def _eval_function_return(
        self,
        info: _FunctionInfo,
        call: ast.Call,
        caller_env: dict[str, StaticValue],
        caller_scope: str,
        call_stack: tuple[str, ...],
    ) -> StaticValue:
        if len(call_stack) >= self.config.max_return_depth:
            return StaticValue.unknown(
                "same-module return depth limit reached at "
                f"{info.qualified_name!r}"
            )
        if info.qualified_name in call_stack:
            return StaticValue.unknown(
                f"recursive same-module return at {info.qualified_name!r}"
            )

        env = dict(self._module_env)
        positional, keywords, _ = self._call_arguments(
            call, caller_env, caller_scope
        )
        self._bind_call_parameters(
            info.node,
            [value for value, _ in positional],
            keywords,
            env,
            caller_scope,
        )
        returns = self._collect_returns(
            info.node.body,
            env,
            caller_scope,
            call_stack + (info.qualified_name,),
        )
        if not returns:
            return StaticValue.unknown(
                f"function {info.qualified_name!r} has no finite return "
                "value"
            )
        if len(returns) > self.config.max_return_values:
            return StaticValue.unknown(
                f"function {info.qualified_name!r} has too many return "
                "values to evaluate"
            )
        return StaticValue.choices(returns)

    def _bind_call_parameters(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        positional: Sequence[StaticValue],
        keywords: dict[str, StaticValue],
        env: dict[str, StaticValue],
        scope: str,
    ) -> None:
        arguments = node.args
        parameters = list(arguments.posonlyargs) + list(arguments.args)
        defaults = [None] * (
            len(parameters) - len(arguments.defaults)
        ) + list(arguments.defaults)
        for index, parameter in enumerate(parameters):
            if index < len(positional):
                env[parameter.arg] = positional[index]
            elif parameter.arg in keywords:
                env[parameter.arg] = keywords[parameter.arg]
            elif defaults[index] is not None:
                env[parameter.arg] = self._eval(
                    defaults[index], env, scope, ()
                )
            else:
                env[parameter.arg] = StaticValue.unknown(
                    f"argument {parameter.arg!r} was not supplied"
                )

        for parameter, default in zip(
            arguments.kwonlyargs, arguments.kw_defaults
        ):
            if parameter.arg in keywords:
                env[parameter.arg] = keywords[parameter.arg]
            elif default is not None:
                env[parameter.arg] = self._eval(default, env, scope, ())
            else:
                env[parameter.arg] = StaticValue.unknown(
                    f"keyword argument {parameter.arg!r} was not supplied"
                )

        if arguments.vararg:
            env[arguments.vararg.arg] = StaticValue.sequence(
                positional[len(parameters):]
            )
        if arguments.kwarg:
            env[arguments.kwarg.arg] = StaticValue.mapping_value(
                (
                    StaticValue("scalar", scalar=name),
                    value,
                )
                for name, value in keywords.items()
                if name != "__unknown__"
            )

    def _collect_returns(
        self,
        statements,
        env: dict[str, StaticValue],
        scope: str,
        call_stack: tuple[str, ...],
    ) -> list[StaticValue]:
        returns = []

        def walk(block, current_env):
            for statement in block:
                if isinstance(
                    statement,
                    (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef),
                ):
                    continue
                if isinstance(statement, ast.Return):
                    if statement.value is None:
                        returns.append(
                            StaticValue("scalar", scalar=None)
                        )
                    else:
                        returns.append(
                            self._eval(
                                statement.value,
                                current_env,
                                scope,
                                call_stack,
                            )
                        )
                    continue
                if isinstance(statement, ast.Assign):
                    value = self._eval(
                        statement.value, current_env, scope, call_stack
                    )
                    for target in statement.targets:
                        self._bind_target(target, value, current_env)
                    continue
                if isinstance(statement, ast.AnnAssign):
                    if statement.value is not None:
                        value = self._eval(
                            statement.value,
                            current_env,
                            scope,
                            call_stack,
                        )
                        self._bind_target(
                            statement.target, value, current_env
                        )
                    continue
                if isinstance(statement, ast.If):
                    walk(statement.body, dict(current_env))
                    walk(statement.orelse, dict(current_env))
                    continue
                if isinstance(statement, (ast.For, ast.AsyncFor)):
                    walk(statement.body, dict(current_env))
                    walk(statement.orelse, dict(current_env))
                    continue
                if isinstance(statement, ast.While):
                    walk(statement.body, dict(current_env))
                    walk(statement.orelse, dict(current_env))
                    continue
                if isinstance(statement, ast.Match):
                    for case in statement.cases:
                        walk(case.body, dict(current_env))
                    continue
                if isinstance(statement, (ast.With, ast.AsyncWith)):
                    walk(statement.body, dict(current_env))
                    continue
                if isinstance(statement, ast.Try):
                    walk(statement.body, dict(current_env))
                    for handler in statement.handlers:
                        walk(handler.body, dict(current_env))
                    walk(statement.orelse, dict(current_env))
                    walk(statement.finalbody, dict(current_env))
                    continue

        walk(statements, dict(env))
        return returns


def analyze_source(
    source: str,
    protected: Sequence[Sequence[str]] | Sequence[str] | str | None,
    filename: str = "<memory>",
    config: ExportCombinationConfig | dict | None = None,
) -> ExportCombinationReport:
    """Analyze in-memory Python source for protected export combinations."""
    if isinstance(config, dict):
        config = ExportCombinationConfig.from_mapping(config)
    return ExportCombinationAnalyzer(
        source=source,
        protected=protected,
        filename=filename,
        config=config,
    ).analyze()


def analyze_file(
    path: str | Path,
    protected: Sequence[Sequence[str]] | Sequence[str] | str | None,
    config: ExportCombinationConfig | dict | None = None,
) -> ExportCombinationReport:
    """Analyze one Python file for protected export combinations."""
    path = Path(path)
    return analyze_source(
        path.read_text(encoding="utf-8"),
        protected=protected,
        filename=str(path),
        config=config,
    )


def find_export_combinations(
    source: str,
    protected: Sequence[Sequence[str]] | Sequence[str] | str | None,
    filename: str = "<memory>",
    config: ExportCombinationConfig | dict | None = None,
) -> tuple[ExportCombinationFinding, ...]:
    """Convenience wrapper returning only findings."""
    return analyze_source(
        source, protected, filename=filename, config=config
    ).findings


analyze_exports = analyze_source
analyze_export_combinations = analyze_source
scan_export_combinations = analyze_source
