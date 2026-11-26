# SPDX-License-Identifier: Apache-2.0
"""Project-configurable lease lifecycle checks for elevated clients."""

from __future__ import annotations

import ast
import fnmatch
import hashlib
from dataclasses import dataclass, field
from typing import Any

import bandit
from bandit.core import issue as bandit_issue
from bandit.core import test_properties as test
from bandit.core import utils as bandit_utils


LEASE_LEAKED = "leaked_lease"
LEASE_LEAK = LEASE_LEAKED
CLEANUP_NOT_GUARANTEED = "cleanup_not_guaranteed"
CLEANUP_UNVERIFIED = CLEANUP_NOT_GUARANTEED
NEEDS_MANUAL_REVIEW = "needs_manual_review"
MANUAL_REVIEW_REQUIRED = NEEDS_MANUAL_REVIEW
REVIEW_REQUIRED = NEEDS_MANUAL_REVIEW
TRUSTED_RENEWAL = "trusted_renewal"

VERDICT_ALIASES = {
    "lease_leak": LEASE_LEAKED,
    "lease_leaked": LEASE_LEAKED,
    "leaked": LEASE_LEAKED,
    "leaked_lease": LEASE_LEAKED,
    "LEAKED_LEASE": LEASE_LEAKED,
    "cleanup_not_guaranteed": CLEANUP_NOT_GUARANTEED,
    "cleanup_not_ensured": CLEANUP_NOT_GUARANTEED,
    "cleanup_unverified": CLEANUP_NOT_GUARANTEED,
    "CLEANUP_NOT_GUARANTEED": CLEANUP_NOT_GUARANTEED,
    "needs_manual_review": NEEDS_MANUAL_REVIEW,
    "manual_review_required": NEEDS_MANUAL_REVIEW,
    "needs_human_review": NEEDS_MANUAL_REVIEW,
    "review_required": NEEDS_MANUAL_REVIEW,
    "NEEDS_MANUAL_REVIEW": NEEDS_MANUAL_REVIEW,
    "trusted_renewal": TRUSTED_RENEWAL,
    "lease_renewed": TRUSTED_RENEWAL,
    "TRUSTED_RENEWAL": TRUSTED_RENEWAL,
}

TEST_IDS = {
    LEASE_LEAKED: "B901",
    CLEANUP_NOT_GUARANTEED: "B902",
    NEEDS_MANUAL_REVIEW: "B903",
    TRUSTED_RENEWAL: "B904",
}

VERDICT_LABELS_ZH = {
    LEASE_LEAKED: "泄出租约",
    CLEANUP_NOT_GUARANTEED: "清理未保证",
    NEEDS_MANUAL_REVIEW: "需要人工看",
    TRUSTED_RENEWAL: "受信续期",
}

_CONFIG_KEYS = {
    "acquisition_functions": (
        "acquisition_functions",
        "lease_acquisition_functions",
        "acquisition",
        "lease_acquisition",
        "lease_acquire",
        "acquire_functions",
        "acquire",
    ),
    "managed_borrow_functions": (
        "managed_borrow_functions",
        "managed_borrow",
        "managed_borrowing",
        "lease_borrow",
        "borrow_functions",
        "borrow",
        "borrowing",
        "context_managers",
    ),
        "handoff_functions": (
            "handoff_functions",
            "handoff",
            "handoffs",
            "lease_handoff",
            "transfer_functions",
            "transfer",
            "lease_transfer",
            "transfers",
            "relay_functions",
            "forward_functions",
        ),
    "deregistration_functions": (
        "deregistration_functions",
        "deregister_functions",
        "deregistration",
        "lease_deregistration",
        "lease_deregistration_functions",
        "deregister",
        "unregister",
        "unregister_functions",
        "release_lease",
        "release_functions",
        "release",
        "lease_release",
        "cleanup_functions",
        "cleanup",
        "lease_cleanup",
        "revoke_functions",
        "logout_functions",
    ),
    "renewal_functions": (
        "renewal_functions",
        "trusted_renewal_functions",
        "renew_functions",
        "renewal",
        "lease_renewal",
        "trusted_renewal",
        "trusted_renewal_api",
        "trusted_renewal_apis",
        "heartbeat_functions",
            "keepalive_functions",
            "extend_validity_functions",
        ),
    "sink_functions": (
        "sink_functions",
        "long_lived_sink_functions",
        "long_lived_sinks",
        "sinks",
        "sink",
        "queue_functions",
        "queue_sinks",
    ),
    "queue_names": (
        "queue_names",
        "long_lived_queues",
        "long_lived_queue",
        "queues",
        "queue_objects",
    ),
}

_DEFAULT_CLEANUP_NAMES = {
    "release",
    "release_lease",
    "close",
    "aclose",
    "deregister",
    "deregister_client",
    "revoke",
    "revoke_lease",
    "logout",
    "shutdown",
}
_DEFAULT_RENEWAL_NAMES = {
    "renew",
    "renew_lease",
    "extend",
    "extend_lease",
    "heartbeat",
    "touch",
}
_DEFAULT_SINK_METHODS = {
    "put",
    "put_nowait",
    "enqueue",
    "enqueue_nowait",
    "append",
    "appendleft",
    "add",
    "submit",
    "publish",
}
_QUEUE_NAME_HINTS = (
    "queue",
    "long_lived",
    "deque",
    "buffer",
    "cache",
)
_DEFERRED_CALL_NAMES = {
    "create_task",
    "ensure_future",
    "call_soon",
    "call_soon_threadsafe",
    "call_later",
    "run_in_executor",
}


def gen_config(_name: str | None = None) -> dict[str, Any]:
    """Return the explicit, opt-in project configuration schema."""
    return {
        "acquisition_functions": [],
        "managed_borrow_functions": [],
        "handoff_functions": [],
        "deregistration_functions": [],
        "renewal_functions": [],
        "sink_functions": [],
        "queue_names": [],
        "generic_method_heuristics": True,
        "report_trusted_renewal": True,
    }


def normalize_verdict(value: str | None) -> str | None:
    if value is None:
        return None
    return VERDICT_ALIASES.get(value, VERDICT_ALIASES.get(str(value).lower()))


def _as_name_set(value: Any) -> set[str]:
    if value is None:
        return set()
    if isinstance(value, str):
        return {item.strip() for item in value.split(",") if item.strip()}
    if isinstance(value, dict):
        result = set()
        for key, item in value.items():
            result.add(str(key))
            result.update(_as_name_set(item))
        return result
    if isinstance(value, (list, tuple, set, frozenset)):
        result = set()
        for item in value:
            result.update(_as_name_set(item))
        return result
    return {str(value)}


def normalize_config(config: Any | None = None) -> dict[str, Any]:
    """Normalize standalone, Bandit, and plugin-section config shapes."""
    if config is None:
        raw: dict[str, Any] = {}
    elif hasattr(config, "get_option"):
        raw = config.get_option("lease_lifecycle") or {}
    elif hasattr(config, "config") and isinstance(config.config, dict):
        raw = config.config
    elif isinstance(config, dict):
        raw = config
    else:
        raw = {}

    if isinstance(raw.get("lease_lifecycle"), dict):
        raw = raw["lease_lifecycle"]
    elif isinstance(raw.get("lease_guard"), dict):
        raw = raw["lease_guard"]
    elif isinstance(raw.get("lease"), dict) and any(
        key in raw["lease"]
        for aliases in _CONFIG_KEYS.values()
        for key in aliases
    ):
        raw = raw["lease"]

    flat: dict[str, Any] = {}

    def _flatten(values: Any) -> None:
        if not isinstance(values, dict):
            return
        for key, value in values.items():
            flat.setdefault(str(key), value)
            if isinstance(value, dict):
                _flatten(value)

    _flatten(raw)
    normalized = gen_config()
    for canonical, aliases in _CONFIG_KEYS.items():
        values: set[str] = set()
        for key in aliases:
            if key in flat:
                values.update(_as_name_set(flat[key]))
        normalized[canonical] = values

    normalized["generic_method_heuristics"] = flat.get(
        "generic_method_heuristics", True
    )
    normalized["report_trusted_renewal"] = flat.get(
        "report_trusted_renewal", True
    )
    return normalized


def _matches_configured(
    name: str | None,
    patterns: set[str],
    generic_names: set[str] | None = None,
) -> bool:
    if not name:
        return False
    short = name.rsplit(".", 1)[-1]
    for pattern in patterns:
        pattern = str(pattern)
        if any(token in pattern for token in "*?["):
            if fnmatch.fnmatch(name, pattern) or fnmatch.fnmatch(
                short, pattern
            ):
                return True
        elif "." in pattern:
            if name == pattern or name.endswith("." + pattern):
                return True
            if short == pattern.rsplit(".", 1)[-1]:
                return True
        elif (
            short == pattern
            or name == pattern
            or name.startswith(pattern + ".")
        ):
            return True
    return bool(generic_names and short in generic_names)


@dataclass
class LeaseFinding:
    verdict: str
    message: str
    line: int
    col: int
    node_type: str
    variable: str | None = None
    reason: str | None = None
    severity: str = "MEDIUM"
    confidence: str = "MEDIUM"
    rule_id: str = ""
    details: dict[str, Any] = field(default_factory=dict)
    end_line: int | None = None
    end_col: int | None = None
    node: ast.AST | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        self.rule_id = self.rule_id or TEST_IDS[self.verdict]
        self.details.setdefault("verdict", self.verdict)
        self.details.setdefault("rule_id", self.rule_id)
        self.details.setdefault(
            "label_zh", VERDICT_LABELS_ZH.get(self.verdict)
        )
        if self.reason:
            self.details.setdefault("reason", self.reason)

    @property
    def category(self) -> str:
        return self.verdict

    @property
    def outcome(self) -> str:
        return self.verdict

    @property
    def status(self) -> str:
        return self.verdict

    @property
    def decision(self) -> str:
        return self.verdict

    @property
    def label_zh(self) -> str | None:
        return VERDICT_LABELS_ZH.get(self.verdict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "lease_verdict": self.verdict,
            "rule_id": self.rule_id,
            "test_id": self.rule_id,
            "message": self.message,
            "line": self.line,
            "col_offset": self.col,
            "end_line": self.end_line,
            "end_col_offset": self.end_col,
            "node_type": self.node_type,
            "variable": self.variable,
            "reason": self.reason,
            "severity": self.severity,
            "confidence": self.confidence,
            "details": self.details,
        }


class LeaseReport:
    """Findings from one analyzed source file."""

    def __init__(
        self,
        source: str = "",
        filename: str = "<string>",
        config: dict[str, Any] | None = None,
    ) -> None:
        self.source = source
        self.filename = filename
        self.config = config or {}
        self.findings: list[LeaseFinding] = []
        self._anchors: dict[tuple[str, int, int], LeaseFinding] = {}

    @property
    def issues(self) -> list[LeaseFinding]:
        return self.findings

    @property
    def results(self) -> list[LeaseFinding]:
        return self.findings

    @property
    def records(self) -> list[LeaseFinding]:
        return self.findings

    @property
    def verdicts(self) -> list[str]:
        return [finding.verdict for finding in self.findings]

    def __len__(self) -> int:
        return len(self.findings)

    def __iter__(self):
        return iter(self.findings)

    @property
    def verdict_counts(self) -> dict[str, int]:
        return self.counts()

    def by_verdict(self, verdict: str) -> list[LeaseFinding]:
        normalized = normalize_verdict(verdict) or verdict
        return [f for f in self.findings if f.verdict == normalized]

    def get(self, verdict: str) -> list[LeaseFinding]:
        return self.by_verdict(verdict)

    def has_verdict(self, verdict: str) -> bool:
        return bool(self.by_verdict(verdict))

    @property
    def leaked(self) -> list[LeaseFinding]:
        return self.by_verdict(LEASE_LEAKED)

    @property
    def cleanup_issues(self) -> list[LeaseFinding]:
        return self.by_verdict(CLEANUP_NOT_GUARANTEED)

    @property
    def review_items(self) -> list[LeaseFinding]:
        return self.by_verdict(NEEDS_MANUAL_REVIEW)

    @property
    def renewals(self) -> list[LeaseFinding]:
        return self.by_verdict(TRUSTED_RENEWAL)

    def add(
        self,
        verdict: str,
        node: ast.AST,
        message: str,
        *,
        reason: str | None = None,
        variable: str | None = None,
        severity: str | None = None,
        confidence: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> LeaseFinding:
        verdict = normalize_verdict(verdict) or verdict
        line = getattr(node, "lineno", 0)
        col = getattr(node, "col_offset", 0)
        key = (verdict, line, col)
        existing = self._anchors.get(key)
        if existing is not None:
            reasons = existing.details.setdefault("reasons", [])
            if reason and reason not in reasons:
                reasons.append(reason)
            variables = existing.details.setdefault("variables", [])
            if variable and variable not in variables:
                variables.append(variable)
            if details:
                existing.details.update(details)
            return existing

        finding = LeaseFinding(
            verdict=verdict,
            message=message,
            line=line,
            col=col,
            end_line=getattr(node, "end_lineno", None),
            end_col=getattr(node, "end_col_offset", None),
            node_type=type(node).__name__,
            node=node,
            variable=variable,
            reason=reason,
            severity=severity or bandit.MEDIUM,
            confidence=confidence or bandit.MEDIUM,
            details=details or {},
        )
        if reason:
            finding.details.setdefault("reasons", [reason])
        if variable:
            finding.details.setdefault("variables", [variable])
        self.findings.append(finding)
        self._anchors[key] = finding
        return finding

    def counts(self) -> dict[str, int]:
        return {
            LEASE_LEAKED: len(self.leaked),
            CLEANUP_NOT_GUARANTEED: len(self.cleanup_issues),
            NEEDS_MANUAL_REVIEW: len(self.review_items),
            TRUSTED_RENEWAL: len(self.renewals),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "filename": self.filename,
            "counts": self.counts(),
            "findings": [finding.as_dict() for finding in self.findings],
        }

    def render_text(self) -> str:
        lines = [f"Lease lifecycle report: {self.filename}"]
        for finding in self.findings:
            lines.append(
                f"{finding.line}:{finding.col} {finding.rule_id} "
                f"[{finding.verdict}] {finding.message}"
            )
        if not self.findings:
            lines.append("No lease lifecycle findings.")
        return "\n".join(lines)


@dataclass(eq=False)
class _Resource:
    name: str
    kind: str
    acquire_node: ast.AST
    acquire_call: ast.Call | None = None
    managed_with: ast.With | ast.AsyncWith | None = None
    aliases: set[str] = field(default_factory=set)
    cleanup_calls: list[ast.Call] = field(default_factory=list)
    renewal_calls: list[ast.Call] = field(default_factory=list)
    transferred: bool = False
    escaped: bool = False


def _attach_parents(tree: ast.AST) -> None:
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child._lease_parent = parent  # type: ignore[attr-defined]


def _parent_chain(node: ast.AST) -> list[ast.AST]:
    chain: list[ast.AST] = []
    current = node
    while hasattr(current, "_lease_parent"):
        parent = current._lease_parent  # type: ignore[attr-defined]
        chain.append(parent)
        current = parent
    return chain


def _build_import_aliases(tree: ast.AST) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                local = alias.asname or alias.name.split(".", 1)[0]
                aliases[local] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                local = alias.asname or alias.name
                aliases[local] = f"{node.module}.{alias.name}"
    return aliases


def _unwrap_await(node: ast.AST | None) -> ast.AST | None:
    while isinstance(node, ast.Await):
        node = node.value
    return node


def _target_names(target: ast.AST) -> list[str]:
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, ast.Starred):
        return _target_names(target.value)
    if isinstance(target, (ast.Tuple, ast.List)):
        names: list[str] = []
        for element in target.elts:
            names.extend(_target_names(element))
        return names
    return []


class _ScopeAnalyzer:
    def __init__(
        self,
        scope: ast.AST,
        tree: ast.Module,
        aliases: dict[str, str],
        config: dict[str, Any],
        report: LeaseReport,
    ) -> None:
        self.scope = scope
        self.tree = tree
        self.aliases = aliases
        self.config = config
        self.report = report
        self.resources: dict[str, _Resource] = {}
        self._outer_nodes = list(self._iter_outer_nodes(scope))
        self.calls = [
            node for node in self._outer_nodes if isinstance(node, ast.Call)
        ]
        self.rethrow_nodes = [
            node
            for node in self._outer_nodes
            if isinstance(node, ast.Raise) and self._in_except_handler(node)
        ]

    def _iter_outer_nodes(self, node: ast.AST):
        for child in ast.iter_child_nodes(node):
            if isinstance(
                child,
                (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda),
            ):
                continue
            yield child
            yield from self._iter_outer_nodes(child)

    def run(self) -> None:
        self._discover_bindings()
        self._discover_aliases()
        self._analyze_calls()
        self._analyze_post_borrow_calls()
        self._analyze_closures()
        self._finalize_cleanup()

    def _call_name(self, call: ast.Call) -> str:
        try:
            return bandit_utils.get_call_name(call, self.aliases) or ""
        except Exception:
            return ""

    def _matches(self, name: str, category: str) -> bool:
        return _matches_configured(name, self.config.get(category, set()))

    def _discover_bindings(self) -> None:
        for node in self._outer_nodes:
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
                value = _unwrap_await(getattr(node, "value", None))
                if not isinstance(value, ast.Call):
                    continue
                name = self._call_name(value)
                if self._matches(name, "acquisition_functions"):
                    kind = "acquisition"
                elif self._matches(name, "managed_borrow_functions"):
                    kind = "managed"
                else:
                    continue
                targets = (
                    node.targets
                    if isinstance(node, ast.Assign)
                    else [node.target]
                )
                self._add_binding(targets, kind, value, None)

            if isinstance(node, (ast.With, ast.AsyncWith)):
                for item in node.items:
                    context_expr = _unwrap_await(item.context_expr)
                    if not isinstance(context_expr, ast.Call):
                        continue
                    name = self._call_name(context_expr)
                    if not (
                        self._matches(name, "managed_borrow_functions")
                        or self._matches(name, "acquisition_functions")
                    ):
                        continue
                    if item.optional_vars is None:
                        continue
                    self._add_binding(
                        [item.optional_vars], "managed", context_expr, node
                    )

    def _add_binding(
        self,
        targets: list[ast.AST],
        kind: str,
        call: ast.Call,
        with_node: ast.With | ast.AsyncWith | None,
    ) -> None:
        for target in targets:
            for name in _target_names(target):
                self.resources[name] = _Resource(
                    name=name,
                    kind=kind,
                    acquire_node=call,
                    acquire_call=call,
                    managed_with=with_node,
                )

    def _discover_aliases(self) -> None:
        for node in self._outer_nodes:
            if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                continue
            resource = self._resource_for_expr(
                _unwrap_await(getattr(node, "value", None))
            )
            if resource is None:
                continue
            targets = (
                node.targets if isinstance(node, ast.Assign) else [node.target]
            )
            for target in targets:
                for name in _target_names(target):
                    if name not in self.resources:
                        self.resources[name] = resource
                        resource.aliases.add(name)

    def _resource_for_expr(
        self, node: ast.AST | None
    ) -> _Resource | None:
        node = _unwrap_await(node)
        if isinstance(node, ast.Name):
            return self.resources.get(node.id)
        if isinstance(node, ast.Attribute):
            base = node.value
            while isinstance(base, ast.Attribute):
                base = base.value
            if isinstance(base, ast.Name):
                return self.resources.get(base.id)
        return None

    def _resources_in_call(self, call: ast.Call) -> set[_Resource]:
        found: set[_Resource] = set()
        for subnode in ast.walk(call):
            resource = self._resource_for_expr(subnode)
            if resource is not None:
                found.add(resource)
        return found

    def _is_cleanup_call(self, name: str) -> bool:
        if self._matches(name, "deregistration_functions"):
            return True
        return bool(
            self.config.get("generic_method_heuristics", True)
            and _matches_configured(name, set(), _DEFAULT_CLEANUP_NAMES)
        )

    def _is_renewal_call(self, name: str) -> bool:
        if self._matches(name, "renewal_functions"):
            return True
        return bool(
            self.config.get("generic_method_heuristics", True)
            and _matches_configured(name, set(), _DEFAULT_RENEWAL_NAMES)
        )

    def _looks_queue_like(self, call: ast.Call, name: str) -> bool:
        lowered = name.lower()
        if any(hint in lowered for hint in _QUEUE_NAME_HINTS):
            return True
        if _matches_configured(name, self.config.get("queue_names", set())):
            return True
        if isinstance(call.func, ast.Attribute) and isinstance(
            call.func.value, ast.Name
        ):
            receiver = call.func.value.id.lower()
            if _matches_configured(
                call.func.value.id,
                self.config.get("queue_names", set()),
            ):
                return True
            if any(hint in receiver for hint in _QUEUE_NAME_HINTS):
                return True
        for keyword in call.keywords:
            if keyword.arg in {"queue", "destination", "target", "sink"}:
                value = keyword.value
                if isinstance(value, ast.Constant) and isinstance(
                    value.value, str
                ):
                    if any(
                        hint in value.value.lower()
                        for hint in _QUEUE_NAME_HINTS
                    ):
                        return True
                if isinstance(value, ast.Name) and any(
                    hint in value.id.lower() for hint in _QUEUE_NAME_HINTS
                ):
                    return True
        return False

    def _flow_kind(self, call: ast.Call, name: str) -> str | None:
        if self._matches(name, "sink_functions"):
            return "sink"
        if self._matches(name, "handoff_functions"):
            return "sink" if self._looks_queue_like(call, name) else "handoff"

        short = name.rsplit(".", 1)[-1]
        if short in _DEFERRED_CALL_NAMES:
            return "deferred"
        if not self.config.get("generic_method_heuristics", True):
            return None
        if short in _DEFAULT_SINK_METHODS and self._looks_queue_like(
            call, name
        ):
            return "sink"
        if any(token in name.lower() for token in ("enqueue", "publish")):
            return "sink"
        return None

    def _analyze_calls(self) -> None:
        for call in self.calls:
            name = self._call_name(call)
            if self._matches(name, "renewal_functions") and self.config.get(
                "report_trusted_renewal", True
            ):
                resources = self._resources_in_call(call)
                variables = sorted(
                    {resource.name for resource in resources}
                )
                for resource in resources:
                    resource.renewal_calls.append(call)
                self.report.add(
                    TRUSTED_RENEWAL,
                    call,
                    "Trusted lease renewal API actively extends "
                    "validity; verdict=trusted_renewal.",
                    reason="trusted_renewal_api",
                    variable=",".join(variables) or None,
                    severity=bandit.LOW,
                    confidence=bandit.HIGH,
                    details={"callee": name, "variables": variables},
                )
                continue

            resources = self._resources_in_call(call)
            if not resources:
                continue
            variables = sorted({resource.name for resource in resources})

            if self._is_renewal_call(name):
                if self.config.get("report_trusted_renewal", True):
                    for resource in resources:
                        resource.renewal_calls.append(call)
                    self.report.add(
                        TRUSTED_RENEWAL,
                        call,
                        "Trusted lease renewal API actively extends "
                        "validity; verdict=trusted_renewal.",
                        reason="trusted_renewal_api",
                        variable=",".join(variables),
                        severity=bandit.LOW,
                        confidence=bandit.HIGH,
                        details={"callee": name, "variables": variables},
                    )
                continue

            if self._is_cleanup_call(name):
                for resource in resources:
                    resource.cleanup_calls.append(call)
                continue

            flow = self._flow_kind(call, name)
            if flow == "sink":
                for resource in resources:
                    resource.escaped = True
                self.report.add(
                    LEASE_LEAKED,
                    call,
                    "Leased elevated client can reach a long-lived sink; "
                    "verdict=leaked_lease.",
                    reason="long_lived_sink",
                    variable=",".join(variables),
                    severity=bandit.HIGH,
                    confidence=bandit.HIGH,
                    details={"callee": name, "variables": variables},
                )
            elif flow == "handoff":
                for resource in resources:
                    resource.transferred = True
                self.report.add(
                    NEEDS_MANUAL_REVIEW,
                    call,
                    "Configured lease handoff needs human verification of "
                    "recipient lifetime; verdict=needs_manual_review.",
                    reason="handoff_boundary",
                    variable=",".join(variables),
                    severity=bandit.MEDIUM,
                    confidence=bandit.MEDIUM,
                    details={"callee": name, "variables": variables},
                )
            elif flow == "deferred":
                self.report.add(
                    NEEDS_MANUAL_REVIEW,
                    call,
                    "Leased client is captured by deferred execution; "
                    "verdict=needs_manual_review.",
                    reason="deferred_execution",
                    variable=",".join(variables),
                    severity=bandit.MEDIUM,
                    confidence=bandit.MEDIUM,
                    details={"callee": name, "variables": variables},
                )

    def _analyze_post_borrow_calls(self) -> None:
        for resource in self.resources.values():
            boundary = None
            if resource.managed_with is not None:
                boundary = resource.managed_with.end_lineno
            elif resource.cleanup_calls:
                boundary = max(call.lineno for call in resource.cleanup_calls)
            if boundary is None:
                continue

            for call in self.calls:
                if call.lineno <= boundary:
                    continue
                if resource not in self._resources_in_call(call):
                    continue
                name = self._call_name(call)
                if self._is_cleanup_call(name) or self._is_renewal_call(name):
                    continue
                self.report.add(
                    LEASE_LEAKED,
                    call,
                    "Leased client is called after managed borrow or "
                    "deregistration ended; verdict=leaked_lease.",
                    reason="call_after_borrow",
                    variable=resource.name,
                    severity=bandit.HIGH,
                    confidence=bandit.HIGH,
                    details={"callee": name, "boundary_line": boundary},
                )

    def _local_names(self, node: ast.AST) -> set[str]:
        local: set[str] = set()
        arguments = getattr(node, "args", None)
        if arguments is not None:
            arg_list = (
                arguments.posonlyargs
                + arguments.args
                + arguments.kwonlyargs
                + [arguments.vararg, arguments.kwarg]
            )
            for arg in arg_list:
                if arg is not None:
                    local.add(arg.arg)
        for subnode in ast.walk(node):
            if isinstance(subnode, ast.Name) and isinstance(
                subnode.ctx, ast.Store
            ):
                local.add(subnode.id)
            if isinstance(
                subnode,
                (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef),
            ) and subnode is not node:
                local.add(subnode.name)
        return local

    def _analyze_closures(self) -> None:
        for node in ast.walk(self.scope):
            if not isinstance(
                node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
            ):
                continue
            if node is self.scope:
                continue

            local_names = self._local_names(node)
            captured: dict[str, _Resource] = {}
            for subnode in ast.walk(node):
                if not isinstance(subnode, ast.Name):
                    continue
                if (
                    isinstance(subnode.ctx, ast.Load)
                    and subnode.id in self.resources
                    and subnode.id not in local_names
                ):
                    captured[subnode.id] = self.resources[subnode.id]
            if not captured:
                continue

            closure_name = getattr(node, "name", None)
            direct_flow = self._direct_closure_flow(node)
            named_escape = self._named_closure_escape(closure_name)
            invocations = self._closure_invocations(node, closure_name)
            after_invocations = [
                invocation
                for invocation in invocations
                if any(
                    self._is_after_borrow(invocation, resource)
                    for resource in captured.values()
                )
            ]
            variables = sorted(captured)
            rethrow_info = {
                "exception_rethrow": bool(self.rethrow_nodes),
                "rethrow_lines": [node.lineno for node in self.rethrow_nodes],
            }

            if direct_flow == "sink" or named_escape == "sink":
                for resource in captured.values():
                    resource.escaped = True
                finding = self.report.add(
                    LEASE_LEAKED,
                    self._flow_anchor(node),
                    "Closure capturing a leased client reaches a long-lived "
                    "sink; verdict=leaked_lease.",
                    reason="closure_escape_to_sink",
                    variable=",".join(variables),
                    severity=bandit.HIGH,
                    confidence=bandit.HIGH,
                    details={
                        "closure": closure_name or "<lambda>",
                        **rethrow_info,
                    },
                )
                finding.reason = "closure_escape_to_sink"
                finding.details["reason"] = finding.reason
                continue

            if after_invocations:
                invocation = after_invocations[0]
                self.report.add(
                    LEASE_LEAKED,
                    invocation,
                    "Capturing closure is invoked after the borrow ended; "
                    "verdict=leaked_lease.",
                    reason="closure_invoked_after_borrow",
                    variable=",".join(variables),
                    severity=bandit.HIGH,
                    confidence=bandit.HIGH,
                    details={
                        "closure": closure_name or "<lambda>",
                        **rethrow_info,
                    },
                )
                continue

            if direct_flow in {"handoff", "deferred", "unknown"} or (
                named_escape in {"handoff", "deferred", "unknown"}
            ):
                self.report.add(
                    NEEDS_MANUAL_REVIEW,
                    self._flow_anchor(node),
                    "Closure captures a leased client and may outlive the "
                    "borrow; verdict=needs_manual_review.",
                    reason="closure_escape_unknown_lifetime",
                    variable=",".join(variables),
                    severity=bandit.MEDIUM,
                    confidence=bandit.MEDIUM,
                    details={
                        "closure": closure_name or "<lambda>",
                        "flow": direct_flow or named_escape,
                        **rethrow_info,
                    },
                )
                continue

            if not invocations:
                self.report.add(
                    NEEDS_MANUAL_REVIEW,
                    node,
                    "Closure captures a leased client but is never invoked "
                    "or passed to a sink; verdict=needs_manual_review.",
                    reason="uncalled_closure_capture",
                    variable=",".join(variables),
                    severity=bandit.MEDIUM,
                    confidence=bandit.MEDIUM,
                    details={
                        "closure": closure_name or "<lambda>",
                        "invocation_count": 0,
                        "rethrow_before_invocation": (
                            self._rethrow_before_use(node)
                        ),
                        **rethrow_info,
                    },
                )

    def _flow_anchor(self, closure_node: ast.AST) -> ast.AST:
        for parent in _parent_chain(closure_node):
            if isinstance(parent, ast.Call):
                return parent
        return closure_node

    def _direct_closure_flow(self, node: ast.AST) -> str | None:
        for parent in _parent_chain(node):
            if isinstance(parent, ast.Call):
                name = self._call_name(parent)
                flow = self._flow_kind(parent, name)
                if flow is not None:
                    return flow
                return "unknown"
            if isinstance(parent, ast.Return):
                return "unknown"
        return None

    def _closure_invocations(
        self, node: ast.AST, closure_name: str | None
    ) -> list[ast.Call]:
        invocations: list[ast.Call] = []
        if isinstance(node, ast.Lambda):
            parent = getattr(node, "_lease_parent", None)
            if isinstance(parent, ast.Call) and parent.func is node:
                invocations.append(parent)
        if not closure_name:
            return invocations
        for candidate in ast.walk(self.tree):
            if (
                isinstance(candidate, ast.Call)
                and isinstance(candidate.func, ast.Name)
                and candidate.func.id == closure_name
            ):
                invocations.append(candidate)
        return invocations

    def _named_closure_escape(
        self, closure_name: str | None
    ) -> str | None:
        if not closure_name:
            return None
        for name_node in ast.walk(self.tree):
            if not isinstance(name_node, ast.Name):
                continue
            if name_node.id != closure_name or not isinstance(
                name_node.ctx, ast.Load
            ):
                continue
            parent = getattr(name_node, "_lease_parent", None)
            if isinstance(parent, ast.Call) and parent.func is name_node:
                continue

            call_parent = None
            for ancestor in _parent_chain(name_node):
                if isinstance(ancestor, ast.Call):
                    call_parent = ancestor
                    break
                if isinstance(
                    ancestor, (ast.FunctionDef, ast.AsyncFunctionDef)
                ):
                    break
            if call_parent is not None:
                flow = self._flow_kind(
                    call_parent, self._call_name(call_parent)
                )
                return flow or "unknown"
            if isinstance(parent, ast.Return):
                return "unknown"
            if isinstance(parent, (ast.Subscript, ast.Attribute)):
                return "unknown"
        return None

    def _is_after_borrow(
        self, invocation: ast.Call, resource: _Resource
    ) -> bool:
        boundary = None
        if resource.managed_with is not None:
            boundary = resource.managed_with.end_lineno
        elif resource.cleanup_calls:
            boundary = max(call.lineno for call in resource.cleanup_calls)
        return boundary is not None and invocation.lineno > boundary

    def _in_except_handler(self, node: ast.AST) -> bool:
        return any(
            isinstance(parent, ast.ExceptHandler)
            for parent in _parent_chain(node)
        )

    def _rethrow_before_use(self, closure_node: ast.AST) -> bool:
        closure_line = getattr(closure_node, "lineno", 0)
        return any(
            raise_node.lineno >= closure_line
            for raise_node in self.rethrow_nodes
        )

    def _cleanup_unconditionally_in_finally(
        self, cleanup_call: ast.Call, try_node: ast.Try
    ) -> bool:
        node: ast.AST = cleanup_call
        for parent in _parent_chain(cleanup_call):
            if parent is try_node:
                return any(
                    node is statement for statement in try_node.finalbody
                ) and not self._inside_conditional_guard(
                    cleanup_call, try_node
                )
            node = parent
            if isinstance(
                parent, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
            ):
                break
        return False

    def _inside_conditional_guard(
        self, call: ast.Call, try_node: ast.Try
    ) -> bool:
        node: ast.AST = call
        for parent in _parent_chain(call):
            if parent is try_node:
                return False
            if isinstance(
                parent, (ast.If, ast.For, ast.AsyncFor, ast.While)
            ):
                return True
            if isinstance(parent, ast.ExceptHandler):
                return True
            node = parent
        return True

    def _cleanup_guaranteed(self, resource: _Resource) -> bool:
        for cleanup_call in resource.cleanup_calls:
            node: ast.AST = cleanup_call
            for parent in _parent_chain(cleanup_call):
                if isinstance(parent, ast.Try):
                    if self._cleanup_unconditionally_in_finally(
                        cleanup_call, parent
                    ):
                        return True
                if isinstance(
                    parent,
                    (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef),
                ):
                    break
                node = parent
        return False

    def _finalize_cleanup(self) -> None:
        for resource in self.resources.values():
            if resource.managed_with is not None:
                continue
            anchor = resource.acquire_call or resource.acquire_node
            if resource.cleanup_calls:
                if self._cleanup_guaranteed(resource):
                    continue
                confidence = bandit.MEDIUM
                reason = "cleanup_not_in_finally"
                if self.rethrow_nodes:
                    reason = "exception_rethrow_can_bypass_cleanup"
                    confidence = bandit.HIGH
                self.report.add(
                    CLEANUP_NOT_GUARANTEED,
                    anchor,
                    "Lease deregistration exists but is not guaranteed on "
                    "all exception/rethrow paths; "
                    "verdict=cleanup_not_guaranteed.",
                    reason=reason,
                    variable=resource.name,
                    severity=bandit.MEDIUM,
                    confidence=confidence,
                    details={
                        "cleanup_lines": [
                            call.lineno for call in resource.cleanup_calls
                        ],
                        "rethrow_lines": [
                            node.lineno for node in self.rethrow_nodes
                        ],
                    },
                )
            elif not resource.escaped and not resource.transferred:
                self.report.add(
                    LEASE_LEAKED,
                    anchor,
                    "Lease acquisition has no configured deregistration; "
                    "verdict=leaked_lease.",
                    reason="missing_deregistration",
                    variable=resource.name,
                    severity=bandit.HIGH,
                    confidence=bandit.HIGH,
                )


class LeaseLifecycleAnalyzer:
    """Analyze Python source for configured lease lifecycle flows."""

    def __init__(self, config: Any | None = None) -> None:
        self.config = normalize_config(config)

    def analyze(
        self, source: str | bytes, filename: str = "<string>"
    ) -> LeaseReport:
        if isinstance(source, bytes):
            source = source.decode("utf-8")
        tree = ast.parse(source, filename=filename)
        _attach_parents(tree)
        aliases = _build_import_aliases(tree)
        report = LeaseReport(source, filename, self.config)

        scopes: list[ast.AST] = [tree]
        scopes.extend(
            node
            for node in ast.walk(tree)
            if isinstance(
                node,
                (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef),
            )
        )
        for scope in scopes:
            _ScopeAnalyzer(scope, tree, aliases, self.config, report).run()
        return report


def analyze_source(
    source: str | bytes,
    config: Any | None = None,
    filename: str = "<string>",
) -> LeaseReport:
    return LeaseLifecycleAnalyzer(config).analyze(source, filename)


analyze_lease_lifecycle = analyze_source
analyze_code = analyze_source


_REPORT_CACHE: dict[str, LeaseReport] = {}


def _config_fingerprint(config: Any) -> str:
    try:
        raw = getattr(config, "_config", config)
        return hashlib.sha256(repr(raw).encode("utf-8")).hexdigest()
    except Exception:
        return "default"


def _report_for_context(context: Any, config: Any) -> LeaseReport | None:
    filename = getattr(context, "filename", None) or "<string>"
    if not isinstance(filename, str):
        filename = "<string>"
    source: str | bytes | None = None
    file_data = getattr(context, "file_data", None)
    if file_data is not None and hasattr(file_data, "read"):
        try:
            if hasattr(file_data, "seek"):
                file_data.seek(0)
            source = file_data.read()
            if hasattr(file_data, "seek"):
                file_data.seek(0)
        except Exception:
            source = None
        if not isinstance(source, (str, bytes)):
            source = None
    if source is None:
        context_dict = getattr(context, "_context", {}) or {}
        if isinstance(context_dict, dict):
            source = context_dict.get("source") or context_dict.get(
                "file_source"
            )
    if not isinstance(source, (str, bytes)):
        return None

    source_bytes = source if isinstance(source, bytes) else source.encode()
    key = "{}:{}:{}".format(
        filename,
        hashlib.sha256(source_bytes).hexdigest(),
        _config_fingerprint(config),
    )
    report = _REPORT_CACHE.get(key)
    if report is None:
        report = analyze_source(source, config, filename)
        if len(_REPORT_CACHE) >= 128:
            _REPORT_CACHE.pop(next(iter(_REPORT_CACHE)))
        _REPORT_CACHE[key] = report
    return report


class LeaseBanditIssue(bandit_issue.Issue):
    """Issue carrying the machine-readable lease verdict."""

    def __init__(self, finding: LeaseFinding) -> None:
        cwe = (
            bandit_issue.Cwe.IMPROPER_CHECK_OF_EXCEPT_COND
            if finding.verdict == CLEANUP_NOT_GUARANTEED
            else bandit_issue.Cwe.IMPROPER_ACCESS_CONTROL
        )
        super().__init__(
            severity=finding.severity,
            cwe=cwe,
            confidence=finding.confidence,
            text=finding.message,
            lineno=finding.line,
            col_offset=finding.col,
            test_id=finding.rule_id,
        )
        self.lease_verdict = finding.verdict
        self.verdict = finding.verdict
        self.rule_id = finding.rule_id
        self.label_zh = finding.label_zh
        self.lease_details = finding.details
        self.finding = finding

    def as_dict(self, with_code: bool = True, max_lines: int = 3):
        data = super().as_dict(
            with_code=with_code, max_lines=max_lines
        )
        data["lease_verdict"] = self.lease_verdict
        data["verdict"] = self.verdict
        data["rule_id"] = self.rule_id
        data["label_zh"] = self.label_zh
        data["lease_details"] = self.lease_details
        return data


def _issue_for_context(
    context: Any, config: Any, verdict: str
) -> LeaseBanditIssue | None:
    report = _report_for_context(context, config)
    if report is None or not hasattr(context, "node"):
        return None
    node = context.node
    for finding in report.by_verdict(verdict):
        if finding.line != getattr(node, "lineno", None):
            continue
        if finding.col != getattr(node, "col_offset", None):
            continue
        if finding.node_type != type(node).__name__:
            continue
        return LeaseBanditIssue(finding)
    return None


_CHECK_NODES = ("Call", "FunctionDef", "AsyncFunctionDef", "Lambda")


@test.takes_config("lease_lifecycle")
@test.test_id("B901")
@test.checks(*_CHECK_NODES)
def lease_leaked(context, config=None):
    """B901: Leased client or capturing closure leaked past its lifetime."""
    return _issue_for_context(context, config, LEASE_LEAKED)


@test.takes_config("lease_lifecycle")
@test.test_id("B902")
@test.checks(*_CHECK_NODES)
def lease_cleanup_not_guaranteed(context, config=None):
    """B902: Deregistration exists but an exception path can bypass it."""
    return _issue_for_context(
        context, config, CLEANUP_NOT_GUARANTEED
    )


@test.takes_config("lease_lifecycle")
@test.test_id("B903")
@test.checks(*_CHECK_NODES)
def lease_manual_review(context, config=None):
    """B903: Closure or handoff lifetime requires human review."""
    return _issue_for_context(context, config, NEEDS_MANUAL_REVIEW)


@test.takes_config("lease_lifecycle")
@test.test_id("B904")
@test.checks(*_CHECK_NODES)
def trusted_lease_renewal(context, config=None):
    """B904: Trusted API actively extends lease validity."""
    normalized = normalize_config(config)
    if not normalized.get("report_trusted_renewal", True):
        return None
    return _issue_for_context(context, normalized, TRUSTED_RENEWAL)


class Verdict:
    """Stable verdict names accepted by reports and tests."""

    LEAKED_LEASE = LEASE_LEAKED
    LEASE_LEAK = LEASE_LEAKED
    LEASE_LEAKED = LEASE_LEAKED
    CLEANUP_NOT_GUARANTEED = CLEANUP_NOT_GUARANTEED
    CLEANUP_UNVERIFIED = CLEANUP_NOT_GUARANTEED
    NEEDS_MANUAL_REVIEW = NEEDS_MANUAL_REVIEW
    MANUAL_REVIEW_REQUIRED = NEEDS_MANUAL_REVIEW
    REVIEW_REQUIRED = NEEDS_MANUAL_REVIEW
    TRUSTED_RENEWAL = TRUSTED_RENEWAL


LeaseLifecycleReport = LeaseReport
LeaseLifecycleFinding = LeaseFinding
LeaseGuardReport = LeaseReport
LeaseGuardAnalyzer = LeaseLifecycleAnalyzer
LeaseGuard = LeaseLifecycleAnalyzer
LeaseLifecycleCheck = LeaseLifecycleAnalyzer
LeaseChecker = LeaseLifecycleAnalyzer
check_lease_lifecycle = analyze_source
run_lease_lifecycle_check = analyze_source
run_analysis = analyze_source
