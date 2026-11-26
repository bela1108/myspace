"""Evaluate candidate patch orders and render the patch-order review."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from math import prod
from pathlib import Path
from typing import Any

from .model import (
    Fixture,
    FixtureError,
    Route,
    RouteState,
    apply_unit,
    build_route_states,
    check_lock,
    check_unit,
    lock_gap,
    open_advisories,
    version_matches,
)


@dataclass(frozen=True)
class Finding:
    """A vulnerability finding parsed from a pip-audit JSON document."""

    id: str
    package: str
    version: str
    severity: str
    fixed: tuple[str, ...]
    summary: str


@dataclass(frozen=True)
class StateAudit:
    """A lock state paired with its pip-audit result and constraint checks."""

    index: int
    unit_id: str | None
    lines: tuple[str, ...]
    lock: dict[str, str]
    findings: tuple[Finding, ...]
    audit_file: str
    audit_sha256: str
    unit_issues: tuple[dict[str, Any], ...]
    constraint_violations: tuple[dict[str, Any], ...]


def _sha256(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def _max_consecutive(indices: list[int]) -> int:
    """Return the longest run of consecutive state indices."""

    if not indices:
        return 0
    best = current = 1
    for previous, current_index in zip(indices, indices[1:]):
        current = current + 1 if current_index == previous + 1 else 1
        best = max(best, current)
    return best


def _state_dict(state: RouteState) -> dict[str, Any]:
    return {
        "index": state.index,
        "unit": state.unit_id,
        "lock": dict(state.lock),
        "unit_issues": [
            {
                "unit": issue.unit_id,
                "package": issue.package,
                "required": issue.required,
                "actual": issue.actual,
            }
            for issue in state.unit_issues
        ],
        "constraint_violations": [
            {
                "constraint": violation.constraint_id,
                "package": violation.package,
                "required": violation.required,
                "actual": violation.actual,
                "reason": violation.reason,
            }
            for violation in state.constraint_violations
        ],
    }


def load_audit(path: Path) -> dict[str, Any]:
    """Load a pip-audit JSON document from disk."""

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise FixtureError(f"missing pip-audit result: {path}") from exc
    except json.JSONDecodeError as exc:
        raise FixtureError(f"invalid pip-audit JSON in {path}: {exc}") from exc
    if "dependencies" not in data:
        raise FixtureError(f"pip-audit result has no dependencies: {path}")
    return data


def findings_from_audit(
    fixture: Fixture, document: dict[str, Any], expected_lock: dict[str, str]
) -> tuple[Finding, ...]:
    """Parse findings and guard against drift between a lock and its audit result."""

    findings: list[Finding] = []
    seen_packages: set[str] = set()
    for dependency in document["dependencies"]:
        name = dependency["name"]
        if "skip_reason" in dependency:
            raise FixtureError(f"unexpected skipped dependency in fixture audit: {name}")
        version = dependency["version"]
        if name not in expected_lock:
            raise FixtureError(f"audit contains unknown package: {name}")
        if version != expected_lock[name]:
            raise FixtureError(
                f"audit/lock drift for {name}: audit has {version}, lock has {expected_lock[name]}"
            )
        seen_packages.add(name)
        for vulnerability in dependency.get("vulns", []):
            advisory = fixture.advisory(vulnerability["id"])
            findings.append(
                Finding(
                    id=advisory.id,
                    package=name,
                    version=version,
                    severity=advisory.severity,
                    fixed=tuple(vulnerability.get("fix_versions", [])),
                    summary=advisory.summary,
                )
            )
    missing = set(expected_lock) - seen_packages
    if missing:
        raise FixtureError(f"audit is missing fixture packages: {sorted(missing)}")
    return tuple(findings)


def judge_sequence(fixture: Fixture, open_sets: list[set[str]]) -> dict[str, Any]:
    """Judge a sequence of open-advisory sets against the signed dispositions."""

    baseline = open_sets[0]
    terminal_index = len(open_sets) - 1
    terminal = open_sets[terminal_index]
    locked = {item.id: item for item in fixture.locked_closed}
    transient_acceptances = {item.id: item for item in fixture.accepted_transient}
    residual_acceptances = {item.id: item for item in fixture.accepted_residual}
    remediation_ids = {item.id for item in fixture.remediation_targets}

    locked_reopenings: list[dict[str, Any]] = []
    transient: list[dict[str, Any]] = []
    residual: list[dict[str, Any]] = []
    intermediate_residual: list[dict[str, Any]] = []
    unaccepted_transient: list[dict[str, Any]] = []
    unaccepted_residual: list[dict[str, Any]] = []
    unclassified: list[dict[str, Any]] = []
    terminal_remediation_open: list[dict[str, Any]] = []

    all_ids = sorted(set().union(*open_sets))
    for advisory_id in all_ids:
        advisory = fixture.advisory(advisory_id)
        states = [index for index, open_ids in enumerate(open_sets) if advisory_id in open_ids]
        if advisory_id in locked:
            disposition = locked[advisory_id]
            entry = {
                "id": advisory_id,
                "package": advisory.package,
                "severity": advisory.severity,
                "states": states,
                "signed_by": disposition.signed_by,
                "signed_on": disposition.signed_on,
                "reopenable": disposition.reopenable,
                "note": disposition.note,
            }
            locked_reopenings.append(entry)
            continue

        if advisory_id in baseline and advisory_id not in terminal:
            if advisory_id not in remediation_ids:
                unclassified.append(
                    {"id": advisory_id, "package": advisory.package, "states": states}
                )
            continue

        if advisory_id in terminal:
            acceptance = residual_acceptances.get(advisory_id)
            expired = acceptance is not None and acceptance.expires < fixture.review_as_of
            entry = {
                "id": advisory_id,
                "package": advisory.package,
                "severity": advisory.severity,
                "states": states,
                "fixed": list(advisory.fixed),
                "accepted": acceptance is not None and not expired,
                "expired": expired,
                "acceptance": acceptance.__dict__ if acceptance is not None else None,
            }
            residual.append(entry)
            if acceptance is None or expired:
                unaccepted_residual.append(entry)
            if any(state_index != terminal_index for state_index in states):
                intermediate_residual.append(entry)
            continue

        if advisory_id in baseline:
            continue

        acceptance = transient_acceptances.get(advisory_id)
        consecutive = _max_consecutive(states)
        expired = acceptance is not None and acceptance.expires < fixture.review_as_of
        accepted = (
            acceptance is not None
            and not expired
            and consecutive <= acceptance.max_consecutive_states
        )
        entry = {
            "id": advisory_id,
            "package": advisory.package,
            "severity": advisory.severity,
            "kind": "transient_introduced",
            "states": states,
            "consecutive_states": consecutive,
            "accepted": accepted,
            "expired": expired,
            "acceptance": acceptance.__dict__ if acceptance is not None else None,
        }
        transient.append(entry)
        if not accepted:
            unaccepted_transient.append(entry)

    for target in fixture.remediation_targets:
        if target.id in terminal:
            terminal_remediation_open.append(
                {"id": target.id, "package": target.package, "required_at": target.required_at}
            )

    locked_open_terminal = sorted(
        item["id"] for item in locked_reopenings if terminal_index in item["states"]
    )
    continuity_safe = not (
        locked_reopenings
        or unaccepted_transient
        or unaccepted_residual
        or intermediate_residual
        or unclassified
        or terminal_remediation_open
    )
    endpoint_only_safe = not (
        terminal_remediation_open
        or unaccepted_residual
        or locked_open_terminal
        or unclassified
    )

    reasons: list[str] = []
    for item in locked_reopenings:
        reasons.append(
            f"{item['id']} reopens at states {item['states']} after a signed "
            f"({item['signed_by']}) non-reopenable disposition"
        )
    for item in unaccepted_transient:
        if item["expired"]:
            reasons.append(f"{item['id']} transient acceptance has expired")
        else:
            reasons.append(
                f"{item['id']} is exposed for {item['consecutive_states']} state(s) without an "
                "accepted transient disposition"
            )
    for item in unaccepted_residual:
        if item["expired"]:
            reasons.append(f"{item['id']} residual acceptance has expired")
        else:
            reasons.append(f"{item['id']} remains open at the terminal lock without acceptance")
    for item in intermediate_residual:
        reasons.append(f"{item['id']} is accepted only as a terminal residual but appears earlier")
    for item in terminal_remediation_open:
        reasons.append(f"remediation target {item['id']} is still open at the terminal lock")
    for item in unclassified:
        reasons.append(f"{item['id']} is open without a matching disposition")

    return {
        "locked_reopenings": locked_reopenings,
        "transient": transient,
        "residual": residual,
        "intermediate_residual": intermediate_residual,
        "unaccepted_transient": unaccepted_transient,
        "unaccepted_residual": unaccepted_residual,
        "unclassified": unclassified,
        "terminal_remediation_open": terminal_remediation_open,
        "locked_open_terminal": locked_open_terminal,
        "continuity_safe": continuity_safe,
        "endpoint_only_safe": endpoint_only_safe,
        "reasons": reasons,
    }


def _terminal_ready(fixture: Fixture, lock: dict[str, str]) -> bool:
    return all(
        version_matches(lock[name], specifier)
        for name, specifier in fixture.terminal_requirements.items()
    )


def evaluate_route(
    fixture: Fixture, route: Route, audit_root: Path
) -> dict[str, Any]:
    """Evaluate a route against its per-state pip-audit results."""

    states: list[StateAudit] = []
    for state in build_route_states(fixture, route):
        audit_path = audit_root / route.id / f"step_{state.index:02d}.json"
        document = load_audit(audit_path)
        findings = findings_from_audit(fixture, document, state.lock)
        raw = audit_path.read_text(encoding="utf-8")
        lines = () if state.unit_id is None else fixture.unit(state.unit_id).lines
        states.append(
            StateAudit(
                index=state.index,
                unit_id=state.unit_id,
                lines=lines,
                lock=dict(state.lock),
                findings=findings,
                audit_file=str(audit_path.relative_to(audit_root.parent)),
                audit_sha256=_sha256(raw),
                unit_issues=tuple(_state_dict(state)["unit_issues"]),
                constraint_violations=tuple(_state_dict(state)["constraint_violations"]),
            )
        )

    open_sets = [{finding.id for finding in state.findings} for state in states]
    judgement = judge_sequence(fixture, open_sets)
    for item in judgement["locked_reopenings"]:
        item["units"] = [
            states[state_index].unit_id for state_index in item["states"]
        ]
        item["versions"] = [
            states[state_index].lock[item["package"]] for state_index in item["states"]
        ]
    for item in judgement["transient"]:
        item["units"] = [states[state_index].unit_id for state_index in item["states"]]
        item["versions"] = [
            states[state_index].lock[item["package"]] for state_index in item["states"]
        ]
    for item in judgement["residual"]:
        item["version"] = states[-1].lock[item["package"]]

    state_dicts: list[dict[str, Any]] = []
    for state in states:
        open_ids = [finding.id for finding in state.findings]
        state_dicts.append(
            {
                "index": state.index,
                "unit": state.unit_id,
                "lines": list(state.lines),
                "lock": dict(state.lock),
                "open": [finding.__dict__ for finding in state.findings],
                "open_ids": open_ids,
                "locked_open": [
                    advisory_id
                    for advisory_id in open_ids
                    if any(item.id == advisory_id for item in fixture.locked_closed)
                ],
                "audit_file": state.audit_file,
                "audit_sha256": state.audit_sha256,
                "unit_issues": list(state.unit_issues),
                "constraint_violations": list(state.constraint_violations),
            }
        )

    terminal = states[-1]
    gap = lock_gap(fixture.baseline, terminal.lock)
    terminal_ready = _terminal_ready(fixture, terminal.lock)
    route_constraints = [
        violation for state in states for violation in state.constraint_violations
    ]
    route_unit_issues = [issue for state in states for issue in state.unit_issues]
    reasons = list(judgement["reasons"])
    if route_constraints:
        for violation in route_constraints:
            reasons.append(
                f"{violation['constraint']} fails: {violation['package']} "
                f"{violation['actual']} does not satisfy {violation['required']}"
            )
    if route_unit_issues:
        for issue in route_unit_issues:
            reasons.append(
                f"unit precondition fails: {issue['unit']} needs {issue['package']} "
                f"{issue['required']} but saw {issue['actual']}"
            )
    if not terminal_ready:
        reasons.append("terminal lock does not satisfy the declared terminal requirements")

    continuity_safe = (
        judgement["continuity_safe"]
        and terminal_ready
        and not route_constraints
        and not route_unit_issues
    )
    endpoint_only_safe = judgement["endpoint_only_safe"] and terminal_ready

    return {
        "id": route.id,
        "label": route.label,
        "lanes": list(route.lanes),
        "intent": route.intent,
        "units": list(route.units),
        "endpoint_gap": gap,
        "terminal_lock": dict(terminal.lock),
        "terminal_ready": terminal_ready,
        "states": state_dicts,
        "locked_reopenings": judgement["locked_reopenings"],
        "transient": judgement["transient"],
        "residual": judgement["residual"],
        "unaccepted_transient": judgement["unaccepted_transient"],
        "unaccepted_residual": judgement["unaccepted_residual"],
        "intermediate_residual": judgement["intermediate_residual"],
        "terminal_remediation_open": judgement["terminal_remediation_open"],
        "constraint_violations": route_constraints,
        "unit_issues": route_unit_issues,
        "endpoint_only_verdict": "pass" if endpoint_only_safe else "fail",
        "continuity_verdict": "pass" if continuity_safe else "fail",
        "verdict": "accept" if continuity_safe else "reject",
        "reasons": reasons,
    }


def _candidate_space(fixture: Fixture) -> dict[str, set[str]]:
    return {package.name: set(package.candidate_versions) for package in fixture.packages}


def derive_paths(fixture: Fixture) -> dict[str, Any]:
    """Derive the cheapest endpoint path and the cheapest risk-continuous path."""

    candidates = _candidate_space(fixture)
    unit_order = {unit.id: index for index, unit in enumerate(fixture.units)}
    results: list[dict[str, Any]] = []

    def visit(
        lock: dict[str, str],
        used: frozenset[str],
        ordered: tuple[str, ...],
        locks: tuple[dict[str, str], ...],
    ) -> None:
        if _terminal_ready(fixture, lock):
            open_sets = [
                {item.id for item in open_advisories(fixture, state)} for state in locks
            ]
            results.append(
                {
                    "units": list(ordered),
                    "terminal_lock": dict(lock),
                    "gap": lock_gap(fixture.baseline, lock),
                    "judgement": judge_sequence(fixture, open_sets),
                }
            )
            return
        for unit in fixture.units:
            if unit.id in used:
                continue
            if check_unit(unit, lock):
                continue
            new_lock = apply_unit(unit, lock)
            if any(new_lock[name] not in candidates[name] for name in new_lock):
                continue
            if check_lock(fixture, new_lock):
                continue
            visit(new_lock, used | {unit.id}, ordered + (unit.id,), locks + (new_lock,))

    visit(dict(fixture.baseline), frozenset(), (), (dict(fixture.baseline),))

    def sort_key(item: dict[str, Any]) -> tuple[int, int, list[int]]:
        return (
            item["gap"],
            len(item["units"]),
            [unit_order[unit_id] for unit_id in item["units"]],
        )

    results.sort(key=sort_key)
    safe = [item for item in results if item["judgement"]["continuity_safe"]]
    naive_best = results[0]
    safe_best = safe[0]
    naive_same_gap = [item for item in results if item["gap"] == naive_best["gap"]]
    safe_same_gap = [item for item in safe if item["gap"] == safe_best["gap"]]

    return {
        "terminal_path_count": len(results),
        "naive_min_gap": naive_best["gap"],
        "naive_min_units": naive_best["units"],
        "naive_min_terminal_lock": naive_best["terminal_lock"],
        "naive_min_continuity_safe": naive_best["judgement"]["continuity_safe"],
        "naive_min_reasons": naive_best["judgement"]["reasons"],
        "naive_paths_at_min_gap": len(naive_same_gap),
        "naive_paths_at_min_gap_safe": sum(
            1 for item in naive_same_gap if item["judgement"]["continuity_safe"]
        ),
        "safe_min_gap": safe_best["gap"],
        "safe_min_units": safe_best["units"],
        "safe_min_terminal_lock": safe_best["terminal_lock"],
        "safe_paths_at_min_gap": len(safe_same_gap),
        "safety_premium": safe_best["gap"] - naive_best["gap"],
    }


def _fixture_digest(fixture: Fixture) -> str:
    digest = hashlib.sha256()
    for path in sorted(fixture.root.rglob("*.json")):
        if "audit" in path.parts:
            continue
        digest.update(path.relative_to(fixture.root).as_posix().encode("utf-8"))
        digest.update(path.read_bytes())
    return digest.hexdigest()


def build_review(fixture: Fixture, audit_root: Path) -> dict[str, Any]:
    """Build the machine-readable review from fixture results and path derivation."""

    routes = [evaluate_route(fixture, route, audit_root) for route in fixture.routes]
    derivation = derive_paths(fixture)
    accepted = [route for route in routes if route["verdict"] == "accept"]
    rejected = [route for route in routes if route["verdict"] == "reject"]
    if not accepted:
        raise FixtureError("no candidate route keeps every locked risk closed")
    recommended = min(accepted, key=lambda route: (route["endpoint_gap"], len(route["units"])))
    counterexample = next(
        (
            route
            for route in rejected
            if route["endpoint_only_verdict"] == "pass"
        ),
        None,
    )

    transient_evidence = [
        {"route": route["id"], **item} for route in routes for item in route["transient"]
    ]
    locked_evidence = [
        {"route": route["id"], **item}
        for route in routes
        for item in route["locked_reopenings"]
    ]
    residual_evidence = [
        {"route": route["id"], **item} for route in routes for item in route["residual"]
    ]
    terminal_open_sets = {
        route["id"]: route["states"][-1]["open_ids"] for route in routes
    }
    identical_terminal_open_sets = len({tuple(item) for item in terminal_open_sets.values()}) == 1

    return {
        "schema": "patch-order-review/review/v1",
        "review_as_of": fixture.review_as_of,
        "fixture_digest": _fixture_digest(fixture),
        "policy": fixture.policy,
        "packages": [
            {
                "name": package.name,
                "line": package.line,
                "role": package.role,
                "candidate_versions": list(package.candidate_versions),
            }
            for package in fixture.packages
        ],
        "baseline": dict(fixture.baseline),
        "terminal_requirements": dict(fixture.terminal_requirements),
        "constraints": [
            {
                "id": constraint.id,
                "when": constraint.when,
                "require": constraint.require,
                "reason": constraint.reason,
            }
            for constraint in fixture.constraints
        ],
        "locked_closed": [item.__dict__ for item in fixture.locked_closed],
        "accepted_transient": [item.__dict__ for item in fixture.accepted_transient],
        "accepted_residual": [item.__dict__ for item in fixture.accepted_residual],
        "candidate_space": {
            "per_package": {
                package.name: len(package.candidate_versions) for package in fixture.packages
            },
            "combinations": prod(
                len(package.candidate_versions) for package in fixture.packages
            ),
            "terminal_paths": derivation["terminal_path_count"],
        },
        "routes": routes,
        "derivation": derivation,
        "evidence": {
            "locked_reopenings": locked_evidence,
            "transient_introduced": transient_evidence,
            "terminal_residual": residual_evidence,
        },
        "endpoint_only_comparison": {
            "is_sufficient": False,
            "terminal_open_sets": terminal_open_sets,
            "identical_terminal_open_sets": identical_terminal_open_sets,
            "counterexample_route": counterexample["id"] if counterexample else None,
            "counterexample_endpoint_only": counterexample["endpoint_only_verdict"]
            if counterexample
            else None,
            "counterexample_continuity": counterexample["continuity_verdict"]
            if counterexample
            else None,
            "counterexample_reopened": [
                item["id"] for item in counterexample["locked_reopenings"]
            ]
            if counterexample
            else [],
        },
        "recommendation": {
            "route": recommended["id"],
            "label": recommended["label"],
            "endpoint_gap": recommended["endpoint_gap"],
            "terminal_lock": recommended["terminal_lock"],
            "reason": (
                "Cheapest accepted ordering. It keeps every signed non-reopenable risk closed "
                "at every state and avoids the 2.0.1 metadata regression."
            ),
        },
    }


def _version_row(lock: dict[str, str], names: list[str]) -> str:
    return " | ".join(lock[name] for name in names)


def _ids(ids: list[str]) -> str:
    return ", ".join(ids) if ids else "—"


def _unit_label(fixture: Fixture, unit_id: str | None) -> str:
    if unit_id is None:
        return "baseline"
    unit = fixture.unit(unit_id)
    return f"`{unit.id}`"


def _lines_label(unit_id: str | None, lines: list[str]) -> str:
    if unit_id is None:
        return "line-7 + line-8"
    return " + ".join(lines)


def render_markdown(fixture: Fixture, review: dict[str, Any]) -> str:
    """Render the human-readable patch-order review in Chinese."""

    package_names = [package.name for package in fixture.packages]
    lines: list[str] = [
        "# 补丁顺序审查：RG-2031-07 双维护线重锁",
        "",
        f"- 审查日期：{review['review_as_of']}",
        f"- 夹具摘要：`{review['fixture_digest']}`",
        "- 审计来源：离线 pydef 夹具经 `pip_audit._format.json.JsonFormat` 生成的本地 pip-audit JSON",
        "- 路线：`min_delta`（最小端点版本差）与 `bridge_release`（桥接版本、持有已签 ABI 边界）",
        "",
        "## 结论",
        "",
        "| 路线 | 端点版本差 | 仅端点判决 | 逐步连续性判决 | 终态 |",
        "| --- | ---: | --- | --- | --- |",
    ]
    for route in review["routes"]:
        lines.append(
            f"| `{route['id']}` | {route['endpoint_gap']} | {route['endpoint_only_verdict']} "
            f"| {route['continuity_verdict']} | {route['verdict']} |"
        )
    recommendation = review["recommendation"]
    counterexample = review["endpoint_only_comparison"]
    lines.extend(
        [
            "",
            f"推荐 `{recommendation['route']}`：{recommendation['label']}。"
            f"它的端点版本差为 {recommendation['endpoint_gap']}，"
            "但每一个中间锁都保持已签风险关闭。",
            "",
            "不能只比较端点：两条路线的终态开放风险完全相同，但 "
            f"`{counterexample['counterexample_route']}` 在中途重开了 "
            f"{_ids(counterexample['counterexample_reopened'])}；"
            "仅端点比较会把它判为 pass。",
            "",
            "## 夹具：四个虚构分发包",
            "",
            "| 包 | 维护线 | 角色 | 候选版本 |",
            "| --- | --- | --- | --- |",
        ]
    )
    for package in review["packages"]:
        lines.append(
            f"| `{package['name']}` | {package['line']} | {package['role']} "
            f"| {', '.join(package['candidate_versions'])} |"
        )
    lines.extend(
        [
            "",
            "基线锁："
            + "，".join(f"`{name}=={review['baseline'][name]}`" for name in package_names),
            "",
            "终态要求："
            + "，".join(
                f"`{name}{specifier}`"
                for name, specifier in review["terminal_requirements"].items()
            ),
            "",
            "## 明示的兼容约束",
            "",
            "| 约束 | 触发条件 | 要求 | 原因 |",
            "| --- | --- | --- | --- |",
        ]
    )
    for constraint in review["constraints"]:
        when = ", ".join(
            f"`{name}{specifier}`" for name, specifier in constraint["when"].items()
        )
        require = ", ".join(
            f"`{name}{specifier}`" for name, specifier in constraint["require"].items()
        )
        lines.append(
            f"| `{constraint['id']}` | {when} | {require} | {constraint['reason']} |"
        )

    for route in review["routes"]:
        lines.extend(
            [
                "",
                f"## 逐状态审计：`{route['id']}`",
                "",
                route["intent"],
                "",
                "| 步 | 补丁单元 | 线路 | "
                + " | ".join(f"`{name}`" for name in package_names)
                + " | 开放风险 | 锁定风险重开 |",
                "| ---: | --- | --- | "
                + " | ".join("---" for _ in package_names)
                + " | --- | --- |",
            ]
        )
        for state in route["states"]:
            lines.append(
                f"| {state['index']} | {_unit_label(fixture, state['unit'])} "
                f"| {_lines_label(state['unit'], state['lines'])} "
                f"| {_version_row(state['lock'], package_names)} "
                f"| {_ids(state['open_ids'])} | {_ids(state['locked_open'])} |"
            )
        if route["reasons"]:
            lines.extend(["", "判决理由："])
            lines.extend(f"- {reason}" for reason in route["reasons"])

    lines.extend(
        [
            "",
            "## 证据 A：临时引入风险",
            "",
            "下表保留两类临时风险：未列入处置的临时引入风险，以及重开已签处置的阻断项。",
            "",
            "| 路线 | 状态 | 风险 | 类别 | 连续状态数 | 处置 |",
            "| --- | --- | --- | --- | ---: | --- |",
        ]
    )
    for item in review["evidence"]["locked_reopenings"]:
        lines.append(
            f"| `{item['route']}` | {item['states']} | `{item['id']}` "
            f"({item['package']}@{', '.join(item['versions'])}) | 重开已签处置（不可重开） | "
            f"{len(item['states'])} | 阻断：{item['signed_by']}，{item['signed_on']} |"
        )
    for item in review["evidence"]["transient_introduced"]:
        acceptance = item["acceptance"]
        if acceptance is None:
            disposition = "未接受，阻断"
        else:
            disposition = (
                f"已接受至 {acceptance['expires']}；{acceptance['mitigation']}"
            )
        lines.append(
            f"| `{item['route']}` | {item['states']} | `{item['id']}` "
            f"({item['package']}@{', '.join(item['versions'])}) | 临时引入 | "
            f"{item['consecutive_states']} | {disposition} |"
        )

    lines.extend(
        [
            "",
            "## 证据 B：终态仍留风险",
            "",
            "| 路线 | 风险 | 终态版本 | 可用修复版本 | 处置 |",
            "| --- | --- | --- | --- | --- |",
        ]
    )
    for item in review["evidence"]["terminal_residual"]:
        acceptance = item["acceptance"]
        if acceptance is None:
            disposition = "未接受，终态不合格"
        else:
            disposition = (
                f"已接受至 {acceptance['expires']}；owner={acceptance['owner']}；"
                f"{acceptance['mitigation']}"
            )
        fixed = ", ".join(item["fixed"]) if item["fixed"] else "无"
        lines.append(
            f"| `{item['route']}` | `{item['id']}` ({item['package']}) "
            f"| {item['version']} | {fixed} | {disposition} |"
        )

    derivation = review["derivation"]
    candidate_space = review["candidate_space"]
    candidate_counts = " × ".join(
        str(value) for value in candidate_space["per_package"].values()
    )
    lines.extend(
        [
            "",
            "## 推导：为什么必须多付一个版本差",
            "",
            f"- 候选锁空间为 {candidate_counts} "
            f"= {candidate_space['combinations']} 个版本组合；在补丁单元前置条件与兼容约束下，"
            f"共有 {candidate_space['terminal_paths']} 条可达终态的合法排序。",
            f"- 忽略中间状态的搜索里，最小端点版本差为 {derivation['naive_min_gap']}，"
            f"代表顺序为 {derivation['naive_min_units']}；"
            f"同差路线 {derivation['naive_paths_at_min_gap']} 条，其中 "
            f"{derivation['naive_paths_at_min_gap_safe']} 条连续安全。",
            f"- 最小端点差路线不是连续安全的：{'; '.join(derivation['naive_min_reasons'])}。",
            f"- 对锁定风险做连续约束后，最小安全端点版本差为 {derivation['safe_min_gap']}，"
            f"代表顺序为 {derivation['safe_min_units']}；"
            f"同差安全路线 {derivation['safe_paths_at_min_gap']} 条。",
            f"- 安全溢价 = {derivation['safety_premium']} 个版本分量。",
            "- 关键排序：`basaltine==2.0.1` 触发 `COMPAT-001`，迫使 `cinderloom` 从 "
            "1.0.1 降级到 0.9.1，重开 0003；`basaltine==2.2.0` 是打包了 2.0.1 "
            "迁移的桥接版本，绕过坏元数据，但要求 `argonvale>=1.5.0`（`COMPAT-005`），"
            "因此必须先执行 `argonvale` 的 1.5.0 顺序迁移，再上桥接版本。",
            "",
            "## 复现",
            "",
            "```bash",
            "python -m patch_order_review",
            "python -m patch_order_review verify",
            "python -m pytest test/test_patch_order_review.py",
            "```",
            "",
            "`python -m patch_order_review` 会重写 `patch_order_review/fixture/audit/` 下的"
            "逐状态 pip-audit JSON、`patch_order_review/reports/review.json` 与本报告。",
        ]
    )
    return "\n".join(lines) + "\n"
