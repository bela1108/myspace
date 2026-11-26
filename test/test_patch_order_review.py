"""Tests for the offline patch-order review fixture and evaluator."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from patch_order_review.auditgen import render_pip_audit_result
from patch_order_review.model import FixtureError, build_route_states, load_fixture
from patch_order_review.reviewer import build_review, derive_paths, evaluate_route


@pytest.fixture(scope="module")
def fixture():
    return load_fixture()


@pytest.fixture(scope="module")
def review(fixture):
    return build_review(fixture, fixture.root / "audit")


def _route(review, route_id):
    return next(route for route in review["routes"] if route["id"] == route_id)


def test_fixture_has_four_packages_and_two_parallel_lines(fixture):
    assert [package.name for package in fixture.packages] == [
        "argonvale",
        "cinderloom",
        "basaltine",
        "driftpin",
    ]
    assert {package.line for package in fixture.packages} == {"line-7", "line-8"}
    assert len(fixture.routes) == 2


def test_min_delta_is_endpoint_clean_but_reopens_signed_risks(review):
    route = _route(review, "min_delta")
    assert route["endpoint_only_verdict"] == "pass"
    assert route["continuity_verdict"] == "fail"
    assert route["verdict"] == "reject"
    reopened = {item["id"] for item in route["locked_reopenings"]}
    assert reopened == {"PYSEC-2026-0003"}
    assert route["endpoint_gap"] == 6


def test_bridge_release_keeps_every_locked_risk_closed(review):
    route = _route(review, "bridge_release")
    assert route["endpoint_only_verdict"] == "pass"
    assert route["continuity_verdict"] == "pass"
    assert route["verdict"] == "accept"
    assert route["locked_reopenings"] == []
    assert route["constraint_violations"] == []
    assert route["unit_issues"] == []


def test_terminal_open_sets_are_identical(review):
    min_delta = _route(review, "min_delta")
    bridge_release = _route(review, "bridge_release")
    assert min_delta["terminal_lock"] != bridge_release["terminal_lock"]
    assert min_delta["states"][-1]["open_ids"] == ["PYSEC-2026-0006"]
    assert bridge_release["states"][-1]["open_ids"] == ["PYSEC-2026-0006"]


def test_other_signed_risks_never_reopen_and_remediation_target_closes(review):
    for route in review["routes"]:
        open_ids = set().union(*(set(state["open_ids"]) for state in route["states"]))
        assert not open_ids & {
            "PYSEC-2026-0001",
            "PYSEC-2026-0004",
            "PYSEC-2026-0005",
        }
        assert "PYSEC-2026-0002" in route["states"][0]["open_ids"]
        assert "PYSEC-2026-0002" not in route["states"][-1]["open_ids"]


def test_terminal_residual_evidence_is_retained(review):
    residual = review["evidence"]["terminal_residual"]
    assert {item["route"] for item in residual} == {"min_delta", "bridge_release"}
    for item in residual:
        assert item["id"] == "PYSEC-2026-0006"
        assert item["fixed"] == []
        assert item["accepted"] is True
        assert item["version"] == "3.3.0"


def test_transient_evidence_distinguishes_accepted_and_blocking(review):
    transient = review["evidence"]["transient_introduced"]
    by_route_and_id = {(item["route"], item["id"]): item for item in transient}

    accepted = by_route_and_id[("bridge_release", "PYSEC-2026-0008")]
    assert accepted["accepted"] is True
    assert accepted["consecutive_states"] <= 2

    unaccepted = by_route_and_id[("min_delta", "PYSEC-2026-0007")]
    assert unaccepted["accepted"] is False
    assert unaccepted["acceptance"] is None


def test_endpoint_only_comparison_is_explicitly_insufficient(review):
    comparison = review["endpoint_only_comparison"]
    assert comparison["is_sufficient"] is False
    assert comparison["identical_terminal_open_sets"] is True
    assert comparison["terminal_open_sets"] == {
        "min_delta": ["PYSEC-2026-0006"],
        "bridge_release": ["PYSEC-2026-0006"],
    }
    assert comparison["counterexample_route"] == "min_delta"
    assert comparison["counterexample_endpoint_only"] == "pass"
    assert comparison["counterexample_continuity"] == "fail"
    assert set(comparison["counterexample_reopened"]) == {"PYSEC-2026-0003"}


def test_derivation_pays_one_version_component_for_continuity(fixture):
    derivation = derive_paths(fixture)
    assert derivation["naive_min_continuity_safe"] is False
    assert derivation["naive_min_gap"] == 6
    assert derivation["safe_min_gap"] == 7
    assert derivation["safety_premium"] == 1
    assert derivation["safe_min_units"] == [
        "L7-A-150",
        "L7-A-160",
        "L8-B-220",
        "L8-D-330",
    ]


def test_every_committed_pip_audit_result_matches_the_fixture(fixture):
    audit_root = fixture.root / "audit"
    for route in fixture.routes:
        for state in build_route_states(fixture, route):
            path = audit_root / route.id / f"step_{state.index:02d}.json"
            expected = render_pip_audit_result(fixture, state.lock) + "\n"
            assert path.read_text(encoding="utf-8") == expected


def test_audit_json_uses_the_pip_audit_manifest_shape(fixture):
    path = fixture.root / "audit" / "min_delta" / "step_03.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    assert set(document) == {"dependencies", "fixes"}
    assert document["fixes"] == []
    by_name = {dependency["name"]: dependency for dependency in document["dependencies"]}
    assert by_name["cinderloom"]["version"] == "0.9.1"
    assert {vuln["id"] for vuln in by_name["cinderloom"]["vulns"]} == {
        "PYSEC-2026-0003",
    }
    assert {vuln["id"] for vuln in by_name["basaltine"]["vulns"]} == {
        "PYSEC-2026-0002",
        "PYSEC-2026-0007",
    }


def test_evaluate_route_detects_audit_lock_drift(fixture, tmp_path: Path):
    route = fixture.routes[0]
    audit_root = tmp_path / "audit"
    for state_route in fixture.routes:
        for state in build_route_states(fixture, state_route):
            path = audit_root / state_route.id / f"step_{state.index:02d}.json"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(render_pip_audit_result(fixture, state.lock), encoding="utf-8")
    drifted = audit_root / route.id / "step_01.json"
    document = json.loads(drifted.read_text(encoding="utf-8"))
    document["dependencies"][0]["version"] = "9.9.9"
    drifted.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(FixtureError, match="audit/lock drift"):
        evaluate_route(fixture, route, audit_root)
