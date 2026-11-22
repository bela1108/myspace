from __future__ import print_function

import json
import os

from cpe.audit import (
    CONFIRMED_CLOSED,
    INSUFFICIENT_EVIDENCE,
    MATCH,
    NO_MATCH,
    STILL_AFFECTED,
    UNKNOWN,
    Advisory,
    InventoryScope,
    InventorySnapshot,
    ReplacementEvidence,
    audit_withdrawal,
    cpe_relation,
    evaluate_expression,
    parse_timestamp,
)
from cpe.audit.model import ComponentRecord


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DATA_DIR = os.path.join(ROOT, "examples", "withdrawal_audit", "data")


def _load(name):
    with open(os.path.join(DATA_DIR, name), encoding="utf-8") as handle:
        return json.load(handle)


def example_inputs():
    advisory = Advisory.from_dict(_load("advisory.json"))
    scope = InventoryScope.from_dict(_load("scope.json"))
    before = InventorySnapshot.from_dict(_load("inventory_before.json"))
    after = InventorySnapshot.from_dict(_load("inventory_after.json"))
    replacements = [
        ReplacementEvidence.from_dict(item)
        for item in _load("replacements.json")
    ]
    return advisory, scope, before, after, replacements


def example_report():
    return audit_withdrawal(*example_inputs())


def _advisory(selectors):
    return Advisory.from_dict({
        "advisory_id": "ADV-TEST",
        "published_at": "2026-10-01T00:00:00Z",
        "withdrawn_at": "2026-11-15T00:00:00Z",
        "expression": [{
            "operator": "OR",
            "children": [],
            "cpe_match": [
                {"vulnerable": True, "cpe23Uri": selector}
                for selector in selectors
            ],
        }],
    })


def _scope(asset_id, family, complete, covered_from, covered_to):
    return InventoryScope.from_dict({
        "scope_ref": "SCOPE-TEST",
        "approved_by": "test",
        "approved_at": "2026-11-18T00:00:00Z",
        "approved_asset_ids": [asset_id],
        "family_coverage": {
            family: {
                "complete": complete,
                "evidence_ref": "FAMILY-EVIDENCE",
                "asset_ids": [asset_id],
                "covered_from": covered_from,
                "covered_to": covered_to,
            },
        },
    })


def _snapshot(snapshot_id, observed_at, asset_id, family, cpe,
              manifest_complete=True):
    return InventorySnapshot.from_dict({
        "snapshot_id": snapshot_id,
        "observed_at": observed_at,
        "assets": [{
            "asset_id": asset_id,
            "family": family,
            "manifest_complete": manifest_complete,
            "evidence_ref": snapshot_id + "-EVIDENCE",
            "components": [{
                "slot": "os",
                "cpe": cpe,
                "evidence_ref": snapshot_id + "-PKG",
            }],
        }],
    })


def test_before_and_after_snapshots_yield_three_distinct_results():
    report = example_report().to_dict()

    assert [row["asset_id"] for row in
            report["results"][CONFIRMED_CLOSED]] == ["web-01"]
    assert [row["asset_id"] for row in
            report["results"][STILL_AFFECTED]] == ["db-01"]
    assert [row["asset_id"] for row in
            report["results"][INSUFFICIENT_EVIDENCE]] == ["edge-01"]

    reconciliation = {
        row["asset_id"]: (row["before_match"], row["after_match"],
                          row["result"])
        for row in report["snapshot_reconciliation"]
    }
    assert reconciliation["web-01"] == (MATCH, NO_MATCH, CONFIRMED_CLOSED)
    assert reconciliation["db-01"] == (MATCH, MATCH, STILL_AFFECTED)
    assert reconciliation["edge-01"] == (UNKNOWN, UNKNOWN,
                                         INSUFFICIENT_EVIDENCE)
    assert len({value[2] for value in reconciliation.values()}) == 3


def test_each_result_carries_basis_and_evidence_references():
    report = example_report().to_dict()

    for status in (CONFIRMED_CLOSED, STILL_AFFECTED, INSUFFICIENT_EVIDENCE):
        assert len(report["results"][status]) == 1
        result = report["results"][status][0]
        assert result["basis"]
        assert result["evidence_refs"]
        assert any("公告适用区间" in line for line in result["basis"])

    closed = report["results"][CONFIRMED_CLOSED][0]
    assert "EVID-CHG-2026-1116-0042" in closed["evidence_refs"]
    assert closed["replacement"]["valid"] is True

    missing = report["results"][INSUFFICIENT_EVIDENCE][0]
    assert missing["after"]["value"] == UNKNOWN
    assert any("未匹配不能推出" in line for line in missing["basis"])


def test_incomplete_family_coverage_prevents_exclusion():
    report = example_report().to_dict()

    assert report["provable_scope"]["excluded_families"] == []
    unresolved = report["provable_scope"]["unresolved_families"]
    assert [item["family"] for item in unresolved] == ["edge"]
    assert any("不能排除" in line or "未匹配不能推出排除" in line
               for line in unresolved[0]["basis"])
    assert report["provable_scope"]["complete"] is False


def test_complete_family_coverage_allows_exclusion():
    advisory = _advisory(["cpe:2.3:a:acme:widget:1.2:*:*:*:*:*:*:*"])
    scope = _scope("net-01", "net-appliance", True,
                   "2026-09-01T00:00:00Z", "2026-11-18T00:00:00Z")
    before = _snapshot("before", "2026-11-14T00:00:00Z", "net-01",
                       "net-appliance",
                       "cpe:2.3:o:acme:switchos:7.0:*:*:*:*:*:*:*")
    after = _snapshot("after", "2026-11-18T00:00:00Z", "net-01",
                      "net-appliance",
                      "cpe:2.3:o:acme:switchos:7.0:*:*:*:*:*:*:*")

    report = audit_withdrawal(advisory, scope, before, after, [])
    data = report.to_dict()

    assert [row["asset_id"] for row in
            data["results"][CONFIRMED_CLOSED]] == ["net-01"]
    assert [item["family"] for item in
            data["provable_scope"]["excluded_families"]] == ["net-appliance"]
    assert data["provable_scope"]["unresolved_families"] == []
    assert data["provable_scope"]["complete"] is True


def test_complete_flag_without_covering_interval_cannot_exclude():
    advisory = _advisory(["cpe:2.3:a:acme:widget:1.2:*:*:*:*:*:*:*"])
    scope = _scope("net-01", "net-appliance", True,
                   "2026-11-16T00:00:00Z", "2026-11-18T00:00:00Z")
    before = _snapshot("before", "2026-11-14T00:00:00Z", "net-01",
                       "net-appliance",
                       "cpe:2.3:o:acme:switchos:7.0:*:*:*:*:*:*:*")
    after = _snapshot("after", "2026-11-18T00:00:00Z", "net-01",
                      "net-appliance",
                      "cpe:2.3:o:acme:switchos:7.0:*:*:*:*:*:*:*")

    data = audit_withdrawal(advisory, scope, before, after, []).to_dict()

    assert data["provable_scope"]["excluded_families"] == []
    assert [row["asset_id"] for row in
            data["results"][INSUFFICIENT_EVIDENCE]] == ["net-01"]
    assert any("未覆盖公告适用区间" in line
               for line in data["provable_scope"]["unresolved_families"][0]["basis"])


def test_unverified_replacement_cannot_close_asset():
    advisory, scope, before, after, replacements = example_inputs()
    replacements[0].verified = False

    data = audit_withdrawal(
        advisory, scope, before, after, replacements).to_dict()

    assert data["results"][CONFIRMED_CLOSED] == []
    missing_ids = [row["asset_id"] for row in
                   data["results"][INSUFFICIENT_EVIDENCE]]
    assert "web-01" in missing_ids
    web = [row for row in data["results"][INSUFFICIENT_EVIDENCE]
           if row["asset_id"] == "web-01"][0]
    assert any("未经核实" in line for line in web["basis"])


def test_replacement_whose_new_cpe_still_matches_cannot_close_asset():
    advisory, scope, before, after, replacements = example_inputs()
    after.assets["web-01"].components = [
        ComponentRecord(slot="app",
                        cpe="cpe:2.3:a:acme:widget:1.3:*:*:*:*:*:*:*",
                        evidence_ref="PKG-WEB-FAKE")]
    replacements[0].new_cpe = "cpe:2.3:a:acme:widget:1.3:*:*:*:*:*:*:*"

    data = audit_withdrawal(
        advisory, scope, before, after, replacements).to_dict()

    assert [row["asset_id"] for row in
            data["results"][STILL_AFFECTED]] == ["web-01", "db-01"]
    web = [row for row in data["results"][STILL_AFFECTED]
           if row["asset_id"] == "web-01"][0]
    assert web["replacement"]["valid"] is False
    assert any("新组件不能证明与公告表达式不相交" in line
               for line in web["replacement"]["reasons"])


def test_replacement_effective_after_snapshot_cannot_close_asset():
    advisory, scope, before, after, replacements = example_inputs()
    replacements[0].effective_at = parse_timestamp("2026-11-19T00:00:00Z")

    data = audit_withdrawal(
        advisory, scope, before, after, replacements).to_dict()

    missing_ids = [row["asset_id"] for row in
                   data["results"][INSUFFICIENT_EVIDENCE]]
    assert "web-01" in missing_ids
    web = [row for row in data["results"][INSUFFICIENT_EVIDENCE]
           if row["asset_id"] == "web-01"][0]
    assert any("晚于撤回后快照观测时间" in line for line in web["basis"])


def test_missing_component_is_unknown_not_no_match():
    expression = _advisory([
        "cpe:2.3:a:acme:widget:1.2:*:*:*:*:*:*:*"]).expression
    components = [ComponentRecord(
        slot="os", cpe="cpe:2.3:o:acme:edgeos:4.0:*:*:*:*:*:*:*")]

    incomplete = evaluate_expression(expression, components, False)
    complete = evaluate_expression(expression, components, True)

    assert incomplete.value == UNKNOWN
    assert complete.value == NO_MATCH
    assert any("清单不完整" in line for line in incomplete.basis)


def test_disjoint_is_the_only_proof_of_no_match():
    selector = "cpe:2.3:a:acme:widget:1.2:*:*:*:*:*:*:*"

    assert cpe_relation(
        selector, "cpe:2.3:a:acme:widget:2.0:*:*:*:*:*:*:*")[0] == NO_MATCH
    assert cpe_relation(
        selector, "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*")[0] == UNKNOWN
    assert cpe_relation(
        selector, "cpe:2.3:a:acme:widget:1.2:*:*:*:*:*:*:*")[0] == MATCH


def test_unknown_propagates_through_logical_and():
    expression = [{
        "operator": "AND",
        "children": [],
        "cpe_match": [
            {"vulnerable": True,
             "cpe23Uri": "cpe:2.3:a:acme:widget:1.2:*:*:*:*:*:*:*"},
            {"vulnerable": True,
             "cpe23Uri": "cpe:2.3:a:acme:datastore:3.4:*:*:*:*:*:*:*"},
        ],
    }]
    components = [ComponentRecord(
        slot="app", cpe="cpe:2.3:a:acme:widget:1.2:*:*:*:*:*:*:*")]

    result = evaluate_expression(expression, components, False)

    assert result.value == UNKNOWN


def test_out_of_scope_asset_is_reported_without_being_judged():
    advisory, scope, before, after, replacements = example_inputs()
    after.assets["spare-01"] = _snapshot(
        "after", "2026-11-18T00:00:00Z", "spare-01", "spare",
        "cpe:2.3:a:acme:widget:1.2:*:*:*:*:*:*:*").assets["spare-01"]

    data = audit_withdrawal(
        advisory, scope, before, after, replacements).to_dict()

    assert data["provable_scope"]["out_of_scope_assets"] == ["spare-01"]
    judged_ids = {
        row["asset_id"]
        for status in (CONFIRMED_CLOSED, STILL_AFFECTED, INSUFFICIENT_EVIDENCE)
        for row in data["results"][status]
    }
    assert "spare-01" not in judged_ids


def test_malformed_component_is_unknown_not_absent():
    expression = _advisory([
        "cpe:2.3:a:acme:widget:1.2:*:*:*:*:*:*:*"]).expression
    components = [ComponentRecord(slot="app", cpe="not-a-cpe")]

    result = evaluate_expression(expression, components, True)

    assert result.value == UNKNOWN


def test_tri_state_agrees_with_cpe_language_when_evidence_is_complete():
    from cpe.cpelang2_3 import CPELanguage2_3
    from cpe.cpeset2_3 import CPESet2_3
    from cpe.cpe2_3_uri import CPE2_3_URI

    advisory, _, _, _, _ = example_inputs()
    language = CPELanguage2_3(json.dumps(advisory.expression), isJSON=True)

    vulnerable = CPESet2_3()
    vulnerable.append(CPE2_3_URI("cpe:/a:acme:widget:1.2"))
    assert language.language_match(vulnerable) is True

    fixed = CPESet2_3()
    fixed.append(CPE2_3_URI("cpe:/a:acme:widget:2.0"))
    assert language.language_match(fixed) is False


def test_committed_example_report_matches_current_engine():
    path = os.path.join(ROOT, "examples", "withdrawal_audit", "report.json")
    with open(path, encoding="utf-8") as handle:
        committed = json.load(handle)

    assert committed == example_report().to_dict()
