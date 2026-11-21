# This file is part of CycloneDX Python Library
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) OWASP Foundation. All Rights Reserved.


from unittest import TestCase

from cyclonedx.impact import (
    ImpactPath,
    ImpactReport,
    UnresolvedEdge,
    analyze_impact,
)
from cyclonedx.impact.enums import ImpactEdgeStatus, ImpactPathStatus
from cyclonedx.model.bom import Bom
from cyclonedx.model.bom_ref import BomRef
from cyclonedx.model.component import Component, ComponentScope
from cyclonedx.model.dependency import Dependency
from cyclonedx.model.impact_analysis import ImpactAnalysisAffectedStatus
from cyclonedx.model.vulnerability import BomTarget, BomTargetVersionRange, Vulnerability


def _component(ref: str, scope: ComponentScope = ComponentScope.REQUIRED) -> Component:
    return Component(name=ref, bom_ref=ref, scope=scope)


def _dependency(ref: str, children: list[str]) -> Dependency:
    return Dependency(ref=BomRef(value=ref), dependencies=[Dependency(ref=BomRef(value=child)) for child in children])


class ImpactFixture:
    """Two deployment roots sharing half of their dependency tree.

    Graph::

        prod-app -> shared-lib -> vuln-lib
                  -> prod-only -> vuln-lib
        test-app -> shared-lib -> vuln-lib
                  -> test-only -> dangling-ref
        shared-lib <-> cycle-lib (cycle)
    """

    def __init__(self) -> None:
        self.prod_app = _component("prod-app")
        self.test_app = _component("test-app")
        self.shared_lib = _component("shared-lib")
        self.prod_only = _component("prod-only")
        self.test_only = _component("test-only")
        self.vuln_lib = _component("vuln-lib")
        self.cycle_lib = _component("cycle-lib")
        self.optional_lib = _component("optional-lib", scope=ComponentScope.OPTIONAL)
        components = [
            self.prod_app, self.test_app, self.shared_lib, self.prod_only, self.test_only,
            self.vuln_lib, self.cycle_lib, self.optional_lib,
        ]
        dependencies = [
            _dependency("prod-app", ["shared-lib", "prod-only", "optional-lib"]),
            _dependency("test-app", ["shared-lib", "test-only"]),
            _dependency("shared-lib", ["vuln-lib", "cycle-lib"]),
            _dependency("cycle-lib", ["shared-lib"]),
            _dependency("prod-only", ["vuln-lib"]),
            _dependency("test-only", ["dangling-ref"]),
        ]
        affected = Vulnerability(
            id="CVE-AFFECTED",
            affects=[BomTarget(ref="vuln-lib", versions=[
                BomTargetVersionRange(version="1.0.0", status=ImpactAnalysisAffectedStatus.AFFECTED),
            ])],
        )
        unknown_range = Vulnerability(
            id="CVE-UNKNOWN-RANGE",
            affects=[BomTarget(ref="vuln-lib")],
        )
        unaffected = Vulnerability(
            id="CVE-UNAFFECTED",
            affects=[BomTarget(ref="vuln-lib", versions=[
                BomTargetVersionRange(version="1.0.0", status=ImpactAnalysisAffectedStatus.UNAFFECTED),
            ])],
        )
        missing_target = Vulnerability(
            id="CVE-MISSING-TARGET",
            affects=[BomTarget(ref="ghost-lib", versions=[
                BomTargetVersionRange(version="2.0.0", status=ImpactAnalysisAffectedStatus.AFFECTED),
            ])],
        )
        self.bom = Bom(
            components=components,
            dependencies=dependencies,
            vulnerabilities=[affected, unknown_range, unaffected, missing_target],
        )
        self.affected_id = "CVE-AFFECTED"
        self.unknown_range_id = "CVE-UNKNOWN-RANGE"
        self.unaffected_id = "CVE-UNAFFECTED"
        self.missing_target_id = "CVE-MISSING-TARGET"


def _impact(bom: Bom, root: Component) -> ImpactReport:
    return analyze_impact(bom, root)


def _impact_by_id(report: ImpactReport, vulnerability_id: str):
    return next(impact for impact in report.impacts if impact.vulnerability_id == vulnerability_id)


class TestAnalyzeImpact(TestCase):

    def setUp(self) -> None:
        self.fixture = ImpactFixture()

    def test_reconstructs_every_dependency_path_for_production_root(self) -> None:
        report = _impact(self.fixture.bom, self.fixture.prod_app)
        impact = _impact_by_id(report, self.fixture.affected_id)

        self.assertEqual(
            sorted(path.bom_refs for path in impact.confirmed_paths),
            sorted([
                ("prod-app", "shared-lib", "vuln-lib"),
                ("prod-app", "prod-only", "vuln-lib"),
            ]),
        )
        self.assertTrue(impact.is_risk)
        self.assertIn(impact, report.risks)

    def test_test_root_keeps_its_own_independent_risk_path(self) -> None:
        # the two roots share shared-lib, but each also has its own deployment path
        prod_report = _impact(self.fixture.bom, self.fixture.prod_app)
        test_report = _impact(self.fixture.bom, self.fixture.test_app)
        test_impact = _impact_by_id(test_report, self.fixture.affected_id)

        self.assertEqual(
            [path.bom_refs for path in test_impact.confirmed_paths],
            [("test-app", "shared-lib", "vuln-lib")],
        )
        self.assertTrue(test_impact.is_risk)

    def test_fixing_one_deployment_path_leaves_the_other_on_the_risk_list(self) -> None:
        bom = self.fixture.bom
        # remove the prod-only -> vuln-lib edge: one of the two production paths is fixed
        bom.dependencies = {
            dependency for dependency in bom.dependencies
            if str(dependency.ref) != "prod-only"
        }
        report = _impact(bom, self.fixture.prod_app)
        impact = _impact_by_id(report, self.fixture.affected_id)

        self.assertEqual(
            [path.bom_refs for path in impact.confirmed_paths],
            [("prod-app", "shared-lib", "vuln-lib")],
        )
        self.assertTrue(impact.is_risk)
        self.assertIn(impact, report.risks)

    def test_fixing_all_paths_clears_the_risk(self) -> None:
        bom = self.fixture.bom
        bom.dependencies = {
            dependency for dependency in bom.dependencies
            if str(dependency.ref) not in ("prod-only", "shared-lib")
        }
        report = _impact(bom, self.fixture.prod_app)
        impact = _impact_by_id(report, self.fixture.affected_id)

        self.assertEqual(impact.confirmed_paths, ())
        self.assertFalse(impact.is_risk)
        self.assertNotIn(impact, report.risks)

    def test_cycle_edge_is_reported_and_does_not_loop_forever(self) -> None:
        report = _impact(self.fixture.bom, self.fixture.prod_app)
        cycle_edges = [edge for edge in report.all_unresolved_edges if edge.status is ImpactEdgeStatus.CYCLE]

        self.assertTrue(any(
            edge.source == "cycle-lib" and edge.target == "shared-lib" for edge in cycle_edges
        ))
        # the affected path through shared-lib is still reconstructed exactly once
        impact = _impact_by_id(report, self.fixture.affected_id)
        self.assertIn(
            ("prod-app", "shared-lib", "vuln-lib"),
            [path.bom_refs for path in impact.paths],
        )

    def test_missing_reference_edge_is_left_in_the_report(self) -> None:
        report = _impact(self.fixture.bom, self.fixture.test_app)
        missing_edges = [
            edge for edge in report.all_unresolved_edges
            if edge.status is ImpactEdgeStatus.MISSING_REFERENCE
        ]

        self.assertEqual(len(missing_edges), 1)
        self.assertEqual(missing_edges[0].source, "test-only")
        self.assertEqual(missing_edges[0].target, "dangling-ref")

    def test_unknown_range_produces_a_pending_path_not_a_confirmed_risk(self) -> None:
        report = _impact(self.fixture.bom, self.fixture.prod_app)
        impact = _impact_by_id(report, self.fixture.unknown_range_id)

        self.assertTrue(impact.pending_paths)
        self.assertEqual(impact.confirmed_paths, ())
        self.assertFalse(impact.is_risk)
        self.assertIn(impact, report.pending)
        self.assertTrue(all(path.status is ImpactPathStatus.PENDING for path in impact.pending_paths))

    def test_out_of_scope_edge_is_pending_and_not_traversed(self) -> None:
        report = _impact(self.fixture.bom, self.fixture.prod_app)
        scope_edges = [
            edge for edge in report.all_unresolved_edges
            if edge.status is ImpactEdgeStatus.OUT_OF_SCOPE
        ]

        self.assertEqual(len(scope_edges), 1)
        self.assertEqual(scope_edges[0].source, "prod-app")
        self.assertEqual(scope_edges[0].target, "optional-lib")

    def test_missing_reference_branch_is_kept_as_a_pending_path(self) -> None:
        report = _impact(self.fixture.bom, self.fixture.test_app)
        impact = _impact_by_id(report, self.fixture.affected_id)
        dangling_paths = [
            path for path in impact.pending_paths
            if any(edge.status is ImpactEdgeStatus.MISSING_REFERENCE for edge in path.unresolved_edges)
        ]

        self.assertEqual(len(dangling_paths), 1)
        self.assertEqual(dangling_paths[0].bom_refs, ("test-app", "test-only"))
        self.assertEqual(dangling_paths[0].unresolved_edges[0].target, "dangling-ref")

    def test_cycle_branch_is_kept_as_a_pending_path(self) -> None:
        report = _impact(self.fixture.bom, self.fixture.prod_app)
        impact = _impact_by_id(report, self.fixture.affected_id)
        cycle_paths = [
            path for path in impact.pending_paths
            if any(edge.status is ImpactEdgeStatus.CYCLE for edge in path.unresolved_edges)
        ]

        self.assertEqual(len(cycle_paths), 1)
        self.assertEqual(cycle_paths[0].bom_refs, ("prod-app", "shared-lib", "cycle-lib"))

    def test_out_of_scope_branch_is_kept_as_a_pending_path(self) -> None:
        report = _impact(self.fixture.bom, self.fixture.prod_app)
        impact = _impact_by_id(report, self.fixture.affected_id)
        scope_paths = [
            path for path in impact.pending_paths
            if any(edge.status is ImpactEdgeStatus.OUT_OF_SCOPE for edge in path.unresolved_edges)
        ]

        self.assertEqual(len(scope_paths), 1)
        self.assertEqual(scope_paths[0].bom_refs, ("prod-app",))

    def test_applicable_scope_can_be_widened_by_the_caller(self) -> None:
        report = analyze_impact(
            self.fixture.bom,
            self.fixture.prod_app,
            applicable_scope=(ComponentScope.REQUIRED, ComponentScope.OPTIONAL),
        )
        self.assertFalse([
            edge for edge in report.all_unresolved_edges
            if edge.status is ImpactEdgeStatus.OUT_OF_SCOPE
        ])

    def test_unaffected_target_does_not_create_paths(self) -> None:
        report = _impact(self.fixture.bom, self.fixture.prod_app)
        impact = _impact_by_id(report, self.fixture.unaffected_id)

        self.assertEqual(impact.paths, ())
        self.assertFalse(impact.is_risk)
        self.assertNotIn(impact, report.risks)
        self.assertNotIn(impact, report.pending)

    def test_missing_affects_target_is_tracked_for_review(self) -> None:
        report = _impact(self.fixture.bom, self.fixture.prod_app)
        impact = _impact_by_id(report, self.fixture.missing_target_id)

        self.assertEqual([target.ref for target in impact.missing_targets], ["ghost-lib"])
        self.assertEqual(impact.paths, ())
        self.assertIn(impact, report.pending)

    def test_unknown_deployment_root_yields_empty_report(self) -> None:
        unknown_root = _component("not-in-bom")
        report = _impact(self.fixture.bom, unknown_root)

        self.assertEqual(report.risks, ())
        # no path can be reconstructed; only target-level data (missing affects refs) survives
        self.assertTrue(all(impact.paths == () for impact in report.impacts))
        self.assertTrue(all(
            impact.pending_paths == () for impact in report.impacts
        ))

    def test_unresolved_edges_are_deduplicated_and_kept_on_report(self) -> None:
        report = _impact(self.fixture.bom, self.fixture.test_app)
        edges = report.all_unresolved_edges

        self.assertEqual(len(edges), len(set(edges)))
        self.assertTrue(any(
            edge.status is ImpactEdgeStatus.MISSING_REFERENCE for edge in edges
        ))


class TestTargetClassification(TestCase):

    def test_unknown_status_entry_is_treated_as_unknown_range(self) -> None:
        component = _component("comp")
        bom = Bom(
            components=[component],
            dependencies=[],
            vulnerabilities=[Vulnerability(
                id="CVE-X",
                affects=[BomTarget(ref="comp", versions=[
                    BomTargetVersionRange(version="1.0.0", status=ImpactAnalysisAffectedStatus.UNKNOWN),
                ])],
            )],
        )
        report = analyze_impact(bom, component)
        impact = _impact_by_id(report, "CVE-X")

        self.assertEqual(len(impact.pending_paths), 1)
        self.assertFalse(impact.is_risk)
