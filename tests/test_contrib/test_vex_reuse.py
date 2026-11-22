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


from typing import Iterable, Optional
from unittest import TestCase

from packageurl import PackageURL

from cyclonedx.contrib.bom.vex_reuse import (
    ArtifactIdentity,
    ComponentCoordinates,
    ReuseDecision,
    ReuseReason,
    VexReuseEngine,
)
from cyclonedx.model import HashAlgorithm, HashType
from cyclonedx.model.bom import Bom, BomMetaData
from cyclonedx.model.bom_ref import BomRef
from cyclonedx.model.component import Component, ComponentScope, ComponentType
from cyclonedx.model.dependency import Dependency
from cyclonedx.model.impact_analysis import ImpactAnalysisState
from cyclonedx.model.vulnerability import BomTarget, Vulnerability, VulnerabilityAnalysis


def make_component(
    name: str,
    ref: str,
    *,
    group: str = "acme",
    version: str = "1.2.3",
    hashes: Optional[Iterable[HashType]] = None,
    scope: Optional[ComponentScope] = None,
    component_type: ComponentType = ComponentType.LIBRARY,
    purl: Optional[PackageURL] = None,
) -> Component:
    return Component(
        name=name,
        bom_ref=BomRef(ref),
        type=component_type,
        group=group,
        version=version,
        scope=scope,
        hashes=hashes,
        purl=purl if purl is not None else PackageURL(
            type="pypi", namespace=group, name=name, version=version,
        ),
    )


def make_hash(content: str) -> HashType:
    return HashType(alg=HashAlgorithm.SHA_256, content=content)


def make_verdict(
    vulnerability_id: str,
    target_ref: str,
    state: ImpactAnalysisState = ImpactAnalysisState.NOT_AFFECTED,
) -> Vulnerability:
    return Vulnerability(
        id=vulnerability_id,
        analysis=VulnerabilityAnalysis(state=state),
        affects=[BomTarget(ref=target_ref)],
    )


def make_bom(
    components: Iterable[Component],
    vulnerabilities: Iterable[Vulnerability] = (),
    dependencies: Optional[Iterable[Dependency]] = None,
    root: Optional[Component] = None,
) -> Bom:
    metadata = BomMetaData(component=root) if root is not None else BomMetaData()
    if dependencies is None:
        # Without an explicit graph every component is its own deployment root,
        # mirroring a BOM whose dependency graph simply lists each top node.
        dependencies = [Dependency(ref=component.bom_ref) for component in components]
    return Bom(
        components=components,
        vulnerabilities=vulnerabilities,
        dependencies=dependencies,
        metadata=metadata,
    )


def graph(edges: dict[str, Iterable[str]]) -> list[Dependency]:
    return [
        Dependency(ref=BomRef(source), dependencies=(Dependency(ref=BomRef(target)) for target in targets))
        for source, targets in edges.items()
    ]


class TestIdentityModel(TestCase):

    def test_coordinates_ignore_bom_ref(self):
        first = make_component("lib", "ref-a")
        second = make_component("lib", "ref-b")
        self.assertEqual(
            ComponentCoordinates.from_component(first),
            ComponentCoordinates.from_component(second),
        )

    def test_artifact_identity_distinguishes_hashes(self):
        first = make_component("lib", "ref-a", hashes=[make_hash("a" * 16)])
        second = make_component("lib", "ref-b", hashes=[make_hash("b" * 16)])
        self.assertNotEqual(
            ArtifactIdentity.from_component(first),
            ArtifactIdentity.from_component(second),
        )
        self.assertTrue(ArtifactIdentity.from_component(first).is_evidenced)

    def test_identity_without_hashes_is_not_evidenced(self):
        component = make_component("lib", "ref-a")
        self.assertFalse(ArtifactIdentity.from_component(component).is_evidenced)

    def test_same_hash_set_compares_equal_regardless_of_order(self):
        first = make_component(
            "lib", "ref-a", hashes=[make_hash("a" * 16), make_hash("b" * 16)],
        )
        second = make_component(
            "lib", "ref-b", hashes=[make_hash("b" * 16), make_hash("a" * 16)],
        )
        self.assertEqual(
            ArtifactIdentity.from_component(first),
            ArtifactIdentity.from_component(second),
        )


class TestVexReuseEngine(TestCase):

    def setUp(self):
        self.engine = VexReuseEngine()

    def test_reuses_verdict_when_artifact_unchanged_but_bom_ref_changes(self):
        old_lib = make_component("lib", "old-ref", hashes=[make_hash("h" * 16)])
        new_lib = make_component("lib", "new-ref", hashes=[make_hash("h" * 16)])
        old_bom = make_bom([old_lib], [make_verdict("CVE-1", "old-ref")])
        new_bom = make_bom([new_lib])

        report = self.engine.compare(old_bom, new_bom)

        self.assertEqual(1, len(report.reusable))
        entry = report.reusable[0]
        self.assertEqual(ReuseDecision.REUSE, entry.decision)
        self.assertEqual(ReuseReason.ARTIFACT_UNCHANGED, entry.reason)
        self.assertEqual("new-ref", entry.new_bom_refs[0].value)
        self.assertEqual("old-ref", entry.old_bom_ref.value)

    def test_reopens_verdict_when_hash_changes_at_same_coordinates(self):
        old_lib = make_component("lib", "lib-ref", hashes=[make_hash("old" * 4)])
        new_lib = make_component("lib", "lib-ref", hashes=[make_hash("new" * 4)])
        old_bom = make_bom([old_lib], [make_verdict("CVE-1", "lib-ref")])
        new_bom = make_bom([new_lib])

        report = self.engine.compare(old_bom, new_bom)

        self.assertEqual(0, len(report.reusable))
        entry = report.requiring_action[0]
        self.assertEqual(ReuseDecision.REOPEN, entry.decision)
        self.assertEqual(ReuseReason.HASH_CHANGED_AT_SAME_COORDINATES, entry.reason)
        self.assertNotEqual(entry.old_identity, entry.new_identities[0])

    def test_order_only_change_is_reused_with_stable_bom_ref(self):
        # Same bom-ref, same delivered content - only BOM collection order can
        # have changed between the two revisions.
        old_lib = make_component("lib", "lib-1", hashes=[make_hash("h" * 16)])
        new_lib = make_component("lib", "lib-1", hashes=[make_hash("h" * 16)])
        old_bom = make_bom([old_lib], [make_verdict("CVE-1", "lib-1")])
        new_bom = make_bom([new_lib])

        entry = self.engine.compare(old_bom, new_bom).entries[0]

        self.assertEqual(ReuseDecision.REUSE, entry.decision)
        self.assertEqual(ReuseReason.ORDER_ONLY_CHANGE, entry.reason)

    def test_ambiguous_builds_at_same_coordinates_need_more_evidence(self):
        old_lib = make_component("lib", "lib-ref", hashes=[make_hash("signed" * 3)])
        new_first = make_component("lib", "build-1", hashes=[make_hash("one" * 4)])
        new_second = make_component("lib", "build-2", hashes=[make_hash("two" * 4)])
        old_bom = make_bom([old_lib], [make_verdict("CVE-1", "lib-ref")])
        new_bom = make_bom([new_first, new_second])

        entry = self.engine.compare(old_bom, new_bom).entries[0]

        self.assertEqual(ReuseDecision.INSUFFICIENT_EVIDENCE, entry.decision)
        self.assertEqual(ReuseReason.AMBIGUOUS_COORDINATES, entry.reason)
        self.assertEqual(2, len(entry.new_bom_refs))

    def test_unevidenced_single_build_is_reused_on_coordinates(self):
        old_lib = make_component("lib", "lib-1")
        new_lib = make_component("lib", "lib-2")
        old_bom = make_bom([old_lib], [make_verdict("CVE-1", "lib-1")])
        new_bom = make_bom([new_lib])

        entry = self.engine.compare(old_bom, new_bom).entries[0]

        self.assertEqual(ReuseDecision.REUSE, entry.decision)

    def test_unevidenced_duplicate_builds_are_ambiguous(self):
        old_lib = make_component("lib", "lib-1")
        new_first = make_component("lib", "lib-2")
        new_second = make_component("lib", "lib-3")
        old_bom = make_bom([old_lib], [make_verdict("CVE-1", "lib-1")])
        new_bom = make_bom([new_first, new_second])

        entry = self.engine.compare(old_bom, new_bom).entries[0]

        self.assertEqual(ReuseDecision.INSUFFICIENT_EVIDENCE, entry.decision)

    def test_removed_component_makes_verdict_obsolete(self):
        old_lib = make_component("lib", "lib-ref", hashes=[make_hash("h" * 16)])
        other = make_component("other", "other-ref", hashes=[make_hash("o" * 16)])
        old_bom = make_bom([old_lib], [make_verdict("CVE-1", "lib-ref")])
        new_bom = make_bom([other])

        entry = self.engine.compare(old_bom, new_bom).entries[0]

        self.assertEqual(ReuseDecision.OBSOLETE, entry.decision)
        self.assertEqual(ReuseReason.COMPONENT_REMOVED, entry.reason)


class TestDeploymentReachability(TestCase):

    def setUp(self):
        self.engine = VexReuseEngine()

    def _root(self, ref, name):
        return make_component(name, ref, component_type=ComponentType.APPLICATION)

    def test_optional_shared_dependency_lists_all_involved_roots(self):
        old_app = self._root("app", "app")
        old_opt = make_component(
            "feature", "feature-old",
            hashes=[make_hash("f" * 16)], scope=ComponentScope.OPTIONAL,
        )
        old_bom = make_bom(
            [old_app, old_opt],
            [make_verdict("CVE-9", "feature-old")],
            graph({"app": ["feature-old"]}),
            root=old_app,
        )
        root_one = self._root("root-1", "service-one")
        root_two = self._root("root-2", "service-two")
        new_opt = make_component(
            "feature", "feature-new",
            hashes=[make_hash("f" * 16)], scope=ComponentScope.OPTIONAL,
        )
        new_bom = make_bom(
            [root_one, root_two, new_opt],
            dependencies=graph({"root-1": ["feature-new"], "root-2": ["feature-new"]}),
        )
        entry = self.engine.compare(old_bom, new_bom).entries[0]
        self.assertEqual(ReuseDecision.REUSE, entry.decision)
        root_values = {r.value for r in entry.deployment_roots}
        self.assertEqual({"root-1", "root-2"}, root_values)

    def test_required_dependency_does_not_need_explicit_roots(self):
        old_app = self._root("app", "app")
        old_dep = make_component("dep", "dep-old", hashes=[make_hash("d" * 16)])
        old_bom = make_bom(
            [old_app, old_dep],
            [make_verdict("CVE-2", "dep-old")],
            graph({"app": ["dep-old"]}),
            root=old_app,
        )
        new_app = self._root("app", "app")
        new_dep = make_component("dep", "dep-new", hashes=[make_hash("d" * 16)])
        new_bom = make_bom(
            [new_app, new_dep],
            dependencies=graph({"app": ["dep-new"]}),
            root=new_app,
        )
        entry = self.engine.compare(old_bom, new_bom).entries[0]
        self.assertEqual(ReuseDecision.REUSE, entry.decision)
        self.assertEqual((), entry.deployment_roots)

    def test_unreachable_unchanged_artifact_is_obsolete(self):
        old_app = self._root("app", "app")
        old_dep = make_component("dep", "dep-old", hashes=[make_hash("d" * 16)])
        old_bom = make_bom(
            [old_app, old_dep],
            [make_verdict("CVE-2", "dep-old")],
            graph({"app": ["dep-old"]}),
            root=old_app,
        )
        new_app = self._root("app", "app")
        new_dep = make_component("dep", "dep-new", hashes=[make_hash("d" * 16)])
        new_bom = make_bom([new_app, new_dep], root=new_app)
        entry = self.engine.compare(old_bom, new_bom).entries[0]
        self.assertEqual(ReuseDecision.OBSOLETE, entry.decision)
        self.assertEqual(ReuseReason.NO_LONGER_REACHABLE, entry.reason)

    def test_one_changed_material_keeps_other_signed_verdicts_reusable(self):
        old_stable = make_component("stable", "stable-1", hashes=[make_hash("s" * 16)])
        old_unstable = make_component("volatile", "volatile-1", hashes=[make_hash("v" * 16)])
        old_bom = make_bom(
            [old_stable, old_unstable],
            [
                make_verdict("CVE-S", "stable-1"),
                make_verdict("CVE-V", "volatile-1"),
            ],
        )
        new_stable = make_component("stable", "stable-2", hashes=[make_hash("s" * 16)])
        new_unstable = make_component("volatile", "volatile-2", hashes=[make_hash("z" * 16)])
        new_bom = make_bom([new_stable, new_unstable])
        report = self.engine.compare(old_bom, new_bom)
        by_cve = {e.verdict.vulnerability_id: e for e in report.entries}
        self.assertEqual(ReuseDecision.REUSE, by_cve["CVE-S"].decision)
        self.assertEqual(ReuseDecision.REOPEN, by_cve["CVE-V"].decision)

    def test_unsigned_verdicts_are_ignored(self):
        old_lib = make_component("lib", "lib-1", hashes=[make_hash("h" * 16)])
        unsigned = Vulnerability(id="CVE-X", affects=[BomTarget(ref="lib-1")])
        old_bom = make_bom([old_lib], [unsigned])
        new_bom = make_bom([make_component("lib", "lib-2", hashes=[make_hash("h" * 16)])])
        report = self.engine.compare(old_bom, new_bom)
        self.assertEqual(0, len(report))
