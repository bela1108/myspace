"""Tests for the offline minimal role-export planner.

These tests build a freshly signed small mirror in a temporary directory
and verify both the mergeable case and the missing-material / deficiency
case described in the repair-contract task.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import offline_export_plan as oep
from tiny_mirror_demo import (
    FULL_ROLE_ORDER,
    MEMBERSHIP_ROLE_ORDER,
    TARGET_ONE,
    TARGET_TWO,
    allow_all_manifest,
    build_tiny_mirror,
    missing_root_manifest,
    signature_blocked_manifest,
    standard_requests,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
UPSTREAM_FIXTURE = REPO_ROOT / "tests" / "repository_data" / "repository"


class TinyMirrorTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._temp.name)
        self.mirror = build_tiny_mirror(self.tmp / "tiny-mirror")
        self.requests = standard_requests()

    def tearDown(self) -> None:
        self._temp.cleanup()

    def plan(self, manifest, **kwargs):
        options = dict(assurance_level="full", verify_crypto=True)
        options.update(kwargs)
        return oep.plan_export(self.mirror, self.requests, manifest, **options)


class MergeableExportTests(TinyMirrorTestBase):
    def test_full_merge_is_minimal_and_deduplicated(self):
        plan = self.plan(
            {
                "transferable_materials": [
                    f"metadata/{role}.json" for role in FULL_ROLE_ORDER
                ]
            }
        )

        self.assertEqual(plan.status, "ready")
        self.assertTrue(plan.sufficient)
        self.assertTrue(plan.mergeable)
        self.assertEqual(plan.minimal_roles, list(FULL_ROLE_ORDER))
        self.assertEqual(
            plan.shared_roles,
            ["root", "timestamp", "snapshot", "targets", "parent"],
        )
        self.assertEqual(len(plan.handoff_files), 7)
        self.assertEqual(plan.certified_handoff_files, plan.handoff_files)
        self.assertEqual(plan.missing, [])

    def test_membership_level_is_even_smaller(self):
        plan = self.plan(["*"], assurance_level="membership")

        self.assertTrue(plan.sufficient)
        self.assertEqual(plan.minimal_roles, list(MEMBERSHIP_ROLE_ORDER))
        self.assertEqual(plan.shared_roles, ["root", "targets", "parent"])
        causes = {(c.scope, c.cause) for c in plan.unattested_scope}
        self.assertIn(("snapshot_consistency", "assurance_level_excluded"), causes)
        self.assertIn(("freshness", "assurance_level_excluded"), causes)
        self.assertIn(
            ("target_artifact_bytes", "out_of_material_scope"), causes
        )

    def test_allow_all_still_excludes_unrelated_nightly_role(self):
        plan = self.plan(allow_all_manifest())

        self.assertTrue(plan.sufficient)
        self.assertEqual(plan.minimal_roles, list(FULL_ROLE_ORDER))
        self.assertIn("nightly", plan.excluded_roles)
        self.assertNotIn("metadata/nightly.json", plan.handoff_files)

    def test_each_request_has_distinct_branch_roles(self):
        plan = self.plan(["*"])
        by_id = {rp.request_id: rp for rp in plan.requests}
        one = by_id["repair-review-one"]
        two = by_id["repair-review-two"]
        self.assertEqual(one.roles[-1], "update-a")
        self.assertEqual(two.roles[-1], "update-b")
        self.assertTrue(one.complete and two.complete)


class MissingMaterialTests(TinyMirrorTestBase):
    def test_denied_root_is_reported_as_missing_and_not_merged(self):
        plan = self.plan(missing_root_manifest())

        self.assertFalse(plan.sufficient)
        self.assertFalse(plan.mergeable)
        self.assertEqual(plan.status, "incomplete")
        # No certified handoff list may be claimed when the anchor is missing.
        self.assertEqual(plan.certified_handoff_files, [])

        root_missing = [m for m in plan.missing if m.role == "root"]
        self.assertEqual(len(root_missing), 1)
        self.assertEqual(root_missing[0].code, "not_transferable")
        self.assertEqual(root_missing[0].required_by, [
            "repair-review-one",
            "repair-review-two",
        ])

        end_to_end = {
            c.target: c
            for c in plan.unattested_scope
            if c.scope == "end_to_end_attestation"
        }
        self.assertEqual(set(end_to_end), {TARGET_ONE, TARGET_TWO})
        for claim in end_to_end.values():
            self.assertIn("metadata/root.json", claim.blocked_by)

        anchor_scopes = {c.scope for c in plan.unattested_scope}
        self.assertIn("trust_anchor", anchor_scopes)
        self.assertIn("key_authorization", anchor_scopes)

    def test_unsigned_alias_and_digest_are_rejected(self):
        plan = self.plan(missing_root_manifest())
        codes = {item.code for item in plan.rejected_substitutes}
        self.assertIn("rejected_unsigned_alias", codes)
        self.assertIn("rejected_arbitrary_digest", codes)
        refs = {item.ref for item in plan.rejected_substitutes}
        self.assertIn("metadata/root.alias", refs)
        self.assertIn("metadata/root.json.sha256", refs)
        # Rejected substitutes never enter the handoff list.
        self.assertFalse(
            any(ref.endswith("root.alias") for ref in plan.handoff_files)
        )

    def test_signature_material_blocked_is_a_distinct_deficiency(self):
        plan = self.plan(signature_blocked_manifest())

        self.assertFalse(plan.sufficient)
        root_items = [m for m in plan.missing if m.role == "root"]
        self.assertEqual(len(root_items), 1)
        self.assertEqual(root_items[0].code, "signature_material_blocked")
        self.assertEqual(plan.certified_handoff_files, [])

    def test_missing_branch_role_only_blocks_that_target(self):
        manifest = {
            "transferable_materials": ["*"],
            "denied_materials": ["metadata/update-a.json"],
        }
        plan = self.plan(manifest)

        self.assertFalse(plan.mergeable)
        missing_roles = {m.role for m in plan.missing}
        self.assertIn("update-a", missing_roles)
        e2e_targets = {
            c.target
            for c in plan.unattested_scope
            if c.scope == "end_to_end_attestation"
        }
        self.assertIn(TARGET_ONE, e2e_targets)
        # Precise scope: the healthy branch/target stays attestable.
        self.assertNotIn(TARGET_TWO, e2e_targets)
        by_id = {rp.request_id: rp for rp in plan.requests}
        self.assertFalse(by_id["repair-review-one"].complete)
        self.assertTrue(by_id["repair-review-two"].complete)
        # The healthy branch alone still has a certified handoff list.
        self.assertIn("metadata/update-b.json", plan.handoff_files)


class UpstreamFixtureTests(unittest.TestCase):
    def test_repository_data_two_targets_minimal_set_and_crypto(self):
        if not UPSTREAM_FIXTURE.exists():
            self.skipTest("upstream repository_data fixture unavailable")

        plan = oep.plan_export(
            UPSTREAM_FIXTURE,
            [
                {"request_id": "direct", "target": "file1.txt"},
                {"request_id": "delegated", "target": "file3.txt"},
            ],
            ["*"],
            assurance_level="full",
            verify_crypto=True,
        )

        self.assertTrue(plan.sufficient, [
            (m.role, m.code, m.detail if hasattr(m, "detail") else m.reason)
            for m in plan.missing
        ])
        self.assertEqual(
            plan.minimal_roles,
            ["root", "timestamp", "snapshot", "targets", "role1"],
        )
        self.assertEqual(
            plan.shared_roles,
            ["root", "timestamp", "snapshot", "targets"],
        )
        self.assertIn("role2", plan.excluded_roles)


class InputFlexibilityAndResolutionTests(TinyMirrorTestBase):
    def test_targets_keyword_and_plain_strings(self):
        by_keyword = oep.plan_export(
            self.mirror,
            targets=[TARGET_ONE, TARGET_TWO],
            manifest=["*"],
            assurance_level="full",
        )
        self.assertTrue(by_keyword.sufficient)
        self.assertEqual(len(by_keyword.requests), 2)

        by_strings = oep.plan_export(
            self.mirror,
            [TARGET_ONE],
            ["*"],
            assurance_level="membership",
        )
        self.assertTrue(by_strings.sufficient)

    def test_unknown_target_is_an_explicit_gap(self):
        plan = oep.plan_export(
            self.mirror,
            [{"request_id": "lost", "target": "approved/not-published.bin"}],
            ["*"],
            assurance_level="full",
        )
        self.assertFalse(plan.sufficient)
        codes = {item.code for item in plan.missing}
        self.assertIn("target_not_found", codes)
        e2e = [
            c
            for c in plan.unattested_scope
            if c.scope == "end_to_end_attestation"
        ]
        self.assertEqual(len(e2e), 1)
        self.assertEqual(e2e[0].target, "approved/not-published.bin")

    def test_no_manifest_means_deny_all(self):
        plan = oep.plan_export(
            self.mirror,
            self.requests,
            assurance_level="membership",
        )
        self.assertFalse(plan.sufficient)
        self.assertTrue(
            all(item.code == "not_transferable" for item in plan.missing)
        )

    def test_unsigned_synthetic_metadata_strict_by_default(self):
        metadata_dir = self.tmp / "synthetic" / "metadata"
        metadata_dir.mkdir(parents=True)

        def write_role(name, signed):
            (metadata_dir / f"{name}.json").write_text(
                json.dumps({"signatures": [], "signed": signed}),
                encoding="utf-8",
            )

        write_role(
            "root",
            {
                "_type": "root",
                "keys": {},
                "roles": {
                    "root": {"keyids": [], "threshold": 1},
                    "targets": {"keyids": [], "threshold": 1},
                },
            },
        )
        write_role("targets", {"_type": "targets", "targets": {"x.bin": {}}})

        # Default (signature enforcement on): empty signatures are a gap.
        strict = oep.plan_export(
            self.tmp / "synthetic", ["x.bin"], ["*"],
            assurance_level="membership",
        )
        self.assertFalse(strict.sufficient)
        self.assertIn(
            "insufficient_signatures", {m.code for m in strict.missing}
        )

        # Selection-only mode stays usable for unsigned synthetic graphs,
        # while still surfacing a non-blocking warning.
        lenient = oep.plan_export(
            self.tmp / "synthetic",
            ["x.bin"],
            ["*"],
            assurance_level="membership",
            enforce_signatures=False,
        )
        self.assertTrue(lenient.sufficient, lenient.missing)
        self.assertTrue(
            any("insufficient_signatures" in w for w in lenient.warnings)
        )


class BundleAndInterfaceTests(TinyMirrorTestBase):
    def test_write_bundle_copies_only_ready_files_and_report(self):
        plan = self.plan(
            {
                "transferable_materials": ["*"],
                "denied_materials": ["metadata/root.json"],
            }
        )
        out = self.tmp / "bundle"
        oep.write_bundle(plan, out)

        self.assertTrue((out / "export-plan.json").is_file())
        self.assertTrue((out / "REPORT.md").is_file())
        copied = {
            p.relative_to(out / "role-files").as_posix()
            for p in (out / "role-files").rglob("*.json")
        }
        self.assertNotIn("metadata/root.json", copied)
        self.assertIn("metadata/update-a.json", copied)

        data = json.loads((out / "export-plan.json").read_text("utf-8"))
        self.assertFalse(data["sufficient"])

    def test_result_supports_mapping_access(self):
        plan = self.plan(["*"])
        self.assertEqual(plan["status"], "ready")
        self.assertIn("handoff_files", plan.to_dict())
        # JSON must be serializable without custom encoders.
        json.loads(plan.to_json())

    def test_planner_class_and_dict_entrypoint(self):
        planner = oep.OfflineExportPlanner(
            self.mirror, ["*"], assurance_level="full", verify_crypto=True
        )
        plan = planner.plan(targets=[TARGET_ONE, TARGET_TWO])
        self.assertTrue(plan.sufficient)

        as_dict = oep.plan_export_dict(
            self.mirror, self.requests, ["*"], assurance_level="full"
        )
        self.assertIsInstance(as_dict, dict)
        self.assertIn("minimal_roles", as_dict)

    def test_cli_plan_with_strict_flag(self):
        requests_file = self.tmp / "requests.json"
        requests_file.write_text(json.dumps(self.requests), "utf-8")
        manifest_file = self.tmp / "manifest.json"
        manifest_file.write_text(
            json.dumps(missing_root_manifest()), "utf-8"
        )
        out_dir = self.tmp / "cli-out"

        rc = oep.main(
            [
                "plan",
                "--mirror",
                str(self.mirror),
                "--requests",
                str(requests_file),
                "--manifest",
                str(manifest_file),
                "--assurance",
                "full",
                "--out",
                str(out_dir),
                "--strict",
            ]
        )
        self.assertEqual(rc, 3)
        self.assertTrue((out_dir / "export-plan.json").is_file())


if __name__ == "__main__":
    unittest.main()
