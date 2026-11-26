# -*- coding: utf-8 -*-

import unittest

from signedjson.approvals import reconcile_release, sign_approval
from signedjson.key import generate_signing_key, get_verify_key


class ApprovalReconciliationTest(unittest.TestCase):
    def setUp(self):
        self.alice_key = generate_signing_key("1")
        self.bob_key = generate_signing_key("1")
        self.carol_key = generate_signing_key("1")
        self.keys = {
            "alice": get_verify_key(self.alice_key),
            "bob": get_verify_key(self.bob_key),
            "carol": get_verify_key(self.carol_key),
        }

    def signed(self, approval, approver, key):
        return sign_approval(approval, approver, key)

    def test_matches_path_digest_and_manifest_version(self):
        manifest = {
            "manifest_version": "v1",
            "items": [
                {"path": "a.txt", "digest": "digest-a"},
                {"path": "b.txt", "digest": "digest-b"},
            ],
        }
        approvals = [
            self.signed(
                {
                    "approver": "alice",
                    "manifest_version": "v1",
                    "items": [{"path": "a.txt", "digest": "digest-a"}],
                },
                "alice",
                self.alice_key,
            )
        ]

        result = reconcile_release(
            manifest,
            {"alice": ["a.txt"]},
            approvals,
            verify_keys=self.keys,
        )

        self.assertEqual(result.releasable_paths, ["a.txt"])
        self.assertEqual(result.missing_paths, ["b.txt"])
        source = result.items[0]["source"]
        self.assertEqual(source["approver"], "alice")
        self.assertEqual(source["manifest_version"], "v1")
        self.assertEqual(source["digest"], "digest-a")
        self.assertEqual(result.items[0]["digest"], "digest-a")

    def test_path_and_digest_cannot_come_from_different_approvals(self):
        manifest = {
            "manifest_version": "v1",
            "items": [{"path": "joined.txt", "digest": "correct-digest"}],
        }
        scopes = {"alice": ["**"], "bob": ["**"]}
        approvals = [
            self.signed(
                {
                    "approver": "alice",
                    "manifest_version": "v1",
                    "items": [{"path": "joined.txt", "digest": "wrong-digest"}],
                },
                "alice",
                self.alice_key,
            ),
            self.signed(
                {
                    "approver": "bob",
                    "manifest_version": "v1",
                    "items": [{"path": "other.txt", "digest": "correct-digest"}],
                },
                "bob",
                self.bob_key,
            ),
        ]

        result = reconcile_release(manifest, scopes, approvals, verify_keys=self.keys)

        self.assertEqual(result.releasable_paths, [])
        self.assertEqual(result.missing_paths, ["joined.txt"])
        self.assertIsNone(result.items[0]["source"])
        self.assertTrue(any("digest_mismatch" in error for error in result.items[0]["errors"]))

    def test_manifest_version_is_part_of_binding(self):
        manifest = {
            "manifest_version": "v2",
            "items": [{"path": "a.txt", "digest": "digest-a"}],
        }
        approvals = [
            self.signed(
                {
                    "approver": "alice",
                    "manifest_version": "v1",
                    "items": [{"path": "a.txt", "digest": "digest-a"}],
                },
                "alice",
                self.alice_key,
            )
        ]

        result = reconcile_release(
            manifest, {"alice": ["a.txt"]}, approvals, verify_keys=self.keys
        )

        self.assertEqual(result.releasable_paths, [])
        self.assertIn("manifest_version_mismatch", result.items[0]["errors"])

    def test_empty_scope_approval_is_retained(self):
        approvals = [
            self.signed(
                {"approver": "nobody", "manifest_version": "v1", "items": []},
                "nobody",
                generate_signing_key("1"),
            )
        ]

        result = reconcile_release(
            {"manifest_version": "v1", "items": []},
            {"nobody": []},
            approvals,
        )

        self.assertEqual(len(result.approvals), 1)
        self.assertEqual(result.approvals[0]["approver"], "nobody")
        self.assertTrue(result.approvals[0]["scope_empty"])

    def test_caller_rule_resolves_senior_and_exception_scopes(self):
        rules = [
            {"approver": "alice", "path": "freeze/", "kind": "senior"},
            {"approver": "bob", "path": "freeze/special/", "kind": "exception"},
        ]
        entry = {"path": "freeze/special/x.txt"}

        alice_exception_wins = reconcile_release(
            manifest={"manifest_version": "v", "items": []},
            scopes=rules,
            approvals=[],
            overlap_rule=lambda senior, exception: "exception",
        )
        from signedjson.approvals import evaluate_scope, collect_scope_rules

        scope_rules = collect_scope_rules(rules)
        denied = evaluate_scope(
            "alice", entry, scope_rules, lambda senior, exception: "exception"
        )
        allowed = evaluate_scope(
            "alice", entry, scope_rules, lambda senior, exception: "senior"
        )
        bob_denied = evaluate_scope(
            "bob", entry, scope_rules, lambda senior, exception: "senior"
        )
        bob_allowed = evaluate_scope(
            "bob", entry, scope_rules, lambda senior, exception: "exception"
        )

        self.assertFalse(denied["covered"])
        self.assertTrue(allowed["covered"])
        self.assertFalse(bob_denied["covered"])
        self.assertTrue(bob_allowed["covered"])
        self.assertEqual(alice_exception_wins.total, 0)

    def test_two_overlapping_manifests_and_independent_approval(self):
        manifest_a = {
            "manifest_version": "list-a",
            "items": [
                {"path": "shared.txt", "digest": "shared-d"},
                {"path": "a-only.txt", "digest": "a-d"},
                {"path": "secret.txt", "digest": "secret-d"},
            ],
        }
        manifest_b = {
            "manifest_version": "list-b",
            "items": [
                {"path": "shared.txt", "digest": "shared-d"},
                {"path": "b-only.txt", "digest": "b-d"},
            ],
        }
        scopes = {
            "alice": ["a-only.txt"],
            "bob": ["b-only.txt"],
            "carol": ["shared.txt"],
        }
        cross_scope = self.signed(
            {
                "approver": "alice",
                "items": [
                    {
                        "path": "a-only.txt",
                        "digest": "a-d",
                        "manifest_version": "list-a",
                    },
                    {
                        "path": "b-only.txt",
                        "digest": "b-d",
                        "manifest_version": "list-b",
                    },
                    {
                        "path": "secret.txt",
                        "digest": "secret-d",
                        "manifest_version": "list-a",
                    },
                ],
            },
            "alice",
            self.alice_key,
        )
        bob_approval = self.signed(
            {
                "approver": "bob",
                "manifest_version": "list-b",
                "items": [{"path": "b-only.txt", "digest": "b-d"}],
            },
            "bob",
            self.bob_key,
        )
        carol_a = self.signed(
            {
                "approver": "carol",
                "manifest_version": "list-a",
                "items": [{"path": "shared.txt", "digest": "shared-d"}],
            },
            "carol",
            self.carol_key,
        )
        carol_b = self.signed(
            {
                "approver": "carol",
                "manifest_version": "list-b",
                "items": [{"path": "shared.txt", "digest": "shared-d"}],
            },
            "carol",
            self.carol_key,
        )

        result = reconcile_release(
            manifests=[manifest_a, manifest_b],
            scopes=scopes,
            approvals=[cross_scope, bob_approval, carol_a, carol_b],
            verify_keys=self.keys,
        )

        self.assertEqual(
            sorted(result.releasable_paths),
            ["a-only.txt", "b-only.txt", "shared.txt", "shared.txt"],
        )
        self.assertEqual(result.missing_paths, ["secret.txt"])
        cross_record = result.approvals[0]
        self.assertEqual(
            sorted(item["path"] for item in cross_record.missing_coverage),
            ["b-only.txt", "secret.txt"],
        )
        b_decision = next(
            item for item in result.decisions if item.path == "b-only.txt"
        )
        self.assertEqual(b_decision.source.approver, "bob")
        self.assertEqual(b_decision.source.approval_id, bob_approval["approval_id"] if "approval_id" in bob_approval else b_decision.source.approval_id)
        self.assertTrue(result.approvals[0].signature_valid)

    def test_invalid_signature_does_not_authorize(self):
        manifest = {
            "manifest_version": "v1",
            "items": [{"path": "a.txt", "digest": "digest-a"}],
        }
        approval = sign_approval(
            {
                "approver": "alice",
                "manifest_version": "v1",
                "items": [{"path": "a.txt", "digest": "digest-a"}],
            },
            "alice",
            self.alice_key,
        )
        approval["signatures"]["alice"]["ed25519:1"] = "AAAA"

        result = reconcile_release(
            manifest,
            {"alice": ["a.txt"]},
            [approval],
            verify_keys=self.keys,
        )

        self.assertEqual(result.releasable_paths, [])
        self.assertFalse(result.approvals[0].signature_valid)


if __name__ == "__main__":
    unittest.main()
