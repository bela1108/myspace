# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""Tests for in_toto.diagnostics offline threshold diagnostics."""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from securesystemslib._gpg.exceptions import KeyExpirationError
from securesystemslib.signer import CryptoSigner

import in_toto
from in_toto import diagnostics
from in_toto.models.layout import Layout, Step
from in_toto.models.link import Link
from in_toto.models.metadata import Metablock
from tests.common import SignerStore


class DiagnosticsTest(unittest.TestCase):
    """Shared fixtures for diagnostic tests."""

    @classmethod
    def setUpClass(cls):
        cls.alice = SignerStore.rsa
        cls.alice_pub = SignerStore.rsa_pub
        cls.alice_keyid = cls.alice_pub["keyid"]

        cls.bob = SignerStore.ecdsa
        cls.bob_pub = SignerStore.ecdsa_pub
        cls.bob_keyid = cls.bob_pub["keyid"]

        cls.carol = SignerStore.ed25519
        cls.carol_pub = SignerStore.ed25519_pub
        cls.carol_keyid = cls.carol_pub["keyid"]

        cls.step_name = "package"
        cls.foo_hash = (
            "d65165279105ca6773180500688df4bdc69a2c7b771752f0a46ef120b7fd8ec3"
        )
        cls.bar_hash = (
            "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"
        )

        # A fourth, dynamically generated functionary, so two artifact views
        # can each be attested by two distinct authorized signers.
        cls.dave = CryptoSigner.generate_ed25519()
        dave_key = cls.dave.public_key
        cls.dave_pub = dave_key.to_dict()
        cls.dave_pub["keyid"] = dave_key.keyid
        cls.dave_keyid = dave_key.keyid

    def make_layout(self, threshold=2):
        """Layout with one step, three authorized functionaries."""
        return Layout(
            keys={
                self.alice_keyid: self.alice_pub,
                self.bob_keyid: self.bob_pub,
                self.carol_keyid: self.carol_pub,
            },
            steps=[
                Step(
                    name=self.step_name,
                    pubkeys=[
                        self.alice_keyid,
                        self.bob_keyid,
                        self.carol_keyid,
                    ],
                    threshold=threshold,
                )
            ],
        )

    def make_signed_link(self, signer, materials=None, products=None):
        metadata = Metablock(
            signed=Link(
                name=self.step_name,
                materials=materials or {},
                products=products or {},
            )
        )
        metadata.create_signature(signer)
        return metadata

    def view_a(self):
        """Artifact view of the first executor batch."""
        return (
            {"src/foo.py": {"sha256": self.foo_hash}},
            {"dist/foo.tar.gz": {"sha256": self.foo_hash}},
        )

    def view_b(self):
        """A second, conflicting artifact view."""
        return (
            {"src/foo.py": {"sha256": self.bar_hash}},
            {"dist/foo.tar.gz": {"sha256": self.bar_hash}},
        )


class TestClassifyStepLinks(DiagnosticsTest):
    """Tests for signature/authorization classification."""

    def _make_link(self, signer, materials=None, products=None):
        link = Metablock(
            signed=Link(
                name=self.step_name,
                materials=materials or {},
                products=products or {},
            )
        )
        link.create_signature(signer)
        return link

    def _layout(self, pubkeys, threshold=2):
        keys = {
            self.alice_keyid: self.alice_pub,
            self.bob_keyid: self.bob_pub,
            self.carol_keyid: self.carol_pub,
        }
        return Layout(
            keys=keys,
            steps=[
                Step(name=self.step_name, pubkeys=pubkeys, threshold=threshold)
            ],
        )

    def test_valid_link_classification(self):
        """Authorized, validly signed links are marked valid."""
        link = self._make_link(self.alice)
        layout = self._layout([self.alice_keyid, self.bob_keyid])
        result = diagnostics.classify_step_links(
            layout, self.step_name, {self.alice_keyid: link}
        )
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["status"], diagnostics.STATUS_VALID)
        self.assertEqual(result[0]["main_keyid"], self.alice_keyid)
        self.assertEqual(len(result[0]["view_id"]), 64)

    def test_unauthorized_signature_is_explained(self):
        """Unauthorized signers explain missing evidence."""
        link = self._make_link(self.carol)
        layout = self._layout([self.alice_keyid, self.bob_keyid])
        result = diagnostics.classify_step_links(
            layout, self.step_name, {self.carol_keyid: link}
        )
        self.assertEqual(result[0]["status"], diagnostics.STATUS_UNAUTHORIZED)
        self.assertIsNone(result[0]["main_keyid"])
        self.assertIsNone(result[0]["view_id"])
        self.assertIn("not authorized", result[0]["reason"])

    def test_broken_signature_is_invalid(self):
        """An authorized signer with a broken signature is invalid."""
        link = self._make_link(self.alice)
        link.signed.materials = {"tampered": {"sha256": "ab"}}
        layout = self._layout([self.alice_keyid, self.bob_keyid])
        result = diagnostics.classify_step_links(
            layout, self.step_name, {self.alice_keyid: link}
        )
        self.assertEqual(
            result[0]["status"], diagnostics.STATUS_INVALID_SIGNATURE
        )
        self.assertIsNone(result[0]["view_id"])

    def test_expired_key_is_classified_and_excluded(self):
        """An expired signing key explains missing evidence, no group."""
        link = self._make_link(self.alice)
        layout = self._layout([self.alice_keyid, self.bob_keyid])
        with patch.object(
            link,
            "verify_signature",
            side_effect=KeyExpirationError(
                {"keyid": "x", "creation_time": 0, "validity_period": 1}
            ),
        ):
            result = diagnostics.classify_step_links(
                layout, self.step_name, {self.alice_keyid: link}
            )
        self.assertEqual(result[0]["status"], diagnostics.STATUS_EXPIRED_KEY)
        self.assertIn("expired", result[0]["reason"].lower())
        self.assertIsNone(result[0]["view_id"])

    def test_classifications_sorted_independently_of_input_order(self):
        """Classification order does not depend on input ordering."""
        links = {
            self.carol_keyid: self._make_link(self.carol),
            self.bob_keyid: self._make_link(self.bob),
            self.alice_keyid: self._make_link(self.alice),
        }
        layout = self._layout(
            [self.alice_keyid, self.bob_keyid, self.carol_keyid]
        )
        result = diagnostics.classify_step_links(layout, self.step_name, links)
        self.assertEqual(
            [entry["keyid"] for entry in result], sorted(links.keys())
        )


class TestDiagnoseStepLinks(DiagnosticsTest):
    """Tests for artifact-view grouping and conflict reporting."""

    def _signed_link(self, signer, materials, products):
        link = Metablock(
            signed=Link(
                name=self.step_name, materials=materials, products=products
            )
        )
        link.create_signature(signer)
        return link

    def _layout(self, threshold=2):
        return Layout(
            keys={
                self.alice_keyid: self.alice_pub,
                self.bob_keyid: self.bob_pub,
                self.carol_keyid: self.carol_pub,
                self.dave_keyid: self.dave_pub,
            },
            steps=[
                Step(
                    name=self.step_name,
                    pubkeys=[
                        self.alice_keyid,
                        self.bob_keyid,
                        self.carol_keyid,
                        self.dave_keyid,
                    ],
                    threshold=threshold,
                )
            ],
        )

    def _conflicting_links(self):
        mat_a, prod_a = self.view_a()
        mat_b, prod_b = self.view_b()
        return {
            self.alice_keyid: self._signed_link(self.alice, mat_a, prod_a),
            self.bob_keyid: self._signed_link(self.bob, mat_a, prod_a),
            self.carol_keyid: self._signed_link(self.carol, mat_b, prod_b),
            self.dave_keyid: self._signed_link(self.dave, mat_b, prod_b),
        }

    def test_conflicting_groups_meet_threshold(self):
        """Two qualifying groups yield a conflicting_views verdict."""
        layout = self._layout(threshold=2)
        report = diagnostics.diagnose_step_links(
            layout, self.step_name, self._conflicting_links()
        )
        self.assertEqual(report["verdict"], diagnostics.VERDICT_CONFLICT)
        qualifying = [g for g in report["groups"] if g["threshold_met"]]
        self.assertEqual(len(qualifying), 2)
        self.assertEqual(len(report["conflicts"]), 1)
        for group in report["groups"]:
            self.assertEqual(group["functionary_count"], len(group["signers"]))

    def test_invalid_signature_never_joins_a_group(self):
        """A broken link cannot prop up a group to the threshold."""
        layout = self._layout(threshold=2)
        mat_a, prod_a = self.view_a()
        links = {
            self.alice_keyid: self._signed_link(self.alice, mat_a, prod_a),
            self.bob_keyid: self._signed_link(self.bob, mat_a, prod_a),
        }
        tampered = self._signed_link(self.carol, mat_a, prod_a)
        tampered.signed.products = {"x": {"sha256": "00"}}
        links[self.carol_keyid] = tampered
        report = diagnostics.diagnose_step_links(layout, self.step_name, links)
        self.assertEqual(report["verdict"], diagnostics.VERDICT_CONSISTENT)
        group = report["groups"][0]
        self.assertNotIn(self.carol_keyid, group["signers"])
        statuses = {c["keyid"]: c["status"] for c in report["classifications"]}
        self.assertEqual(
            statuses[self.carol_keyid], diagnostics.STATUS_INVALID_SIGNATURE
        )

    def test_unauthorized_link_cannot_form_second_group(self):
        """Unauthorized evidence cannot create a qualifying group."""
        layout = self._layout(threshold=2)
        mat_a, prod_a = self.view_a()
        mat_b, prod_b = self.view_b()
        # carol is authorized in the layout, so use an unknown key instead.
        unknown = SignerStore.ed25519
        layout = Layout(
            keys={
                self.alice_keyid: self.alice_pub,
                self.bob_keyid: self.bob_pub,
            },
            steps=[
                Step(
                    name=self.step_name,
                    pubkeys=[self.alice_keyid, self.bob_keyid],
                    threshold=2,
                )
            ],
        )
        links = {
            self.alice_keyid: self._signed_link(self.alice, mat_a, prod_a),
            self.bob_keyid: self._signed_link(self.bob, mat_a, prod_a),
            self.carol_keyid: self._signed_link(unknown, mat_b, prod_b),
        }
        report = diagnostics.diagnose_step_links(layout, self.step_name, links)
        self.assertEqual(report["verdict"], diagnostics.VERDICT_CONSISTENT)
        self.assertEqual(len(report["groups"]), 1)
        self.assertEqual(len(report["conflicts"]), 0)

    def test_conflict_reports_minimal_fields_and_signers(self):
        """Conflicts list the minimal differing fields with signers."""
        layout = self._layout(threshold=2)
        report = diagnostics.diagnose_step_links(
            layout, self.step_name, self._conflicting_links()
        )
        conflict = report["conflicts"][0]
        fields = {
            (d["section"], d["field"], d["kind"]) for d in conflict["fields"]
        }
        # view_a vs view_b differ in hashes of the same two artifact paths
        self.assertEqual(
            fields,
            {
                ("materials", "src/foo.py", "hash_mismatch"),
                ("products", "dist/foo.tar.gz", "hash_mismatch"),
            },
        )
        for diff in conflict["fields"]:
            self.assertEqual(diff["algorithms"], ["sha256"])
        all_signers = set()
        for signers in conflict["signers"].values():
            all_signers.update(signers)
        self.assertEqual(
            all_signers,
            {
                self.alice_keyid,
                self.bob_keyid,
                self.carol_keyid,
                self.dave_keyid,
            },
        )

    def test_only_in_one_view_is_reported_as_minimal_field(self):
        """An artifact missing on one side is a minimal conflicting field."""
        layout = self._layout(threshold=2)
        mat_a, prod_a = self.view_a()
        mat_b, prod_b = self.view_b()
        prod_b = dict(prod_b)
        prod_b["dist/extra.txt"] = {"sha256": self.bar_hash}
        links = {
            self.alice_keyid: self._signed_link(self.alice, mat_a, prod_a),
            self.bob_keyid: self._signed_link(self.bob, mat_a, prod_a),
            self.carol_keyid: self._signed_link(self.carol, mat_b, prod_b),
            self.dave_keyid: self._signed_link(self.dave, mat_b, prod_b),
        }
        report = diagnostics.diagnose_step_links(layout, self.step_name, links)
        product_diffs = [
            d
            for d in report["conflicts"][0]["fields"]
            if d["section"] == "products"
        ]
        self.assertIn(
            ("dist/extra.txt", "only_in_group"),
            {(d["field"], d["kind"]) for d in product_diffs},
        )

    def test_insufficient_evidence_verdict(self):
        """No group reaching the threshold explains missing evidence."""
        layout = self._layout(threshold=2)
        mat_a, prod_a = self.view_a()
        mat_b, prod_b = self.view_b()
        links = {
            self.alice_keyid: self._signed_link(self.alice, mat_a, prod_a),
            self.bob_keyid: self._signed_link(self.bob, mat_b, prod_b),
        }
        report = diagnostics.diagnose_step_links(layout, self.step_name, links)
        self.assertEqual(report["verdict"], diagnostics.VERDICT_INSUFFICIENT)
        self.assertEqual(len(report["groups"]), 2)
        self.assertTrue(all(not g["threshold_met"] for g in report["groups"]))
        self.assertEqual(report["conflicts"], [])

    def test_reordering_inputs_gives_identical_report(self):
        """The diagnostic is deterministic under input permutations."""
        layout = self._layout(threshold=2)
        links = self._conflicting_links()
        first = diagnostics.diagnose_step_links(layout, self.step_name, links)
        reordered = dict(reversed(list(links.items())))
        second = diagnostics.diagnose_step_links(
            layout, self.step_name, reordered
        )
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )
        # Group ordering itself must be stable (sorted by view_id).
        self.assertEqual(
            [g["view_id"] for g in first["groups"]],
            [g["view_id"] for g in second["groups"]],
        )

    def test_report_is_json_serializable(self):
        """The report can be embedded into in-toto review tooling as JSON."""
        layout = self._layout(threshold=2)
        report = diagnostics.diagnose_step_links(
            layout, self.step_name, self._conflicting_links()
        )
        encoded = json.dumps(report)
        self.assertEqual(json.loads(encoded), report)


class TestDiagnoseLayoutLinks(DiagnosticsTest):
    """Tests for the layout-level convenience wrapper."""

    def test_report_contains_all_steps_and_metadata(self):
        step = Step(name="release", pubkeys=[], threshold=1)
        layout = Layout(steps=[step])
        report = diagnostics.diagnose_layout_links(layout, {})
        self.assertEqual(report["diagnostic"], diagnostics.DIAGNOSTIC_TYPE)
        self.assertEqual(report["version"], diagnostics.DIAGNOSTIC_VERSION)
        self.assertIn("release", report["steps"])
        self.assertEqual(
            report["steps"]["release"]["verdict"],
            diagnostics.VERDICT_INSUFFICIENT,
        )


class TestDiagnosticsCli(DiagnosticsTest):
    """End-to-end tests for the in-toto-diagnostics CLI."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(dir=os.getcwd())
        self.old_cwd = os.getcwd()
        os.chdir(self.temp_dir)
        self.addCleanup(os.chdir, self.old_cwd)
        self.addCleanup(shutil.rmtree, self.temp_dir)
        self.alice = SignerStore.rsa
        self.alice_pub = SignerStore.rsa_pub
        self.alice_keyid = self.alice_pub["keyid"]
        self.bob = SignerStore.ecdsa
        self.bob_pub = SignerStore.ecdsa_pub
        self.bob_keyid = self.bob_pub["keyid"]

    def _write_link(self, signer, keyid, materials, products):
        link = Metablock(
            signed=Link(name="release", materials=materials, products=products)
        )
        link.create_signature(signer)
        path = in_toto.models.link.FILENAME_FORMAT.format(
            step_name="release", keyid=keyid
        )
        link.dump(path)
        return path

    def test_cli_reports_conflict_with_exit_code_1(self):
        mat_a, prod_a = self.view_a()
        mat_b, prod_b = self.view_b()
        self._write_link(self.alice, self.alice_keyid, mat_a, prod_a)
        self._write_link(self.bob, self.bob_keyid, mat_b, prod_b)
        layout = Layout(
            keys={
                self.alice_keyid: self.alice_pub,
                self.bob_keyid: self.bob_pub,
            },
            steps=[
                Step(
                    name="release",
                    pubkeys=[self.alice_keyid, self.bob_keyid],
                    threshold=1,
                )
            ],
        )
        metablock = Metablock(signed=layout)
        metablock.create_signature(self.alice)
        metablock.dump("root.layout")
        pub_path = os.path.join(self.old_cwd, "tests", "pems", "rsa_public.pem")
        script = "-m in_toto.in_toto_diagnostics"
        env = dict(os.environ, PYTHONPATH=self.old_cwd)
        proc = subprocess.run(  # noqa: S603
            [
                sys.executable,
                *script.split(),
                "-l",
                "root.layout",
                "-k",
                pub_path,
                "-o",
                "-",
            ],
            capture_output=True,
            text=True,
            check=False,
            env=env,
        )
        self.assertEqual(proc.returncode, 1, proc.stderr)
        report = json.loads(proc.stdout)
        self.assertEqual(
            report["steps"]["release"]["verdict"], diagnostics.VERDICT_CONFLICT
        )

    def test_cli_writes_report_file(self):
        self._write_link(self.alice, self.alice_keyid, *self.view_a())
        layout = Layout(
            keys={self.alice_keyid: self.alice_pub},
            steps=[
                Step(name="release", pubkeys=[self.alice_keyid], threshold=1)
            ],
        )
        metablock = Metablock(signed=layout)
        metablock.create_signature(self.alice)
        metablock.dump("root.layout")
        pub_path = os.path.join(self.old_cwd, "tests", "pems", "rsa_public.pem")
        script = "-m in_toto.in_toto_diagnostics"
        env = dict(os.environ, PYTHONPATH=self.old_cwd)
        proc = subprocess.run(  # noqa: S603
            [
                sys.executable,
                *script.split(),
                "-l",
                "root.layout",
                "-k",
                pub_path,
                "-o",
                "report.json",
            ],
            capture_output=True,
            text=True,
            check=False,
            env=env,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        with open("report.json", encoding="utf8") as fp:
            report = json.load(fp)
        self.assertEqual(
            report["steps"]["release"]["verdict"],
            diagnostics.VERDICT_CONSISTENT,
        )


if __name__ == "__main__":
    unittest.main()
