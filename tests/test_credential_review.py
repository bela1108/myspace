# SPDX-License-Identifier: Apache-2.0

"""Tests for offline credential-reference approval review."""

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from in_toto.models.layout import Layout, Step, SUBLAYOUT_LINK_DIR_FORMAT
from in_toto.models.link import FILENAME_FORMAT, Link
from in_toto.models.metadata import Metablock
from in_toto.reviewlib import (
    review_credential_approvals,
    review_layout,
    review_link,
    review_summary_link,
)
from in_toto.verifylib import get_summary_link
from tests.common import SignerStore

PEMS = Path(__file__).parent / "pems"


class CredentialReviewTest(unittest.TestCase):
    def setUp(self):
        self.signer = SignerStore.rsa
        self.public_key = SignerStore.rsa_pub
        self.keyid = self.public_key["keyid"]
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def _signed_link_metadata(self, **link_kwargs):
        metadata = Metablock(signed=Link(**link_kwargs))
        metadata.create_signature(self.signer)
        return metadata

    def _dump_link(self, metadata, step_name, directory=None, keyid=None):
        directory = directory or self.dir
        keyid = keyid or self.keyid
        path = os.path.join(
            directory, FILENAME_FORMAT.format(step_name=step_name, keyid=keyid)
        )
        metadata.dump(path)
        return path

    def _write_approvals(self, records):
        path = os.path.join(self.dir, "approvals.json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump({"approvals": records}, handle)
        return path

    def test_absent_and_empty_link_fields_are_distinct(self):
        legacy = Link(name="package")
        zero = Link(name="package", credential_refs=[])

        self.assertNotIn("credential_refs", legacy.to_dict())
        self.assertIsNone(legacy.credential_refs)
        self.assertEqual([], zero.credential_refs)
        self.assertEqual([], zero.to_dict()["credential_refs"])

        legacy_report = review_link(legacy, [])
        zero_report = review_link(zero, [])

        self.assertFalse(legacy_report.approved)
        self.assertEqual("not_collected", legacy_report.findings[0].status)
        self.assertEqual("legacy", legacy_report.findings[0].status)
        self.assertTrue(zero_report.approved)
        self.assertEqual("zero_references", zero_report.findings[0].status)
        self.assertEqual("empty", zero_report.findings[0].status)

    def test_signed_link_reports_every_approval_scope_and_location(self):
        approvals_path = self._write_approvals(
            [
                {
                    "id": "security-scope",
                    "step": "package",
                    "credential_ref": "fake://release-repo-readonly",
                    "scopes": ["release-repo:read"],
                    "approver": "security@example.invalid",
                },
                {
                    "id": "package-scope",
                    "step": "package",
                    "ref": "fake://release-repo-readonly",
                    "authorization_scopes": ["packages:read"],
                    "approver": "packages@example.invalid",
                },
            ]
        )
        metadata = self._signed_link_metadata(
            name="package",
            credential_refs=[
                {
                    "ref": "fake://release-repo-readonly",
                    "purpose": "read release repository",
                }
            ],
        )
        link_path = self._dump_link(metadata, "package")

        report = review_link(
            metadata,
            approvals_path,
            path=link_path,
            verification_key=self.public_key,
        )

        self.assertTrue(report.approved, report)
        finding = report.findings[0]
        self.assertEqual("approved", finding.status)
        self.assertTrue(finding.signature_verified)
        self.assertEqual(2, len(finding.approvals))
        self.assertIn("release-repo:read", finding.authorized_scopes)
        self.assertIn("packages:read", finding.authorized_scopes)
        self.assertEqual(
            [
                f"{approvals_path}#/approvals/0",
                f"{approvals_path}#/approvals/1",
            ],
            finding.approval_locations,
        )
        self.assertIn(link_path, finding.credential_location)
        self.assertIn("#/signed/credential_refs/0/ref", finding.credential_location)
        json.dumps(report)

    def test_unapproved_reference_is_blocking(self):
        metadata = self._signed_link_metadata(
            name="package",
            credential_refs=["fake://unapproved-reference"],
        )
        report = review_link(
            metadata,
            {"approvals": []},
            verification_key=self.public_key,
        )
        self.assertFalse(report.approved)
        self.assertEqual("unapproved", report.findings[0].status)
        self.assertEqual("missing_approval", report.findings[0].status)

    def test_invalid_signature_is_not_reviewed(self):
        metadata = self._signed_link_metadata(
            name="package", credential_refs=["fake://ref"]
        )
        other_key = SignerStore.ecdsa_pub
        report = review_link(
            metadata,
            [{"ref": "fake://ref"}],
            verification_key=other_key,
        )
        self.assertFalse(report.approved)
        self.assertEqual("invalid_signature", report.findings[0].status)

    def test_summary_only_names_missing_signed_attestation(self):
        report = review_summary_link(
            step="package", keyid=self.keyid, link_path=self.dir
        )
        finding = report.findings[0]

        self.assertFalse(report.approved)
        self.assertEqual("missing_attestation", finding.status)
        self.assertEqual("summary_only", finding.status)
        self.assertEqual("signed-link", finding.required_attestation["type"])
        self.assertIn(
            FILENAME_FORMAT.format(step_name="package", keyid=self.keyid),
            finding.required_attestation["filename"],
        )
        self.assertIn("signed original Link", finding.reason)
        json.dumps(report)

    def test_same_named_sublayout_steps_are_separately_located(self):
        approvals_path = self._write_approvals(
            [
                {
                    "id": "only-release-package",
                    "step_path": "package/package",
                    "credential_ref": "fake://release-credential",
                    "scope": "release:read",
                }
            ]
        )

        root_steps = []
        for outer_name in ("package", "verify"):
            root_steps.append(
                Step(name=outer_name, pubkeys=[self.keyid], threshold=1)
            )

            sublayout = Layout(
                keys={self.keyid: self.public_key},
                steps=[Step(name="package", pubkeys=[self.keyid], threshold=1)],
            )
            outer_metadata = Metablock(signed=sublayout)
            outer_metadata.create_signature(self.signer)
            self._dump_link(outer_metadata, outer_name)

            nested_dir = os.path.join(
                self.dir,
                SUBLAYOUT_LINK_DIR_FORMAT.format(
                    name=outer_name, keyid=self.keyid
                ),
            )
            os.makedirs(nested_dir, exist_ok=True)
            nested_link = self._signed_link_metadata(
                name="package",
                credential_refs=[
                    {"ref": "fake://release-credential", "purpose": "read"}
                ],
            )
            self._dump_link(nested_link, "package", directory=nested_dir)

        root_layout = Layout(
            keys={self.keyid: self.public_key}, steps=root_steps
        )
        root_metadata = Metablock(signed=root_layout)
        root_metadata.create_signature(self.signer)

        with patch("in_toto.verifylib.run_all_inspections") as inspections:
            report = review_layout(
                root_metadata,
                approvals_path,
                link_dir=self.dir,
                layout_key_dict={self.keyid: self.public_key},
            )

        inspections.assert_not_called()
        by_path = {
            finding.step_path: finding
            for finding in report.findings
            if finding.get("credential_ref")
        }
        self.assertEqual(
            {"package/package", "verify/package"}, set(by_path)
        )
        self.assertTrue(by_path["package/package"].approved)
        self.assertFalse(by_path["verify/package"].approved)
        self.assertIn(
            os.path.join("package." + self.keyid[:8], "package."),
            by_path["package/package"].credential_location,
        )
        self.assertIn(
            os.path.join("verify." + self.keyid[:8], "package."),
            by_path["verify/package"].credential_location,
        )

    def test_dispatcher_accepts_link_metadata(self):
        metadata = self._signed_link_metadata(
            name="package", credential_refs=[]
        )
        report = review_credential_approvals(metadata, [])
        self.assertTrue(report.approved)

    def test_generated_summary_link_is_not_treated_as_legacy_link(self):
        summary = get_summary_link(Layout(steps=[]), {}, "package")
        report = review_link(summary, [])
        self.assertEqual("missing_attestation", report.findings[0].status)
        self.assertEqual("summary_only", report.findings[0].status)


if __name__ == "__main__":
    unittest.main()
