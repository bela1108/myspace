# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""
<Program Name>
  test_provenance.py

<Author>
  The in-toto contributors

<Started>
  Nov 23, 2026

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Test cases for in_toto/provenance.py forensic provenance reconciliation.

"""

import unittest

import securesystemslib.exceptions

from in_toto.models.link import Link
from in_toto.models.metadata import Metablock
from in_toto.provenance import (
    EvidencePackage,
    PackageProvenance,
    ProvenanceStatus,
    Receipt,
    review_packages,
)
from tests.common import SignerStore

PACKAGE_HASHES = {"sha256": "ab" * 32}
OTHER_HASHES = {"sha256": "cd" * 32}
UNKNOWN_HASHES = {"sha256": "ef" * 32}

QUARANTINE_OFFICER = "quarantine-officer-1"
OTHER_PERSON = "field-technician-7"


def _build_links():
    """Links for a supply chain in which an incident package was re-packaged
    after quarantine, producing the same digest twice."""
    return [
        Link(
            name="build",
            materials={},
            products={"pkg.tar.gz": PACKAGE_HASHES},
        ),
        Link(
            name="repackage",
            materials={"pkg.tar.gz": PACKAGE_HASHES},
            products={"pkg-repacked.tar.gz": PACKAGE_HASHES},
        ),
        Link(
            name="inspect",
            materials={"pkg-repacked.tar.gz": PACKAGE_HASHES},
            products={"report.txt": OTHER_HASHES},
        ),
    ]


class TestProvenanceReconciliation(unittest.TestCase):
    """Tests for review_packages, the forensic review entry point."""

    def test_same_hash_packages_stay_separate(self):
        """Two same-hash evidence entries each get their own provenance, and
        only the one signed for by quarantine personnel is conclusive."""
        packages = [
            EvidencePackage(
                package_id="evidence-1",
                hashes=PACKAGE_HASHES,
                receipt_id="receipt-1",
            ),
            EvidencePackage(
                package_id="evidence-2",
                hashes=PACKAGE_HASHES,
                receipt_id="receipt-2",
            ),
        ]
        receipts = [
            Receipt(
                receipt_id="receipt-1",
                signer=QUARANTINE_OFFICER,
                hashes=PACKAGE_HASHES,
            ),
            Receipt(
                receipt_id="receipt-2",
                signer=OTHER_PERSON,
                hashes=PACKAGE_HASHES,
            ),
        ]

        results = review_packages(
            packages, _build_links(), receipts, [QUARANTINE_OFFICER]
        )

        self.assertEqual(len(results), 2)
        self.assertTrue(
            all(isinstance(result, PackageProvenance) for result in results)
        )

        by_id = {result.package_id: result for result in results}

        # Only the package actually signed for by quarantine personnel may
        # yield a provenance conclusion.
        conclusive = by_id["evidence-1"]
        self.assertEqual(conclusive.status, ProvenanceStatus.CONCLUSIVE)
        self.assertTrue(conclusive.is_conclusive)
        self.assertIsNotNone(conclusive.conclusion)
        self.assertIn(QUARANTINE_OFFICER, conclusive.conclusion)

        other = by_id["evidence-2"]
        self.assertEqual(
            other.status, ProvenanceStatus.RECEIPT_NOT_QUARANTINE
        )
        self.assertFalse(other.is_conclusive)
        self.assertIsNone(other.conclusion)

        # Both entries see the same attested build steps, recorded
        # separately per occurrence of the identical file.
        for result in results:
            self.assertEqual(
                {(build.step, build.product_path) for build in result.builds},
                {
                    ("build", "pkg.tar.gz"),
                    ("repackage", "pkg-repacked.tar.gz"),
                },
            )
            self.assertEqual(
                {
                    (transfer.step, transfer.material_path)
                    for transfer in result.transfers
                },
                {
                    ("repackage", "pkg.tar.gz"),
                    ("inspect", "pkg-repacked.tar.gz"),
                },
            )

    def test_missing_receipt(self):
        """A built package without a receipt is missing-receipt, not
        missing-build-step."""
        packages = [
            EvidencePackage(package_id="evidence-1", hashes=PACKAGE_HASHES)
        ]

        results = review_packages(
            packages, _build_links(), [], [QUARANTINE_OFFICER]
        )

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, ProvenanceStatus.MISSING_RECEIPT)
        self.assertIsNone(results[0].receipt)
        self.assertFalse(results[0].is_conclusive)

    def test_unknown_receipt_reference_is_missing_receipt(self):
        """A dangling receipt reference counts as a missing receipt."""
        packages = [
            EvidencePackage(
                package_id="evidence-1",
                hashes=PACKAGE_HASHES,
                receipt_id="no-such-receipt",
            )
        ]

        results = review_packages(
            packages, _build_links(), [], [QUARANTINE_OFFICER]
        )

        self.assertEqual(results[0].status, ProvenanceStatus.MISSING_RECEIPT)

    def test_missing_build_step(self):
        """A received package with no attested build step is
        missing-build-step, even if quarantine personnel signed for it."""
        packages = [
            EvidencePackage(
                package_id="evidence-1",
                hashes=UNKNOWN_HASHES,
                receipt_id="receipt-1",
            )
        ]
        receipts = [
            Receipt(
                receipt_id="receipt-1",
                signer=QUARANTINE_OFFICER,
                hashes=UNKNOWN_HASHES,
            )
        ]

        results = review_packages(
            packages, _build_links(), receipts, [QUARANTINE_OFFICER]
        )

        self.assertEqual(
            results[0].status, ProvenanceStatus.MISSING_BUILD_STEP
        )
        self.assertEqual(results[0].builds, [])
        self.assertFalse(results[0].is_conclusive)

    def test_missing_receipt_and_build_step(self):
        """A package with neither receipt nor build step is reported as
        missing both."""
        packages = [
            EvidencePackage(package_id="evidence-1", hashes=UNKNOWN_HASHES)
        ]

        results = review_packages(
            packages, _build_links(), [], [QUARANTINE_OFFICER]
        )

        self.assertEqual(
            results[0].status,
            ProvenanceStatus.MISSING_RECEIPT_AND_BUILD_STEP,
        )

    def test_receipt_hash_mismatch(self):
        """A receipt recording different hashes cannot back a conclusion."""
        packages = [
            EvidencePackage(
                package_id="evidence-1",
                hashes=PACKAGE_HASHES,
                receipt_id="receipt-1",
            )
        ]
        receipts = [
            Receipt(
                receipt_id="receipt-1",
                signer=QUARANTINE_OFFICER,
                hashes=OTHER_HASHES,
            )
        ]

        results = review_packages(
            packages, _build_links(), receipts, [QUARANTINE_OFFICER]
        )

        self.assertEqual(
            results[0].status, ProvenanceStatus.RECEIPT_HASH_MISMATCH
        )
        self.assertFalse(results[0].is_conclusive)

    def test_metablock_links_carry_functionary_identities(self):
        """Step identities include the keyids of link signers when
        Metablocks are passed."""
        metablock = Metablock(
            signed=Link(
                name="build",
                materials={},
                products={"pkg.tar.gz": PACKAGE_HASHES},
            )
        )
        metablock.create_signature(SignerStore.rsa)

        packages = [
            EvidencePackage(
                package_id="evidence-1",
                hashes=PACKAGE_HASHES,
                receipt_id="receipt-1",
            )
        ]
        receipts = [
            Receipt(
                receipt_id="receipt-1",
                signer=QUARANTINE_OFFICER,
                hashes=PACKAGE_HASHES,
            )
        ]

        results = review_packages(
            packages, [metablock], receipts, [QUARANTINE_OFFICER]
        )

        self.assertEqual(results[0].status, ProvenanceStatus.CONCLUSIVE)
        self.assertEqual(
            results[0].builds[0].functionaries,
            [SignerStore.rsa_pub["keyid"]],
        )

    def test_bad_arguments_raise_format_error(self):
        """Malformed arguments are rejected."""
        with self.assertRaises(securesystemslib.exceptions.FormatError):
            EvidencePackage(package_id="evidence-1", hashes={"sha256": "zz"})

        with self.assertRaises(securesystemslib.exceptions.FormatError):
            Receipt(receipt_id="receipt-1", signer=1, hashes=PACKAGE_HASHES)

        with self.assertRaises(securesystemslib.exceptions.FormatError):
            review_packages(
                ["not-a-package"], _build_links(), [], [QUARANTINE_OFFICER]
            )

        with self.assertRaises(securesystemslib.exceptions.FormatError):
            review_packages([], ["not-a-link"], [], [QUARANTINE_OFFICER])


if __name__ == "__main__":
    unittest.main()
