# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""Tests for read-only parameter substitution/link comparison audits."""

from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from in_toto.in_toto_compare_links import run as run_compare_cli
from in_toto.models.link import Link
from in_toto.models.metadata import Metablock
from in_toto.parameter_audit import audit_links, normalize_command
from tests.common import PEMS, SignerStore

MATERIAL_DIGEST = "a" * 64
PRODUCT_DIGEST = "b" * 64
MATERIALS = {"materials/input.txt": {"sha256": MATERIAL_DIGEST}}
PRODUCTS = {"products/output.bin": {"sha256": PRODUCT_DIGEST}}
POLICY = {
    "command_aliases": {
        "--source": "--input",
        "--target": "--output",
        "--in": "--input",
        "--out": "--output",
        "--input": "--input",
        "--output": "--output",
    },
    "template_values": {
        "materials/input.txt": "{input}",
        "products/output.bin": "{output}",
    },
}


def signed_link(
    command,
    *,
    name="build-package",
    materials=None,
    products=None,
):
    link = Link(
        name=name,
        command=command,
        materials=MATERIALS if materials is None else materials,
        products=PRODUCTS if products is None else products,
        byproducts={"return-value": 0},
        environment={},
    )
    metadata = Metablock(signed=link)
    metadata.create_signature(SignerStore.ed25519)
    return metadata


class ParameterAuditTests(unittest.TestCase):
    def test_provably_equivalent_with_different_parameter_names(self):
        left = signed_link(
            [
                "python3",
                "build.py",
                "--source",
                "materials/input.txt",
                "--target",
                "products/output.bin",
            ]
        )
        right = signed_link(
            [
                "python3",
                "build.py",
                "--in",
                "materials/input.txt",
                "--out",
                "products/output.bin",
            ]
        )

        report = audit_links(
            left,
            right,
            verification_keys=[SignerStore.ed25519_pub],
            policy=POLICY,
        )

        self.assertEqual(report["verdict"], "proven_equivalent")
        self.assertTrue(report["equivalent"])
        self.assertEqual(report["primary_reason"], "equivalent")
        command = report["checks"]["normalized_command"]
        self.assertTrue(command["match"])
        self.assertTrue(command["template_match"])
        self.assertEqual(
            command["left_normalized"], command["right_normalized"]
        )
        self.assertEqual(
            command["left_template"],
            [
                "python3",
                "build.py",
                "--input",
                "{input}",
                "--output",
                "{output}",
            ],
        )
        self.assertTrue(report["checks"]["materials"]["match"])
        self.assertTrue(report["checks"]["products"]["match"])
        self.assertTrue(report["checks"]["step_identity"]["name_match"])
        self.assertTrue(report["checks"]["signatures"]["proven"])

    def test_placeholder_names_are_renamed_without_mutation(self):
        command = ["build", "{SOURCE}", "--out={TARGET}"]
        normalized = normalize_command(
            command,
            parameter_aliases={"SOURCE": "INPUT", "TARGET": "OUTPUT"},
            parameters={"INPUT": "input.txt", "OUTPUT": "out.bin"},
        )

        self.assertEqual(normalized, ["build", "input.txt", "--out=out.bin"])
        self.assertEqual(
            command, ["build", "{SOURCE}", "--out={TARGET}"]
        )

    def test_audit_does_not_mutate_signed_metadata(self):
        left = signed_link(["build", "--source", "materials/input.txt"])
        right = signed_link(["build", "--in", "materials/input.txt"])
        left_before = copy.deepcopy(left.to_dict())
        right_before = copy.deepcopy(right.to_dict())

        audit_links(
            left,
            right,
            verification_keys=[SignerStore.ed25519_pub],
            policy=POLICY,
        )

        self.assertEqual(left.to_dict(), left_before)
        self.assertEqual(right.to_dict(), right_before)

    def test_different_command_is_not_masked_by_equal_products(self):
        left = signed_link(["build.py", "--input", "materials/input.txt"])
        right = signed_link(
            ["build_debug.py", "--input", "materials/input.txt", "--debug"]
        )

        report = audit_links(
            left,
            right,
            verification_keys=[SignerStore.ed25519_pub],
            policy=POLICY,
        )

        self.assertFalse(report["equivalent"])
        self.assertEqual(report["primary_reason"], "command_mismatch")
        self.assertFalse(
            report["checks"]["normalized_command"]["match"]
        )
        self.assertTrue(report["checks"]["products"]["match"])
        codes = {item["code"] for item in report["findings"]}
        self.assertIn("COMMAND_MISMATCH", codes)

    def test_missing_materials_are_not_masked_by_equal_products(self):
        left = signed_link(["build.py", "--input", "materials/input.txt"])
        right = signed_link(
            ["build.py", "--input", "materials/input.txt"], materials={}
        )

        report = audit_links(
            left,
            right,
            verification_keys=[SignerStore.ed25519_pub],
            policy=POLICY,
        )

        self.assertFalse(report["equivalent"])
        self.assertEqual(report["primary_reason"], "missing_materials")
        materials = report["checks"]["materials"]
        self.assertFalse(materials["complete"])
        self.assertFalse(materials["match"])
        self.assertEqual(materials["missing_on_right"], ["materials/input.txt"])
        self.assertTrue(report["checks"]["products"]["match"])
        codes = {item["code"] for item in report["findings"]}
        self.assertIn("MATERIAL_PROVENANCE_MISSING", codes)

    def test_step_identity_mismatch(self):
        left = signed_link(["build.py"], name="build-package")
        right = signed_link(["build.py"], name="scan-package")

        report = audit_links(
            left,
            right,
            verification_keys=[SignerStore.ed25519_pub],
        )

        self.assertFalse(report["equivalent"])
        self.assertEqual(report["primary_reason"], "step_identity_mismatch")
        self.assertFalse(report["checks"]["step_identity"]["name_match"])

    def test_untrusted_signature_is_not_proven(self):
        left = signed_link(["build.py"])
        right = signed_link(["build.py"])

        report = audit_links(
            left,
            right,
            verification_keys=[SignerStore.rsa_pub],
        )

        self.assertFalse(report["equivalent"])
        self.assertEqual(report["primary_reason"], "signature_unverified")
        self.assertFalse(report["checks"]["signatures"]["proven"])

    def test_cli_writes_report_and_returns_verification_status(self):
        left = signed_link(["build.py", "--source", "materials/input.txt"])
        right = signed_link(["build.py", "--in", "materials/input.txt"])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            left_path = root / "left.link"
            right_path = root / "right.link"
            config_path = root / "policy.json"
            report_path = root / "report.json"
            left.dump(str(left_path))
            right.dump(str(right_path))
            config_path.write_text(json.dumps(POLICY), encoding="utf-8")

            report, exit_code = run_compare_cli(
                [
                    "--left",
                    str(left_path),
                    "--right",
                    str(right_path),
                    "--verification-key",
                    str(PEMS / "ed25519_public.pem"),
                    "--config",
                    str(config_path),
                    "--report",
                    str(report_path),
                    "--quiet",
                ]
            )

            self.assertEqual(exit_code, 0)
            self.assertTrue(report["equivalent"])
            self.assertTrue(json.loads(report_path.read_text())["equivalent"])


if __name__ == "__main__":
    unittest.main()
