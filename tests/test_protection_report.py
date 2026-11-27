"""Offline protection reports over the small public fixtures."""

import io
import json
import struct
import subprocess
import sys
import unittest
import zipfile
from pathlib import Path

from msoffcrypto.report import (
    inspect_file,
    render_comparison,
    render_json,
    render_markdown,
    render_text,
)

TEST_DIR = Path(__file__).resolve().parent
INPUT_DIR = TEST_DIR / "inputs"
OUTPUT_DIR = TEST_DIR / "outputs"
ROOT_DIR = TEST_DIR.parent


class ProtectionReportTest(unittest.TestCase):
    def test_legacy_formats_record_declaration_and_source(self):
        cases = (
            ("rc4cryptoapi_password.doc", "doc97", "FibBase.fEncrypted"),
            ("rc4cryptoapi_password.xls", "xls97", "FilePass"),
            (
                "rc4cryptoapi_password.ppt",
                "ppt97",
                "UserEditAtom.encryptSessionPersistIdRef",
            ),
        )
        for filename, format_name, field in cases:
            with self.subTest(filename=filename):
                report = inspect_file(INPUT_DIR / filename)
                self.assertEqual(report["container_type"], "ole")
                self.assertEqual(report["format"], format_name)
                self.assertTrue(report["protection"]["declared"])
                self.assertEqual(report["protection"]["method"], "rc4_cryptoapi")
                self.assertIn(field, report["protection"]["source"])
                self.assertEqual(report["materials"]["status"], "complete")
                self.assertEqual(report["conclusion"]["code"], "protection_declared")

    def test_new_format_keeps_ole_container_and_encryption_source(self):
        report = inspect_file(INPUT_DIR / "example_password.docx")
        self.assertEqual(report["container_type"], "ole")
        self.assertEqual(report["format"], "ooxml")
        self.assertTrue(report["protection"]["declared"])
        self.assertEqual(report["protection"]["method"], "agile")
        self.assertIn("EncryptionInfo", report["protection"]["source"])
        self.assertEqual(report["materials"]["status"], "complete")
        self.assertEqual(report["conclusion"]["code"], "protection_declared")

    def test_new_format_missing_material_is_partial(self):
        source = OUTPUT_DIR / "example.docx"
        partial = io.BytesIO()
        with zipfile.ZipFile(source) as incoming:
            with zipfile.ZipFile(partial, "w", zipfile.ZIP_DEFLATED) as outgoing:
                for info in incoming.infolist():
                    outgoing.writestr(info, incoming.read(info.filename))
                outgoing.writestr("EncryptionInfo", struct.pack("<HH", 4, 4) + b"\x00" * 12)

        report = inspect_file(partial.getvalue(), filename="partial.docx")
        self.assertEqual(report["container_type"], "zip")
        self.assertEqual(report["format"], "ooxml")
        self.assertTrue(report["protection"]["declared"])
        self.assertEqual(report["materials"]["status"], "partial")
        self.assertEqual(report["materials"]["missing"], ["EncryptedPackage"])
        self.assertEqual(report["conclusion"]["code"], "protection_incomplete")

    def test_normal_unprotected_files(self):
        cases = (
            ("plain.doc", "ole", "doc97"),
            ("plain.xls", "ole", "xls97"),
            ("plain.ppt", "ole", "ppt97"),
        )
        for filename, container, format_name in cases:
            with self.subTest(filename=filename):
                report = inspect_file(INPUT_DIR / filename)
                self.assertEqual(report["container_type"], container)
                self.assertEqual(report["format"], format_name)
                self.assertFalse(report["protection"]["declared"])
                self.assertEqual(report["conclusion"]["code"], "not_protected")

        report = inspect_file(OUTPUT_DIR / "example.docx")
        self.assertEqual(report["container_type"], "zip")
        self.assertEqual(report["format"], "ooxml")
        self.assertFalse(report["protection"]["declared"])
        self.assertEqual(report["materials"]["status"], "not_required")
        self.assertEqual(report["conclusion"]["code"], "not_protected")

    def test_reports_are_comparable_and_keep_input_position(self):
        old = inspect_file(INPUT_DIR / "rc4cryptoapi_password.doc")
        new = inspect_file(INPUT_DIR / "example_password.docx")
        self.assertEqual(set(old), set(new))
        self.assertEqual(set(old["protection"]), set(new["protection"]))
        self.assertEqual(set(old["materials"]), set(new["materials"]))
        self.assertEqual(set(old["conclusion"]), set(new["conclusion"]))

        parsed = json.loads(render_json(old))
        self.assertEqual(parsed["conclusion"], old["conclusion"])
        comparison = render_comparison((old, new))
        self.assertIn("rc4cryptoapi_password.doc", comparison)
        self.assertIn("example_password.docx", comparison)

        with open(INPUT_DIR / "rc4cryptoapi_password.doc", "rb") as handle:
            handle.seek(7)
            inspect_file(handle)
            self.assertEqual(handle.tell(), 7)

    def test_unknown_fields_remain_readable(self):
        unknown = inspect_file(b"not an Office file", filename="unknown.bin")
        self.assertEqual(unknown["container_type"], "unknown")
        self.assertEqual(unknown["conclusion"]["code"], "unknown")

        report = {
            "container_type": "future-container",
            "future_field": {"value": 1},
        }
        text = render_text(report)
        markdown = render_markdown(report)
        self.assertIn("future_field", text)
        self.assertIn("future_field", markdown)
        self.assertIn("unknown", text)

    def test_cli_inspect_returns_json(self):
        process = subprocess.run(
            [
                sys.executable,
                "-m",
                "msoffcrypto",
                "--inspect",
                str(INPUT_DIR / "rc4cryptoapi_password.xls"),
            ],
            cwd=ROOT_DIR,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(process.returncode, 0, process.stderr)
        report = json.loads(process.stdout)
        self.assertEqual(report["format"], "xls97")
        self.assertEqual(report["conclusion"]["code"], "protection_declared")


if __name__ == "__main__":
    unittest.main()
