"""Evidence-oriented comparison tests using authorized synthetic OOXML files."""

import io
import json
import unittest
import zipfile

from msoffcrypto import compare_office_files
from msoffcrypto.format.ooxml import OOXMLFile


PASSWORD = "Comparison-Password-17"
ORIGINAL_TEXT = "synthetic evidence marker: original"
MODIFIED_TEXT = "synthetic evidence marker: modified"

CONTENT_TYPES = b"""<?xml version="1.0" encoding="UTF-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>
"""

ROOT_RELS = b"""<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>
"""


def _document_xml(text):
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        "<w:body><w:p><w:r><w:t>{}</w:t></w:r></w:p></w:body>"
        "</w:document>"
    ).format(text).encode("utf-8")


def _plain_docx(text):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_STORED) as package:
        package.writestr("[Content_Types].xml", CONTENT_TYPES)
        package.writestr("_rels/.rels", ROOT_RELS)
        package.writestr("word/document.xml", _document_xml(text))
        package.writestr("word/media/padding.bin", b"\0" * 5000)
    return output.getvalue()


def _encrypted_docx(plaintext, password=PASSWORD):
    office_file = OOXMLFile(io.BytesIO(plaintext))
    output = io.BytesIO()
    office_file.encrypt(password, output)
    return output.getvalue()


def _part(report, side, location):
    for part in report["verified_plaintext_identity"][side]["parts"]:
        if part["location"] == location:
            return part
    raise AssertionError("missing part: {}".format(location))


class ComparisonReportTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original_plain = _plain_docx(ORIGINAL_TEXT)
        cls.reencrypted_left = _encrypted_docx(cls.original_plain)
        cls.reencrypted_right = _encrypted_docx(cls.original_plain)
        cls.modified_right = _encrypted_docx(_plain_docx(MODIFIED_TEXT))

    def assert_redacted(self, report):
        serialized = json.dumps(report, ensure_ascii=True, sort_keys=True)
        self.assertNotIn(PASSWORD, serialized)
        self.assertNotIn(ORIGINAL_TEXT, serialized)
        self.assertNotIn(MODIFIED_TEXT, serialized)

    def test_same_plaintext_after_reencryption(self):
        report = compare_office_files(
            self.reencrypted_left,
            self.reencrypted_right,
            password=PASSWORD,
        )

        self.assertEqual(
            report["conclusion"]["code"],
            "same_plaintext_encryption_changed",
        )
        self.assertTrue(
            report["verified_plaintext_identity"]["comparison"][
                "parts_identical"
            ]
        )
        self.assertTrue(
            report["verified_plaintext_identity"]["comparison"][
                "package_sha256_identical"
            ]
        )

        public = report["public_header"]["comparison"]
        self.assertFalse(public["same_file_sha256"])
        self.assertFalse(public["same_header_sha256"])
        self.assertFalse(public["same_encryption_attributes"])
        self.assertFalse(public["same_encrypted_payload_sha256"])
        self.assertTrue(public["changed_attribute_paths"])
        self.assertEqual(
            report["credential_unavailable"]["any"],
            False,
        )

        left_document = _part(report, "left", "zip:word/document.xml")
        right_document = _part(report, "right", "zip:word/document.xml")
        self.assertEqual(left_document["sha256"], right_document["sha256"])
        self.assertIn(
            "ole:EncryptionInfo",
            [
                "{}:{}".format(
                    item["trace"]["container"], item["trace"]["stream"]
                )
                for item in report["public_header"]["left"]["container_parts"]
            ],
        )
        self.assert_redacted(report)

    def test_modified_plaintext_is_reported_per_part(self):
        report = compare_office_files(
            self.reencrypted_left,
            self.modified_right,
            password=PASSWORD,
        )

        self.assertEqual(report["conclusion"]["code"], "different_plaintext")
        comparison = report["verified_plaintext_identity"]["comparison"]
        self.assertFalse(comparison["parts_identical"])
        changed_locations = {
            part["location"] for part in comparison["changed_parts"]
        }
        self.assertIn("zip:word/document.xml", changed_locations)
        self.assertTrue(
            all(
                part["left"]["sha256"] != part["right"]["sha256"]
                for part in comparison["changed_parts"]
            )
        )
        self.assert_redacted(report)

    def test_missing_password_leaves_plaintext_unverified(self):
        report = compare_office_files(
            self.reencrypted_left,
            self.reencrypted_right,
        )

        self.assertEqual(report["conclusion"]["code"], "plaintext_unverified")
        self.assertIsNone(
            report["verified_plaintext_identity"]["comparison"]
        )
        self.assertTrue(report["credential_unavailable"]["any"])
        for side in ("left", "right"):
            identity = report["verified_plaintext_identity"][side]
            unavailable = report["credential_unavailable"][side]
            self.assertFalse(identity["available"])
            self.assertIsNone(identity["parts"])
            self.assertEqual(identity["reason"], "password_not_supplied")
            self.assertEqual(unavailable["reason"], "password_not_supplied")
            self.assertEqual(
                unavailable["blocked_evidence"][0]["trace"],
                {"container": "ole", "stream": "EncryptedPackage"},
            )
        self.assert_redacted(report)

    def test_rejected_password_is_not_reported_as_plaintext_identity(self):
        report = compare_office_files(
            self.reencrypted_left,
            self.reencrypted_right,
            password="wrong-password",
        )

        self.assertEqual(report["conclusion"]["code"], "plaintext_unverified")
        for side in ("left", "right"):
            identity = report["verified_plaintext_identity"][side]
            self.assertFalse(identity["available"])
            self.assertEqual(identity["reason"], "credential_rejected")
            self.assertTrue(identity["credential_supplied"])
            self.assertIsNone(identity["parts"])
        self.assert_redacted(report)


if __name__ == "__main__":
    unittest.main()
