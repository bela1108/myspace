"""Tests for the read-only extraction manifest."""

import hashlib
import io
import json
import os
from shutil import rmtree
from tempfile import mkdtemp
import unittest
import zipfile

import olefile

from oletools import oleobj
from oletools.olemanifest import (
    ExtractionManifest,
    extract_manifest,
)
from tests.test_utils import DATA_BASE_DIR


OLEOBJ_DIR = os.path.join(DATA_BASE_DIR, "oleobj")
PUBLIC_DOC = os.path.join(OLEOBJ_DIR, "embedded-simple-2007.doc")
RESTRICTED_DOCX = os.path.join(
    OLEOBJ_DIR, "embedded-simple-2007.docx")


def file_sha256(filename):
    with open(filename, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


class TestExtractionManifest(unittest.TestCase):
    def test_same_content_keeps_distinct_references(self):
        before = (file_sha256(PUBLIC_DOC), file_sha256(RESTRICTED_DOCX))
        manifest = extract_manifest([
            (PUBLIC_DOC, "public"),
            (RESTRICTED_DOCX, "restricted"),
        ])
        self.assertEqual(len(manifest), 2)
        self.assertEqual(manifest.blob_count, 1)
        public, restricted = manifest.references
        self.assertEqual(public.content_digest, restricted.content_digest)
        self.assertEqual(public.disclosure_level, "public")
        self.assertEqual(restricted.disclosure_level, "restricted")
        self.assertNotEqual(public.reference_id, restricted.reference_id)
        self.assertNotEqual(public.parent_path, restricted.parent_path)
        self.assertNotEqual(
            public.container_member_path, restricted.container_member_path)
        self.assertEqual(
            len(manifest.entries_for_digest(public.content_digest)), 2)
        self.assertEqual(
            manifest.blob_store.get(public.content_digest),
            manifest.blob_store.get(restricted.content_digest),
        )
        self.assertTrue(manifest.delivery_allowed(
            public.reference_id, "public"))
        self.assertFalse(manifest.delivery_allowed(
            restricted.reference_id, "public"))
        self.assertEqual(before, (
            file_sha256(PUBLIC_DOC), file_sha256(RESTRICTED_DOCX)))

    def test_synthetic_nested_member_marks_unconfirmed_range(self):
        payload = olefile.MAGIC + b"truncated synthetic ole object"
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr(
                "word/embeddings/oleObject1.bin", payload)
        parent = os.path.join(OLEOBJ_DIR, "_synthetic-manifest.docx")
        with open(parent, "wb") as handle:
            handle.write(buffer.getvalue())
        try:
            manifest = extract_manifest((parent, "restricted"))
        finally:
            os.remove(parent)
        self.assertEqual(len(manifest), 1)
        entry = manifest.entries[0]
        self.assertEqual(entry.status, "unconfirmed")
        self.assertEqual(entry.unconfirmed_range, (0, len(payload)))
        self.assertEqual(entry.unconfirmed_scope, "container_member")

    def test_oleobj_process_file_can_populate_manifest(self):
        manifest = ExtractionManifest()
        output_dir = mkdtemp(prefix="olemanifest-")
        try:
            oleobj.process_file(PUBLIC_DOC, None,
                output_dir=output_dir, manifest=manifest,
                disclosure_level="public")
        finally:
            rmtree(output_dir)
        self.assertGreaterEqual(len(manifest.entries), 1)
        self.assertEqual(manifest.entries[0].disclosure_level, "public")

    def test_json_roundtrip_contains_both_references(self):
        manifest = extract_manifest({
            PUBLIC_DOC: "public",
            RESTRICTED_DOCX: "restricted",
        })
        data = json.loads(manifest.to_json())
        self.assertEqual(len(data["references"]), 2)
        self.assertEqual(len(data["entries"]), 2)
        self.assertEqual(len(data["blobs"]), 1)


if __name__ == "__main__":
    unittest.main()
