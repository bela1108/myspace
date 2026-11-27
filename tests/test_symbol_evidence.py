import hashlib
import json
import os
import struct
import tempfile
import unittest
import uuid

from symbol_evidence import (
    DEBUG_RECORD_MATCH,
    DIGEST_VERIFIED,
    NAME_ONLY,
    Claim,
    SignoffEntry,
    build_report,
    evaluate_claim,
    extract_debug_identities,
    load_pe_image,
    load_signoff,
)
from symbol_evidence.cli import main as cli_main

GUID = "01234567-89ab-cdef-0123-456789abcdef"
GUID_BARE = GUID.replace("-", "")
AGE = 7
FULL_DIGEST = "a" * 64


def build_pe(pdb_path=r"C:\build\core.pdb", guid=GUID, age=AGE, kind="rsds"):
    """Build a minimal PE with a real IMAGE_DEBUG_DIRECTORY + CodeView record."""

    data = bytearray(0x400)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x14C, 1, 0, 0, 0, 0xE0, 0x0102)
    opt = 0x98
    struct.pack_into("<H", data, opt, 0x10B)
    struct.pack_into("<I", data, opt + 0x10, 0x1000)
    struct.pack_into("<I", data, opt + 0x1C, 0x400000)
    struct.pack_into("<I", data, opt + 0x20, 0x1000)
    struct.pack_into("<I", data, opt + 0x24, 0x200)
    struct.pack_into("<I", data, opt + 0x38, 0x2000)
    struct.pack_into("<I", data, opt + 0x3C, 0x200)
    struct.pack_into("<H", data, opt + 0x44, 3)
    struct.pack_into("<I", data, opt + 0x5C, 16)
    struct.pack_into("<II", data, opt + 0x60 + 6 * 8, 0x1000, 28)

    section = 0x178
    data[section : section + 8] = b".rdata\0\0"
    struct.pack_into(
        "<IIIIIIHHI",
        data,
        section + 8,
        0x200,
        0x1000,
        0x200,
        0x200,
        0,
        0,
        0,
        0,
        0x40000040,
    )

    if kind == "rsds":
        guid_value = uuid.UUID(guid)
        payload = (
            struct.pack(
                "<4sIHHBB6sI",
                b"RSDS",
                guid_value.fields[0],
                guid_value.fields[1],
                guid_value.fields[2],
                guid_value.fields[3],
                guid_value.fields[4],
                guid_value.bytes[10:],
                age,
            )
            + pdb_path.encode("utf-8")
            + b"\0"
        )
    else:
        payload = struct.pack("<4sIII", b"NB10", 0, 0x12345678, age)
        payload += pdb_path.encode("utf-8") + b"\0"

    struct.pack_into(
        "<IIHHIIII", data, 0x200, 0, 0, 0, 0, 2, len(payload), 0x1220, 0x220
    )
    data[0x220 : 0x220 + len(payload)] = payload
    return bytes(data)


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


class TestDebugIdentity(unittest.TestCase):
    def test_reads_rsds_identity_from_read_only_debug_directory(self):
        data = build_pe()
        image = load_pe_image(data=data)
        self.assertEqual(1, len(image.identities))
        identity = image.identities[0]
        self.assertEqual("rsds", identity.kind)
        self.assertEqual("core.pdb", identity.pdb_name)
        self.assertEqual(GUID_BARE, identity.guid)
        self.assertEqual(AGE, identity.age)
        self.assertEqual("rsds:%s:%s" % (GUID_BARE, AGE), identity.identity_key)
        self.assertEqual(sha256_bytes(data), image.sha256)

    def test_extract_accepts_pe_instance_without_writing(self):
        image = load_pe_image(data=build_pe())
        identities = extract_debug_identities(image.pe)
        self.assertEqual(1, len(identities))
        self.assertEqual("core.pdb", identities[0].pdb_name)

    def test_reads_nb10_identity(self):
        image = load_pe_image(data=build_pe(kind="nb10", age=3))
        identity = image.identities[0]
        self.assertEqual("nb10", identity.kind)
        self.assertEqual("12345678", identity.signature)
        self.assertEqual(3, identity.age)
        self.assertEqual("nb10:12345678:3", identity.identity_key)


class TestEvidenceLevels(unittest.TestCase):
    def setUp(self):
        self.data = build_pe()
        self.image = load_pe_image(data=self.data)

    def test_name_only_is_not_verified(self):
        claim = Claim(display_name="core.pdb", ordinal=1)
        evidence = evaluate_claim(claim, self.image.identities)
        self.assertEqual(NAME_ONLY, evidence.level)
        self.assertFalse(evidence.verified)
        self.assertIn("仅文件名/显示名匹配", evidence.basis)

    def test_debug_record_identity_match_is_not_verified(self):
        claim = Claim(display_name="core.pdb", guid=GUID, age=AGE, ordinal=1)
        evidence = evaluate_claim(claim, self.image.identities)
        self.assertEqual(DEBUG_RECORD_MATCH, evidence.level)
        self.assertFalse(evidence.verified)

    def test_complete_digest_with_signoff_is_verified(self):
        claim = Claim(
            display_name="core.pdb",
            guid=GUID,
            age=AGE,
            digest=FULL_DIGEST,
            ordinal=1,
        )
        signoff = [
            SignoffEntry(
                name="core.pdb",
                guid=GUID,
                age=AGE,
                digest=FULL_DIGEST,
                row=1,
            )
        ]
        evidence = evaluate_claim(
            claim,
            self.image.identities,
            signoff_entries=signoff,
            pe_sha256=self.image.sha256,
        )
        self.assertEqual(DIGEST_VERIFIED, evidence.level)
        self.assertTrue(evidence.verified)

    def test_partial_digest_cannot_be_verified_even_when_signoff_matches_name(self):
        claim = Claim(
            display_name="core.pdb",
            guid=GUID,
            age=AGE,
            digest="a" * 8,
            ordinal=1,
        )
        signoff = [
            SignoffEntry(
                name="core.pdb",
                guid=GUID,
                age=AGE,
                digest=FULL_DIGEST,
                row=1,
            )
        ]
        evidence = evaluate_claim(
            claim,
            self.image.identities,
            signoff_entries=signoff,
            pe_sha256=self.image.sha256,
        )
        self.assertEqual(DEBUG_RECORD_MATCH, evidence.level)
        self.assertFalse(evidence.verified)
        self.assertFalse(evidence.digest_complete)

    def test_wrong_complete_digest_is_not_verified(self):
        claim = Claim(
            display_name="core.pdb",
            guid=GUID,
            age=AGE,
            digest="b" * 64,
            ordinal=1,
        )
        signoff = [
            SignoffEntry(
                name="core.pdb",
                guid=GUID,
                age=AGE,
                digest=FULL_DIGEST,
                row=1,
            )
        ]
        evidence = evaluate_claim(
            claim,
            self.image.identities,
            signoff_entries=signoff,
            pe_sha256=self.image.sha256,
        )
        self.assertFalse(evidence.verified)
        self.assertNotEqual(DIGEST_VERIFIED, evidence.level)
        self.assertTrue(evidence.conflicts)

    def test_a_clean_signoff_row_is_not_blocked_by_an_unrelated_stale_row(self):
        claim = Claim(
            display_name="core.pdb",
            guid=GUID,
            age=AGE,
            digest=FULL_DIGEST,
            ordinal=1,
        )
        signoff = [
            SignoffEntry(
                name="core.pdb",
                guid=GUID,
                age=AGE,
                digest="b" * 64,
                row=1,
            ),
            SignoffEntry(
                name="core.pdb",
                guid=GUID,
                age=AGE,
                digest=FULL_DIGEST,
                row=2,
            ),
        ]
        evidence = evaluate_claim(
            claim,
            self.image.identities,
            signoff_entries=signoff,
            pe_sha256=self.image.sha256,
        )
        self.assertEqual(DIGEST_VERIFIED, evidence.level)
        self.assertTrue(evidence.verified)


class TestReportExport(unittest.TestCase):
    def setUp(self):
        self.data = build_pe()
        self.image = load_pe_image(data=self.data)

    def _report(self, claims, signoff):
        return build_report(pe_data=self.data, signoff=signoff, claims=claims)

    def test_duplicate_display_name_only_complete_digest_verified(self):
        claims = [
            Claim(
                display_name="core.pdb",
                guid=GUID,
                age=AGE,
                digest=FULL_DIGEST,
                record_id="complete-record",
                ordinal=1,
            ),
            Claim(
                display_name="core.pdb",
                guid=GUID,
                age=AGE,
                digest="b" * 8,
                record_id="partial-record",
                ordinal=2,
            ),
        ]
        signoff = [
            SignoffEntry(name="core.pdb", guid=GUID, age=AGE, digest=FULL_DIGEST, row=1)
        ]
        report = self._report(claims, signoff)
        export = report.to_dict()

        records = export["records"]
        self.assertEqual(2, len(records))
        self.assertEqual("core.pdb", records[0]["display_name"])
        self.assertEqual("core.pdb", records[1]["display_name"])
        self.assertNotEqual(records[0]["id"], records[1]["id"])
        self.assertTrue(records[0]["verified"])
        self.assertFalse(records[1]["verified"])
        self.assertEqual("digest_verified", records[0]["evidence_level"])
        self.assertEqual(1, export["summary"]["verified"])
        self.assertEqual(1, len(export["summary"]["duplicate_display_names"]))

    def test_missing_digest_is_not_verified_even_if_signoff_has_one(self):
        claim = Claim(
            display_name="core.pdb",
            guid=GUID,
            age=AGE,
            record_id="no-digest",
            ordinal=1,
        )
        signoff = [
            SignoffEntry(name="core.pdb", guid=GUID, age=AGE, digest=FULL_DIGEST, row=1)
        ]
        report = self._report([claim], signoff)
        record = report.to_dict()["records"][0]
        self.assertEqual(DEBUG_RECORD_MATCH, record["evidence_level"])
        self.assertFalse(record["verified"])
        self.assertFalse(record["digest_complete"])

    def test_flat_legacy_fields_are_preserved(self):
        claim = Claim(
            display_name="core.pdb",
            source_file="src/core.c",
            line=42,
            symbol="run",
            guid=GUID,
            age=AGE,
            digest=FULL_DIGEST,
            record_id="legacy",
            ordinal=1,
        )
        signoff = [
            SignoffEntry(name="core.pdb", guid=GUID, age=AGE, digest=FULL_DIGEST, row=1)
        ]
        report = self._report([claim], signoff)
        export = report.to_dict()
        record = export["records"][0]
        for field in (
            "name",
            "source",
            "line",
            "symbol",
            "pdb",
            "guid",
            "age",
            "sha256",
            "verified",
        ):
            self.assertIn(field, record)
        self.assertEqual("core.pdb", record["name"])
        self.assertEqual("src/core.c", record["source"])
        self.assertEqual(FULL_DIGEST, record["sha256"])
        self.assertIn("legacy", record)
        self.assertEqual(record["verified"], record["legacy"]["verified"])
        self.assertIn("claims", export)
        self.assertEqual(export["claims"], export["records"])

    def test_pe_digest_mismatch_blocks_verification(self):
        claim = Claim(
            display_name="core.pdb",
            guid=GUID,
            age=AGE,
            digest=FULL_DIGEST,
            ordinal=1,
        )
        signoff = [
            SignoffEntry(
                name="core.pdb",
                guid=GUID,
                age=AGE,
                digest=FULL_DIGEST,
                pe_digest="c" * 64,
                row=1,
            )
        ]
        report = self._report([claim], signoff)
        record = report.to_dict()["records"][0]
        self.assertFalse(record["verified"])
        self.assertTrue(record["evidence"]["conflicts"])


class TestSignoffAndCli(unittest.TestCase):
    def test_chinese_csv_signoff_headers(self):
        text = (
            "符号库,PDB GUID,Age,文件摘要,签收人,签收单号\n"
            "core.pdb,%s,%s,%s,张三,SYM-001\n" % (GUID, AGE, FULL_DIGEST)
        )
        entries = load_signoff(text)
        self.assertEqual(1, len(entries))
        entry = entries[0]
        self.assertEqual("core.pdb", entry.name)
        self.assertEqual(GUID_BARE, entry.guid)
        self.assertEqual(AGE, entry.age)
        self.assertTrue(entry.digest.is_complete)
        self.assertEqual("张三", entry.signer)
        self.assertEqual("SYM-001", entry.reference)

    def test_generic_digest_on_pe_name_is_treated_as_image_digest(self):
        entries = load_signoff("name,sha256\nimage.exe,%s\n" % ("d" * 64))
        self.assertEqual(1, len(entries))
        self.assertIsNone(entries[0].digest)
        self.assertTrue(entries[0].pe_digest.is_complete)

    def test_cli_exports_json_markdown_and_csv(self):
        data = build_pe()
        with tempfile.TemporaryDirectory() as tmp:
            pe_path = os.path.join(tmp, "image.exe")
            with open(pe_path, "wb") as handle:
                handle.write(data)
            signoff_path = os.path.join(tmp, "signoff.csv")
            with open(signoff_path, "w", encoding="utf-8") as handle:
                handle.write(
                    "name,guid,age,sha256\ncore.pdb,%s,%s,%s\n"
                    % (GUID, AGE, FULL_DIGEST)
                )
            claims_path = os.path.join(tmp, "claims.json")
            with open(claims_path, "w", encoding="utf-8") as handle:
                json.dump(
                    [
                        {
                            "id": "one",
                            "name": "core.pdb",
                            "guid": GUID,
                            "age": AGE,
                            "sha256": FULL_DIGEST,
                        }
                    ],
                    handle,
                )
            output_dir = os.path.join(tmp, "out")
            self.assertEqual(
                0,
                cli_main(
                    [
                        pe_path,
                        "--signoff",
                        signoff_path,
                        "--claims",
                        claims_path,
                        "--output-dir",
                        output_dir,
                    ]
                ),
            )
            self.assertTrue(
                os.path.exists(os.path.join(output_dir, "symbol_evidence.json"))
            )
            self.assertTrue(
                os.path.exists(os.path.join(output_dir, "symbol_evidence.md"))
            )
            self.assertTrue(
                os.path.exists(os.path.join(output_dir, "symbol_evidence.csv"))
            )
            with open(
                os.path.join(output_dir, "symbol_evidence.json"), encoding="utf-8"
            ) as handle:
                report = json.load(handle)
            self.assertEqual(1, report["summary"]["verified"])
            self.assertTrue(report["records"][0]["verified"])
            self.assertEqual("digest_verified", report["records"][0]["evidence_level"])


if __name__ == "__main__":
    unittest.main()
