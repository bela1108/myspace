import struct
import unittest

import LnkParse3
from LnkParse3.audit import CollectionSheet
from LnkParse3.audit import ExistenceAudit
from LnkParse3.audit import FieldStatus
from LnkParse3.audit import FileIdentity


CLSID = b"\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46"

HAS_NAME = 0x00000004
HAS_ARGUMENTS = 0x00000020
IS_UNICODE = 0x00000080

TERMINAL_BLOCK = b"\x00\x00\x00\x00"
CODEPAGE_BLOCK = struct.pack("<III", 0x0C, 0xA0000004, 1252)


def make_header(flags):
    return (
        struct.pack("<I", 0x4C)
        + CLSID
        + struct.pack("<I", flags)
        + b"\x00" * 4  # FileAttributes
        + b"\x00" * 24  # CreationTime, AccessTime, WriteTime
        + struct.pack("<I", 0)  # FileSize
        + struct.pack("<i", 0)  # IconIndex
        + struct.pack("<I", 1)  # ShowCommand
        + b"\x00" * 2  # HotKey
        + b"\x00" * 10  # Reserved1, Reserved2, Reserved3
    )


def counted_string(text):
    return struct.pack("<H", len(text)) + text.encode("utf-16-le")


def make_lnk(flags, strings=(), extras=b""):
    data = make_header(flags)
    for text in strings:
        data += counted_string(text)
    return data + extras + TERMINAL_BLOCK


class TestCollectionSheet(unittest.TestCase):
    def test_declared_empty_is_distinguished_from_not_declared(self):
        indata = make_lnk(IS_UNICODE | HAS_NAME, strings=[""])
        lnk = LnkParse3.lnk_file(indata=indata)

        sheet = CollectionSheet.from_lnk("pass-1", lnk)

        self.assertEqual(
            sheet.observe("description").status, FieldStatus.DECLARED_EMPTY
        )
        self.assertEqual(
            sheet.observe("relative_path").status, FieldStatus.NOT_DECLARED
        )

    def test_scope_limits_the_collected_channels(self):
        indata = make_lnk(IS_UNICODE | HAS_NAME, strings=["notes"])
        lnk = LnkParse3.lnk_file(indata=indata)

        sheet = CollectionSheet.from_lnk("header-only", lnk, scope=("header",))

        self.assertEqual(sheet.scope(), frozenset({"header"}))
        observation = sheet.observe("description")
        self.assertEqual(observation.status, FieldStatus.INCOMPLETE)
        self.assertIn("string data", observation.detail)

    def test_unknown_scope_channel_is_rejected(self):
        indata = make_lnk(IS_UNICODE, strings=[])
        lnk = LnkParse3.lnk_file(indata=indata)

        with self.assertRaises(ValueError):
            CollectionSheet.from_lnk("bad", lnk, scope=("header", "bogus"))

    def test_building_a_sheet_does_not_modify_the_lnk(self):
        indata = make_lnk(IS_UNICODE | HAS_NAME, strings=["notes"], extras=CODEPAGE_BLOCK)
        lnk = LnkParse3.lnk_file(indata=indata)
        before = lnk.get_json(get_all=True)

        sheet = CollectionSheet.from_lnk("pass-1", lnk)
        ExistenceAudit([sheet]).render_matrix()

        self.assertEqual(lnk.get_json(get_all=True), before)
        self.assertEqual(sheet.extras, frozenset({"CONSOLE_CODEPAGE_BLOCK"}))


class TestExistenceAudit(unittest.TestCase):
    def test_complementary_sheets_complete_a_field(self):
        indata = make_lnk(IS_UNICODE | HAS_NAME | HAS_ARGUMENTS, strings=["", "/q"])
        lnk = LnkParse3.lnk_file(indata=indata)
        header_pass = CollectionSheet.from_lnk("pass-header", lnk, scope=("header",))
        string_pass = CollectionSheet.from_lnk("pass-strings", lnk, scope=("strings",))

        audit = ExistenceAudit([header_pass, string_pass])
        matrix = audit.coverage_matrix()

        self.assertEqual(
            audit.verdict("description").status, FieldStatus.DECLARED_EMPTY
        )
        self.assertEqual(audit.verdict("command_line_arguments").value, "/q")
        self.assertEqual(
            matrix["description"]["completions"],
            [
                {
                    "sheets": ["pass-header", "pass-strings"],
                    "status": "declared_empty",
                    "value": "",
                }
            ],
        )
        self.assertEqual(matrix["description"]["unresolved"], [])

    def test_file_version_difference_blocks_complementation(self):
        old = LnkParse3.lnk_file(indata=make_lnk(IS_UNICODE | HAS_NAME, strings=["old"]))
        new = LnkParse3.lnk_file(indata=make_lnk(IS_UNICODE | HAS_NAME, strings=["new"]))
        first = CollectionSheet.from_lnk("pass-old", old, scope=("header", "strings"))
        second = CollectionSheet.from_lnk("pass-new", new, scope=("header",))

        audit = ExistenceAudit([first, second])
        matrix = audit.coverage_matrix()

        self.assertFalse(first.compatible_with(second))
        self.assertEqual(matrix["description"]["completions"], [])
        self.assertEqual(
            matrix["description"]["unresolved"],
            [{"sheet": "pass-new", "reason": "file_version_differs"}],
        )
        self.assertEqual(audit.verdict("description").status, FieldStatus.PRESENT)

    def test_conflicting_versions_give_no_conclusion(self):
        old = LnkParse3.lnk_file(indata=make_lnk(IS_UNICODE | HAS_NAME, strings=["old"]))
        new = LnkParse3.lnk_file(indata=make_lnk(IS_UNICODE | HAS_NAME, strings=["new"]))
        first = CollectionSheet.from_lnk("pass-old", old)
        second = CollectionSheet.from_lnk("pass-new", new)

        audit = ExistenceAudit([first, second])

        self.assertEqual(
            audit.verdict("description").status, FieldStatus.NO_CONCLUSION
        )

    def test_incompatible_overlap_cannot_complete(self):
        indata = make_lnk(IS_UNICODE | HAS_NAME, strings=["notes"])
        lnk = LnkParse3.lnk_file(indata=indata)
        identity = FileIdentity.from_bytes(indata)
        declared = CollectionSheet.from_lnk("ref", lnk).declared

        first = CollectionSheet(
            "pass-a",
            identity,
            declared=declared,
            values={"description": "one"},
        )
        second = CollectionSheet(
            "pass-b",
            identity,
            declared=declared,
            values={"description": "two"},
        )

        self.assertFalse(first.compatible_with(second))
        audit = ExistenceAudit([first, second])
        self.assertEqual(
            audit.verdict("description").status, FieldStatus.NO_CONCLUSION
        )
        self.assertEqual(audit.coverage_matrix()["description"]["completions"], [])

    def test_single_incomplete_pass_reports_incomplete_material(self):
        indata = make_lnk(IS_UNICODE | HAS_NAME, strings=["notes"])
        lnk = LnkParse3.lnk_file(indata=indata)
        sheet = CollectionSheet.from_lnk("pass-header", lnk, scope=("header",))

        audit = ExistenceAudit([sheet])
        matrix = audit.coverage_matrix()

        self.assertEqual(audit.verdict("description").status, FieldStatus.INCOMPLETE)
        self.assertEqual(
            matrix["description"]["unresolved"],
            [{"sheet": "pass-header", "reason": "incomplete_material"}],
        )

    def test_report_and_rendered_matrix(self):
        indata = make_lnk(IS_UNICODE | HAS_NAME, strings=[""], extras=CODEPAGE_BLOCK)
        lnk = LnkParse3.lnk_file(indata=indata)
        header_pass = CollectionSheet.from_lnk("pass-header", lnk, scope=("header",))
        full_pass = CollectionSheet.from_lnk("pass-full", lnk)

        audit = ExistenceAudit([header_pass, full_pass])
        report = audit.report()
        rendered = audit.render_matrix()

        self.assertEqual(report["description"]["status"], "declared_empty")
        self.assertEqual(report["description"]["evidence"], ["pass-full", "pass-header"])
        self.assertEqual(report["icon_location"]["status"], "not_declared")
        self.assertIn("pass-header", rendered)
        self.assertIn("pass-full", rendered)
        self.assertIn("declared_empty", rendered)


if __name__ == "__main__":
    unittest.main()
