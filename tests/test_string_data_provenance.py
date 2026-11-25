import base64
import struct
import unittest
import warnings
from pathlib import Path
from typing import NamedTuple

import LnkParse3


FIXTURE = Path(__file__).resolve().parent / "samples" / "microsoft_example"
LINK_CLSID = bytes.fromhex("0114020000000000c000000000000046")
HEADER_SIZE = 0x4C
TERMINAL_BLOCK = b"\x00" * 4

HAS_NAME = 0x00000004
HAS_RELATIVE_PATH = 0x00000008
HAS_WORKING_DIR = 0x00000010
IS_UNICODE = 0x00000080

FLAG_BY_KEY = {
    "description": HAS_NAME,
    "relative_path": HAS_RELATIVE_PATH,
    "working_directory": HAS_WORKING_DIR,
}


class PhysicalString(NamedTuple):
    key: str
    value: str
    count_offset: int

    @property
    def text_offset(self) -> int:
        return self.count_offset + 2

    @property
    def encoded_text(self) -> bytes:
        return self.value.encode("utf-16-le")

    @property
    def end_offset(self) -> int:
        return self.text_offset + len(self.encoded_text)

    def raw_segment(self) -> bytes:
        return struct.pack("<H", len(self.value)) + self.encoded_text


def build_header(flags: int) -> bytes:
    return b"".join(
        [
            struct.pack("<I", HEADER_SIZE),
            LINK_CLSID,
            struct.pack("<I", flags),
            struct.pack("<I", 0x20),
            bytes(24),
            struct.pack("<I", 0),
            struct.pack("<i", 0),
            struct.pack("<I", 1),
            struct.pack("<H", 0),
            struct.pack("<H", 0),
            struct.pack("<I", 0),
            struct.pack("<I", 0),
        ]
    )


def build_minimal_lnk(entries):
    flags = IS_UNICODE
    body = []
    segments = []
    count_offset = HEADER_SIZE

    for key, value in entries:
        flags |= FLAG_BY_KEY[key]
        segment = PhysicalString(key, value, count_offset)
        raw_segment = segment.raw_segment()
        body.append(raw_segment)
        segments.append(segment)
        count_offset += len(raw_segment)

    data = build_header(flags) + b"".join(body) + TERMINAL_BLOCK
    return data, tuple(segments)


def assert_physical_string(test_case, data: bytes, segment: PhysicalString) -> None:
    char_count = struct.unpack_from("<H", data, segment.count_offset)[0]
    test_case.assertEqual(char_count, len(segment.value))
    test_case.assertEqual(
        data[segment.text_offset : segment.end_offset],
        segment.encoded_text,
    )
    test_case.assertEqual(
        data[segment.text_offset : segment.end_offset].decode("utf-16-le"),
        segment.value,
    )


class StringDataProvenanceTest(unittest.TestCase):
    def parse_strictly(self, data: bytes):
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            return LnkParse3.lnk_file(indata=data)

    def test_shipped_fixture_keeps_filesystem_strings_in_string_data(self):
        data = base64.b64decode(b"".join(FIXTURE.read_bytes().split()))

        expected_segments = (
            PhysicalString("relative_path", r".\a.txt", 0x147),
            PhysicalString("working_directory", r"C:\test", 0x157),
        )

        for segment in expected_segments:
            with self.subTest(string=segment.key):
                assert_physical_string(self, data, segment)

        self.assertEqual(
            expected_segments[0].end_offset,
            expected_segments[1].count_offset,
        )

        lnk = self.parse_strictly(data)
        parsed = lnk.string_data.as_dict()

        self.assertEqual(
            list(parsed),
            ["relative_path", "working_directory"],
        )
        self.assertEqual(lnk.string_data.size(), 0x20)
        self.assertEqual(lnk.size, len(data))

        for segment in expected_segments:
            self.assertEqual(parsed[segment.key], segment.value)

    def test_constructed_retained_fields_have_independent_physical_order(self):
        entries = (
            ("relative_path", r".\archive\relative"),
            ("working_directory", r"D:\Archives\workdir"),
        )
        data, expected_segments = build_minimal_lnk(entries)

        self.assertEqual(
            [segment.key for segment in expected_segments],
            ["relative_path", "working_directory"],
        )
        self.assertEqual(expected_segments[0].count_offset, HEADER_SIZE)
        self.assertEqual(
            expected_segments[1].count_offset,
            expected_segments[0].end_offset,
        )

        lnk = self.parse_strictly(data)
        parsed = lnk.string_data.as_dict()

        self.assertEqual(list(parsed), [segment.key for segment in expected_segments])
        self.assertEqual(
            lnk.string_data.size(),
            sum(segment.end_offset - segment.count_offset for segment in expected_segments),
        )
        self.assertEqual(lnk.size, len(data))

        for segment in expected_segments:
            assert_physical_string(self, data, segment)
            self.assertEqual(parsed[segment.key], segment.value)

    def test_absent_relative_flag_does_not_reserve_physical_string_slot(self):
        entries = (
            ("description", "archive description"),
            ("working_directory", r"D:\Archives\work"),
        )
        data, expected_segments = build_minimal_lnk(entries)
        link_flags = struct.unpack_from("<I", data, 20)[0]

        self.assertEqual(link_flags & HAS_RELATIVE_PATH, 0)
        self.assertEqual(link_flags & HAS_NAME, HAS_NAME)
        self.assertEqual(link_flags & HAS_WORKING_DIR, HAS_WORKING_DIR)
        self.assertEqual(
            expected_segments[1].count_offset,
            expected_segments[0].end_offset,
        )

        lnk = self.parse_strictly(data)
        parsed = lnk.string_data.as_dict()

        self.assertFalse(lnk.has_relative_path())
        self.assertIsNone(lnk.string_data.relative_path())
        self.assertEqual(list(parsed), ["description", "working_directory"])

        for segment in expected_segments:
            assert_physical_string(self, data, segment)
            self.assertEqual(parsed[segment.key], segment.value)

    def test_declared_absent_filesystem_strings_have_empty_string_data(self):
        data, expected_segments = build_minimal_lnk(())
        link_flags = struct.unpack_from("<I", data, 20)[0]

        self.assertEqual(expected_segments, ())
        self.assertEqual(link_flags & (HAS_RELATIVE_PATH | HAS_WORKING_DIR), 0)

        lnk = self.parse_strictly(data)

        self.assertFalse(lnk.has_relative_path())
        self.assertFalse(lnk.has_working_dir())
        self.assertIsNone(lnk.string_data.relative_path())
        self.assertIsNone(lnk.string_data.working_directory())
        self.assertEqual(lnk.string_data.as_dict(), {})
        self.assertEqual(lnk.string_data.size(), 0)
        self.assertEqual(lnk.size, len(data))


if __name__ == "__main__":
    unittest.main()
