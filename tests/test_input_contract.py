import hashlib
import io
import unittest
from os.path import dirname, join
from unittest import mock

from msoffcrypto import OfficeFile, exceptions
from msoffcrypto.format.xls97 import Xls97File
from msoffcrypto.input import InputContract, RelativeStream

DATA_DIR = join(dirname(__file__), "inputs")
PREFIX = b"case-import-prefix"

FORMAT_FILES = (
    ("example_password.docx", True),
    ("example_password.xlsx", True),
    ("plain.doc", False),
    ("plain.ppt", False),
    ("plain.xls", False),
)


class NonSeekableStream:
    def __init__(self, data):
        self.data = data
        self.position = 0
        self.closed = False

    def seekable(self):
        return False

    def tell(self):
        raise OSError("not seekable")

    def seek(self, offset, whence=0):
        raise OSError("not seekable")

    def read(self, size=-1):
        if size is None or size < 0:
            size = len(self.data) - self.position
        value = self.data[self.position : self.position + size]
        self.position += len(value)
        return value

    def close(self):
        self.closed = True


def prefixed_bytes(name):
    with open(join(DATA_DIR, name), "rb") as stream:
        return PREFIX + stream.read()


class InputContractTest(unittest.TestCase):
    def test_relative_stream_keeps_physical_offset(self):
        stream = io.BytesIO(b"prefix-document")
        stream.seek(len(b"prefix-"))
        relative = RelativeStream(stream, stream.tell())

        self.assertEqual(relative.read(8), b"document")
        relative.seek(0)
        self.assertEqual(stream.tell(), len(b"prefix-"))
        self.assertEqual(relative.read(), b"document")
        relative.seek(0, 2)
        self.assertEqual(relative.tell(), len(b"document"))

    def test_probe_restores_replayable_input_across_formats(self):
        for name, encrypted in FORMAT_FILES:
            with self.subTest(name=name):
                stream = io.BytesIO(prefixed_bytes(name))
                stream.seek(len(PREFIX))
                expected_digest = hashlib.sha256(stream.read()).hexdigest()
                stream.seek(len(PREFIX))

                office_file = OfficeFile(stream)
                self.assertEqual(office_file.is_encrypted(), encrypted)
                self.assertEqual(stream.tell(), len(PREFIX))

                with office_file.input_contract.review() as review_stream:
                    digest = hashlib.sha256(review_stream.read()).hexdigest()

                self.assertEqual(digest, expected_digest)
                self.assertEqual(stream.tell(), len(PREFIX))
                office_file.close()
                self.assertFalse(stream.closed)

    def test_recoverable_failure_restores_start_offset(self):
        for name, format_class in (
            ("plain.doc", "msoffcrypto.format.doc97.Doc97File"),
            ("plain.ppt", "msoffcrypto.format.ppt97.Ppt97File"),
            ("plain.xls", "msoffcrypto.format.xls97.Xls97File"),
        ):
            with self.subTest(name=name):
                stream = io.BytesIO(prefixed_bytes(name))
                stream.seek(len(PREFIX))
                with mock.patch(format_class, side_effect=RuntimeError("probe interrupted")):
                    with self.assertRaises(RuntimeError):
                        OfficeFile(stream)

                self.assertEqual(stream.tell(), len(PREFIX))
                self.assertEqual(stream.read(8), prefixed_bytes(name)[len(PREFIX) : len(PREFIX) + 8])

    def test_parse_failure_restores_start_offset(self):
        stream = io.BytesIO(prefixed_bytes("plain.doc"))
        stream.seek(len(PREFIX))
        with mock.patch("msoffcrypto.format.doc97._parseFib", side_effect=RuntimeError("parse interrupted")):
            with self.assertRaises(RuntimeError):
                OfficeFile(stream)

        self.assertEqual(stream.tell(), len(PREFIX))

    def test_recoverable_ooxml_failure_restores_start_offset(self):
        stream = io.BytesIO(prefixed_bytes("example_password.docx"))
        stream.seek(len(PREFIX))
        with mock.patch("msoffcrypto.format.ooxml.OOXMLFile", side_effect=RuntimeError("probe interrupted")):
            with self.assertRaises(RuntimeError):
                OfficeFile(stream)

        self.assertEqual(stream.tell(), len(PREFIX))

    def test_review_after_decryption_restores_physical_offset(self):
        data = prefixed_bytes("example_password.docx")
        stream = io.BytesIO(data)
        stream.seek(len(PREFIX))
        office_file = OfficeFile(stream)
        office_file.load_key(password="Password1234_", verify_password=True)
        output = io.BytesIO()
        office_file.decrypt(output)

        with office_file.input_contract.review() as review_stream:
            digest = hashlib.sha256(review_stream.read()).hexdigest()

        self.assertEqual(digest, hashlib.sha256(data[len(PREFIX) :]).hexdigest())
        self.assertEqual(stream.tell(), len(PREFIX))
        office_file.close()

    def test_non_seekable_input_requires_explicit_support(self):
        document = prefixed_bytes("plain.xls")[len(PREFIX) :]
        stream = NonSeekableStream(document)
        with self.assertRaises(OSError):
            OfficeFile(stream)
        self.assertEqual(stream.position, 0)
        self.assertFalse(stream.closed)

    def test_non_seekable_input_uses_budgeted_local_copy(self):
        data = prefixed_bytes("plain.xls")[len(PREFIX) :]
        stream = NonSeekableStream(data)
        office_file = OfficeFile(stream, copy_budget=len(data))

        self.assertFalse(office_file.input_contract.replayable)
        self.assertTrue(office_file.input_contract.owns_stream)
        self.assertEqual(office_file.is_encrypted(), False)
        with office_file.input_contract.review() as review_stream:
            self.assertEqual(review_stream.read(), data)

        office_file.close()
        self.assertFalse(stream.closed)
        self.assertTrue(office_file.input_contract.stream.closed)

    def test_direct_format_accepts_budgeted_non_seekable_input(self):
        data = prefixed_bytes("plain.xls")[len(PREFIX) :]
        stream = NonSeekableStream(data)
        office_file = Xls97File(stream, copy_budget=len(data))

        self.assertEqual(office_file.is_encrypted(), False)
        office_file.close()
        self.assertTrue(office_file.input_contract.stream.closed)
        self.assertFalse(stream.closed)

    def test_budgeted_copy_rejects_oversized_input_and_restores_contract(self):
        data = prefixed_bytes("plain.xls")[len(PREFIX) :]
        stream = NonSeekableStream(data)
        with self.assertRaises(ValueError):
            InputContract(stream, copy_budget=len(data) - 1)
        self.assertFalse(stream.closed)

    def test_zero_budget_accepts_empty_non_seekable_input(self):
        stream = NonSeekableStream(b"")
        contract = InputContract(stream, copy_budget=0)

        self.assertEqual(contract.stream.read(), b"")
        contract.close()

    def test_unsupported_format_restores_start_offset(self):
        stream = io.BytesIO(PREFIX + b"not an office document")
        stream.seek(len(PREFIX))
        with self.assertRaises(exceptions.FileFormatError):
            OfficeFile(stream)
        self.assertEqual(stream.tell(), len(PREFIX))


if __name__ == "__main__":
    unittest.main()
