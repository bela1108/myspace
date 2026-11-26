import zipfile

import olefile

from msoffcrypto import exceptions


def OfficeFile(file):
    """Return an office file object based on the format of given file.

    Args:
        file (:obj:`_io.BufferedReader`): Input file.

    Returns:
        BaseOfficeFile object.

    Examples:
        >>> with open("tests/inputs/example_password.docx", "rb") as f:
        ...     officefile = OfficeFile(f)
        ...     officefile.keyTypes
        ('password', 'private_key', 'secret_key')

        >>> with open("tests/inputs/example_password.docx", "rb") as f:
        ...     officefile = OfficeFile(f)
        ...     officefile.load_key(password="Password1234_", verify_password=True)

        >>> with open("README.md", "rb") as f:
        ...     officefile = OfficeFile(f)
        Traceback (most recent call last):
            ...
        msoffcrypto.exceptions.FileFormatError: ...

        >>> with open("tests/inputs/example_password.docx", "rb") as f:
        ...     officefile = OfficeFile(f)
        ...     officefile.load_key(password="0000", verify_password=True)
        Traceback (most recent call last):
            ...
        msoffcrypto.exceptions.InvalidKeyError: ...

    Given file handle will not be closed, the file position will most certainly
    change.
    """
    file.seek(0)  # required by isOleFile
    if olefile.isOleFile(file):
        ole = olefile.OleFileIO(file)
    elif zipfile.is_zipfile(file):  # Heuristic
        from msoffcrypto.format.ooxml import OOXMLFile

        return OOXMLFile(file)
    else:
        raise exceptions.FileFormatError("Unsupported file format")

    # TODO: Make format specifiable by option in case of obstruction
    # Try this first; see https://github.com/nolze/msoffcrypto-tool/issues/17
    if ole.exists("EncryptionInfo"):
        from msoffcrypto.format.ooxml import OOXMLFile

        return OOXMLFile(file)
    # MS-DOC: The WordDocument stream MUST be present in the file.
    # https://msdn.microsoft.com/en-us/library/dd926131(v=office.12).aspx
    elif ole.exists("wordDocument"):
        from msoffcrypto.format.doc97 import Doc97File

        return Doc97File(file)
    # MS-XLS: A file MUST contain exactly one Workbook Stream, ...
    # https://msdn.microsoft.com/en-us/library/dd911009(v=office.12).aspx
    elif ole.exists("Workbook"):
        from msoffcrypto.format.xls97 import Xls97File

        return Xls97File(file)
    # MS-PPT: A required stream whose name MUST be "PowerPoint Document".
    # https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-ppt/1fc22d56-28f9-4818-bd45-67c2bf721ccf
    elif ole.exists("PowerPoint Document"):
        from msoffcrypto.format.ppt97 import Ppt97File

        return Ppt97File(file)
    else:
        raise exceptions.FileFormatError("Unrecognized file format")


_RECEIPT_EXPORTS = {
    "Receipt",
    "ReceiptLedger",
    "AdjudicationRecord",
    "AdjudicationLedger",
    "ReviewLedger",
    "ReadOnlyReceipt",
    "ForensicReceipt",
    "read_only_receipt",
    "FormatReceipt",
    "ReceiptReport",
    "ForensicReviewReport",
    "Observation",
    "FormatObservation",
    "FormatConclusion",
    "PublicProperties",
    "Correction",
    "Renewal",
    "Record",
    "ReviewRecord",
    "ReceiptRecord",
    "ObservationRecord",
    "ConclusionRecord",
    "ObservationStatus",
    "ConclusionStatus",
    "ReceiptStatus",
    "ReviewStatus",
    "InterruptedWriteError",
    "ReceiptError",
    "InspectionError",
    "inspect_file",
    "inspect_bytes",
    "inspect_office_file",
    "read_only_inspect",
    "observe_file",
    "observe_format",
    "format_observation",
    "detect_format",
    "identify_format",
    "inspect_office",
    "create_observation",
    "build_observation",
    "load_receipt",
    "read_receipt",
    "open_receipt",
    "write_receipt",
    "create_receipt",
    "resume_receipt",
    "correct_observation",
    "renew_observation",
    "accept_correction",
    "record_observation",
    "initial_format_conclusion",
    "initial_conclusion",
    "verify_receipt",
    "migrate_legacy_receipt",
}


def __getattr__(name):
    """Expose the receipt API without importing it for ordinary decryption."""

    if name in {"receipt", "forensic_receipt", "inspection", "attestation"}:
        import importlib

        return importlib.import_module("msoffcrypto." + name)
    if name in _RECEIPT_EXPORTS:
        from msoffcrypto import receipt as _receipt

        return getattr(_receipt, name)
    raise AttributeError("module 'msoffcrypto' has no attribute {!r}".format(name))
