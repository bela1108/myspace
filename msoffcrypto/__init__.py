import zipfile

import olefile

from msoffcrypto import exceptions
from msoffcrypto.input import InputContract


def OfficeFile(file, copy_budget=None):
    """Return an office file object based on the format of given file.

    Args:
        file (:obj:`_io.BufferedReader`): Input file. Its current position is
            treated as the beginning of the office document.
        copy_budget (int): Maximum number of bytes that may be copied locally
            when ``file`` is not seekable.

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

    A seekable file handle is not closed and can be reviewed from its original
    position through the returned file's input contract. A non-seekable handle
    is not supported unless ``copy_budget`` permits a local copy; that copy is
    closed by the returned file's ``close()`` method.
    """
    input_contract = InputContract(file, copy_budget=copy_budget)
    input_stream = input_contract.stream
    try:
        if olefile.isOleFile(input_stream):
            ole = olefile.OleFileIO(input_stream)
        elif zipfile.is_zipfile(input_stream):  # Heuristic
            from msoffcrypto.format.ooxml import OOXMLFile

            office_file = OOXMLFile(input_contract)
            input_contract.restore()
            return office_file
        else:
            raise exceptions.FileFormatError("Unsupported file format")

        # TODO: Make format specifiable by option in case of obstruction
        # Try this first; see https://github.com/nolze/msoffcrypto-tool/issues/17
        if ole.exists("EncryptionInfo"):
            from msoffcrypto.format.ooxml import OOXMLFile

            office_file = OOXMLFile(input_contract)
        # MS-DOC: The WordDocument stream MUST be present in the file.
        # https://msdn.microsoft.com/en-us/library/dd926131(v=office.12).aspx
        elif ole.exists("wordDocument"):
            from msoffcrypto.format.doc97 import Doc97File

            office_file = Doc97File(input_contract)
        # MS-XLS: A file MUST contain exactly one Workbook Stream, ...
        # https://msdn.microsoft.com/en-us/library/dd911009(v=office.12).aspx
        elif ole.exists("Workbook"):
            from msoffcrypto.format.xls97 import Xls97File

            office_file = Xls97File(input_contract)
        # MS-PPT: A required stream whose name MUST be "PowerPoint Document".
        # https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-ppt/1fc22d56-28f9-4818-bd45-67c2bf721ccf
        elif ole.exists("PowerPoint Document"):
            from msoffcrypto.format.ppt97 import Ppt97File

            office_file = Ppt97File(input_contract)
        else:
            raise exceptions.FileFormatError("Unrecognized file format")
    except Exception:
        input_contract.restore()
        input_contract.close()
        raise

    input_contract.restore()
    return office_file
