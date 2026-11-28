class FileFormatError(Exception):
    """Raised when the format of given file is unsupported or unrecognized."""

    pass


class ParseError(Exception):
    """Raised when the file cannot be parsed correctly."""

    pass


class DecryptionError(Exception):
    """Raised when the file cannot be decrypted."""

    pass


class EncryptionError(Exception):
    """Raised when the file cannot be encrypted."""

    pass


class InvalidKeyError(DecryptionError):
    """Raised when the given password or key is incorrect or cannot be verified."""

    pass


class PolicyError(Exception):
    """Base class for archive policy failures."""

    pass


class ReadPermissionDeniedError(PolicyError):
    """Raised when a caller is not allowed to read a material."""

    pass


class TransferRejectedError(PolicyError):
    """Raised when a transfer result does not satisfy the active policy."""

    pass
