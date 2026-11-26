class RegipyException(Exception):
    """
    This is the parent exception for all regipy exceptions
    """

    pass


class RegipyGeneralException(RegipyException):
    """
    General exception
    """

    pass


class RegistryValueNotFoundException(RegipyException):
    pass


class NoRegistrySubkeysException(RegipyException):
    pass


class NoRegistryValuesException(RegipyException):
    pass


class RegistryKeyNotFoundException(RegipyException):
    pass


class UnidentifiedHiveException(RegipyException):
    pass


class RegistryRecoveryException(RegipyException):
    pass


class RegistryParsingException(RegipyException):
    """
    Raised when there is a parsing error, most probably a corrupted hive
    """

    pass


class EvidenceReferenceException(RegipyGeneralException):
    """Base class for evidence-reference construction and lookup errors."""

    pass


class UnmappedLegacyReferenceException(EvidenceReferenceException):
    """A legacy CSV row has no explicit mapping to an evidence reference."""

    pass


class AmbiguousLegacyReferenceException(EvidenceReferenceException):
    """Explicit mapping keys for a legacy CSV row disagree."""

    pass
