import contextlib


__version__ = "2.7.0"


from .ledger import (
    STAGE_EXPLICIT_POLICY,
    STAGE_PARSE,
    STAGE_PARSING,
    STAGE_POLICY,
    STAGE_STRUCTURAL,
    STAGE_STRUCTURE,
    STATUS_APPLIED,
    STATUS_PENDING,
    STATUS_UNALIGNED,
    ChangeLedger,
    InternalChange,
    PublicChange,
)


ChangeRecord = PublicChange


__all__ = [
    "STAGE_EXPLICIT_POLICY",
    "STAGE_PARSE",
    "STAGE_PARSING",
    "STAGE_POLICY",
    "STAGE_STRUCTURAL",
    "STAGE_STRUCTURE",
    "STATUS_APPLIED",
    "STATUS_PENDING",
    "STATUS_UNALIGNED",
    "ChangeLedger",
    "ChangeRecord",
    "InternalChange",
    "PublicChange",
]

with contextlib.suppress(ImportError):
    from .sanitizer import Sanitizer, SanitizeResult, sanitize_with_ledger  # noqa: F401

    __all__.extend(
        [
            "SanitizeResult",
            "Sanitizer",
            "sanitize_with_ledger",
        ]
    )
