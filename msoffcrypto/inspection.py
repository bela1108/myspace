"""Read-only Office format inspection helpers.

This module is a small alias for msoffcrypto.receipt so callers can import
the observation helpers without depending on the ledger class.
"""

from msoffcrypto.receipt import (  # noqa: F401
    FormatConclusion,
    FormatObservation,
    Observation,
    PublicProperties,
    Receipt,
    inspect_bytes,
    inspect_file,
    inspect_office_file,
    observe_format,
    read_only_inspect,
)

__all__ = [
    "FormatConclusion",
    "FormatObservation",
    "Observation",
    "PublicProperties",
    "Receipt",
    "inspect_bytes",
    "inspect_file",
    "inspect_office_file",
    "observe_format",
    "read_only_inspect",
]
