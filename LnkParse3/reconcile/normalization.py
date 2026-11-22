"""Normalization helpers for the identifiers used during reconciliation.

Every comparison in this package goes through one of these helpers so that
equivalent spellings (``0xABCD`` vs ``abcd`` vs ``ABCD-...``) compare equal
while genuinely different identifiers never collapse together.
"""

import re


def normalize_serial(value):
    """Normalize a Windows volume serial number to a bare lowercase hex string.

    Windows reports serials as 32-bit values such as ``0x307A8A81``. Parsers
    and collection tools may spell the same value as ``307A8A81``,
    ``307a-8a81`` or ``{307a8a81}``. All of those normalize to
    ``307a8a81``.

    Returns ``None`` when there is nothing usable to normalize.
    """
    if value is None:
        return None

    if isinstance(value, int):
        if value < 0:
            return None
        return f"{value:x}"

    text = str(value).strip()
    if not text:
        return None

    text = text.lower()
    if text.startswith("0x"):
        text = text.removeprefix("0x")
    text = re.sub(r"[^0-9a-f]", "", text)

    if not text:
        return None
    return text


def normalize_drive_letter(value):
    """Normalize a drive letter to a bare uppercase letter (``C``)."""
    if value is None:
        return None

    text = str(value).strip().upper()
    if not text:
        return None

    match = re.match(r"^([A-Z]):?", text)
    if not match:
        return None
    return match.group(1)


def normalize_label(value):
    """Normalize a volume label for trimmed, case-insensitive comparison."""
    if value is None:
        return None

    text = str(value).strip()
    if not text:
        return None
    return text.casefold()


def normalize_path_key(value):
    """Normalize a target path so the same logical path groups together.

    Windows paths are case-insensitive and accept either slash; surrounding
    whitespace and a trailing backslash are not meaningful for grouping.
    """
    if value is None:
        return None

    text = str(value).strip().replace("/", "\\")
    if not text:
        return None

    text = text.rstrip("\\").casefold()
    return text or None


def drive_letter_from_path(path):
    """Extract the leading drive letter (``C``) from a local path."""
    if not path:
        return None

    match = re.match(r"^\s*([A-Za-z]):", str(path))
    if not match:
        return None
    return match.group(1).upper()
