"""Compatibility spelling for :mod:`LnkParse3.offline_check`."""

from LnkParse3.offline_check import load_msi_excerpt
from LnkParse3.offline_check import MsiExcerpt
from LnkParse3.offline_check import verify_lnk_with_msi


verify_offline = verify_lnk_with_msi

__all__ = [
    "MsiExcerpt",
    "load_msi_excerpt",
    "verify_lnk_with_msi",
    "verify_offline",
]
