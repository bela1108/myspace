"""Compatibility name for the offline MSI registration check."""

from LnkParse3.offline_check import load_msi_excerpt
from LnkParse3.offline_check import MsiExcerpt
from LnkParse3.offline_check import verify_lnk_with_msi


check_lnk_against_msi = verify_lnk_with_msi
verify_lnk_against_msi = verify_lnk_with_msi

__all__ = [
    "MsiExcerpt",
    "check_lnk_against_msi",
    "load_msi_excerpt",
    "verify_lnk_against_msi",
    "verify_lnk_with_msi",
]
