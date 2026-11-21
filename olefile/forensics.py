"""Read-only file-format evidence helpers for olefile.

This module is a thin, import-friendly facade over the report implemented
next to the OleFileIO read path. It does not write to the compound file.
"""

from .olefile import (
    FormatEvidence,
    FormatEvidenceItem,
    EVIDENCE_CONSTRAINT,
    EVIDENCE_COMPATIBILITY,
    EVIDENCE_CONTRADICTION,
    EVIDENCE_INSUFFICIENT,
    get_format_evidence,
    get_forensic_report,
    get_file_format_evidence,
    get_format_evidence_report,
    get_evidence_report,
    analyze_format,
    format_evidence,
)

__all__ = [
    "FormatEvidence",
    "FormatEvidenceItem",
    "EVIDENCE_CONSTRAINT",
    "EVIDENCE_COMPATIBILITY",
    "EVIDENCE_CONTRADICTION",
    "EVIDENCE_INSUFFICIENT",
    "get_format_evidence",
    "get_forensic_report",
    "get_file_format_evidence",
    "get_format_evidence_report",
    "get_evidence_report",
    "analyze_format",
    "format_evidence",
]
