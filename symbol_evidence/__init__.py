"""Evidence grading for PE debug records and symbol-library sign-off sheets.

The package deliberately treats the PE as read-only: identities come from the
``DIRECTORY_ENTRY_DEBUG`` data that :mod:`pefile` already parsed.
"""

from .debug import (
    extract_debug_identities,
    extract_debug_identity,
    load_pe_image,
    read_pe_identity,
)
from .evaluate import evaluate_claim, evaluate_claims
from .model import (
    DEBUG_RECORD_MATCH,
    DIGEST_VERIFIED,
    NAME_ONLY,
    NO_EVIDENCE,
    Claim,
    ClaimEvidence,
    DebugIdentity,
    Digest,
    EvidenceLevel,
    SignoffEntry,
)
from .report import EvidenceReport, build_report
from .signoff import load_claims, load_signoff

__all__ = [
    "DEBUG_RECORD_MATCH",
    "DIGEST_VERIFIED",
    "NAME_ONLY",
    "NO_EVIDENCE",
    "Claim",
    "ClaimEvidence",
    "DebugIdentity",
    "Digest",
    "EvidenceLevel",
    "EvidenceReport",
    "SignoffEntry",
    "build_report",
    "evaluate_claim",
    "evaluate_claims",
    "generate_report",
    "grade_claim",
    "grade_claims",
    "extract_debug_identities",
    "extract_debug_identity",
    "load_claims",
    "load_pe_image",
    "load_signoff",
    "read_pe_identity",
]


grade_claim = evaluate_claim
grade_claims = evaluate_claims
generate_report = build_report
